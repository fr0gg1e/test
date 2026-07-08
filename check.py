#!/usr/bin/env python3
"""Just check facts. No attack. What handlers run for each key type."""
import os, subprocess, sys

def sh(cmd, t=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
        return (r.stdout + r.stderr).strip()
    except: return "(timeout)"

def p(msg): print(msg, flush=True)

p("=== 1. REQUEST-KEY CONFIG ===")
p(sh("cat /etc/request-key.conf 2>/dev/null"))
p("\n--- request-key.d/ ---")
p(sh("ls -la /etc/request-key.d/ 2>/dev/null"))
p(sh("cat /etc/request-key.d/*.conf 2>/dev/null"))

p("\n=== 2. HANDLER BINARIES — which have setns? ===")
for b in ["/usr/sbin/cifs.upcall", "/usr/sbin/cifs.idmap", "/sbin/cifs.idmap",
          "/sbin/key.dns_resolver", "/usr/sbin/key.dns_resolver",
          "/sbin/request-key", "/usr/sbin/request-key"]:
    exists = os.path.exists(b)
    if exists:
        has_setns = "setns" in sh("strings '%s' 2>/dev/null" % b)
        has_getpwuid = "getpwuid" in sh("strings '%s' 2>/dev/null" % b)
        has_proc_ns = "proc" in sh("strings '%s' 2>/dev/null | grep -i 'ns/' | head -5" % b)
        caps = sh("getcap '%s' 2>/dev/null" % b).strip()
        suid = oct(os.stat(b).st_mode)[-4:]
        p("  %s: setns=%s getpwuid=%s /proc/ns=%s mode=%s %s" % (
            b, has_setns, has_getpwuid, has_proc_ns, suid, caps if caps else ""))
    else:
        p("  %s: NOT FOUND" % b)

p("\n=== 3. STRACE: request_key(cifs.idmap) — what handler runs? ===")
# Build tiny trigger
src = "/tmp/rktrig.c"
with open(src, "w") as f:
    f.write(r'''
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(int ac, char **av) {
    const char *type = ac > 1 ? av[1] : "cifs.idmap";
    const char *desc = ac > 2 ? av[2] : "uid:0";
    const char *call = ac > 3 ? av[3] : "";
    syscall(250, 1, "check-sess", 0, 0, 0);
    errno = 0;
    long r = syscall(249, type, desc, call, -3);
    printf("request_key(%s, %s) = %ld errno=%d %s\n", type, desc, r, errno, strerror(errno));
    if (r >= 0) sleep(3);
    return r < 0 ? 1 : 0;
}
''')
os.system("gcc -o /tmp/rktrig %s 2>&1" % src)

p("\n--- strace cifs.idmap (uid:0) ---")
p(sh("timeout 10 strace -f -e trace=execve,clone,setns,openat -o /tmp/st_idmap.txt /tmp/rktrig cifs.idmap uid:0 '' 2>&1; head -50 /tmp/st_idmap.txt", t=20))

p("\n--- strace dns_resolver (localhost) ---")
p(sh("timeout 10 strace -f -e trace=execve,clone,setns,openat -o /tmp/st_dns.txt /tmp/rktrig dns_resolver localhost '' 2>&1; head -50 /tmp/st_dns.txt", t=20))

p("\n--- full strace dns (look for handler exec) ---")
p(sh("grep -E 'execve|setns|/proc.*ns' /tmp/st_dns.txt 2>/dev/null | head -30"))

p("\n--- full strace idmap (look for handler exec) ---")
p(sh("grep -E 'execve|setns|/proc.*ns' /tmp/st_idmap.txt 2>/dev/null | head -30"))

p("\n=== 4. key.dns_resolver — does it have namespace switch? ===")
for b in ["/sbin/key.dns_resolver", "/usr/sbin/key.dns_resolver"]:
    if os.path.exists(b):
        p("  strings with ns/setns/proc:")
        p(sh("strings '%s' | grep -iE 'setns|namespace|/proc|ns/net|ns/mnt|CLONE_NEW' | head -20" % b))
        p("  readelf NEEDED + RPATH:")
        p(sh("readelf -d '%s' 2>/dev/null | grep -iE 'needed|rpath|runpath'" % b))

p("\n=== 5. DOES HANDLER RUN IN OUR NAMESPACE? (marker test) ===")
# Create marker in our namespace, check if handler sees it
marker = "/tmp/ns_marker_%d" % os.getpid()
with open(marker, "w") as f:
    f.write("visible")
p("  Marker: %s" % marker)
p("  (handlers run via call_usermodehelper in init ns — marker should be visible")
p("   since /tmp is shared. But overlayfs mounts would NOT be visible.)")

p("\n=== 6. cifs.upcall — exact setns behavior ===")
for b in ["/usr/sbin/cifs.upcall"]:
    if os.path.exists(b):
        p("  All strings with ns/proc/pid:")
        p(sh("strings '%s' | grep -iE 'ns/|setns|/proc|pid=|switch.*ns|namespace' | head -30" % b))

p("\n=== DONE ===")
