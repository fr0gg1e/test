#!/bin/bash
echo "=== 1. IDMAP PLUGIN CONFIG ==="
ls -la /etc/cifs-utils/ 2>&1
cat /etc/cifs-utils/idmap-plugin 2>&1

echo ""
echo "=== 2. PLUGIN DIR ==="
ls -la /usr/lib64/cifs-utils/ 2>&1
find /usr/lib64/cifs-utils/ -writable 2>/dev/null

echo ""
echo "=== 3. WRITABLE CHECK ==="
test -w /etc/cifs-utils/ && echo "WRITABLE: /etc/cifs-utils/" || echo "NOT writable: /etc/cifs-utils/"
test -f /etc/cifs-utils/idmap-plugin && { test -w /etc/cifs-utils/idmap-plugin && echo "WRITABLE: idmap-plugin" || echo "NOT writable: idmap-plugin"; } || echo "idmap-plugin NOT FOUND"

echo ""
echo "=== 4. STRACE DLOPEN ==="
timeout 10 strace -f -e trace=openat -o /tmp/st_dlopen.txt /tmp/rktrig cifs.idmap "uid:0" "" 2>&1
echo "--- plugin/so opens ---"
grep -iE 'cifs-utils|idmap|plugin|\.so' /tmp/st_dlopen.txt 2>/dev/null

echo ""
echo "=== 5. ACTUAL WRITABLE NSS ==="
result=$(find /lib64 /usr/lib64 -name 'libnss_*' -writable 2>/dev/null)
if [ -n "$result" ]; then
    echo "$result"
    echo "^^^ WRITABLE NSS FOUND ^^^"
else
    echo "(none writable)"
fi

echo ""
echo "=== 6. CIFS.IDMAP STRINGS DLOPEN ==="
strings /usr/sbin/cifs.idmap 2>/dev/null | grep -iE 'dlopen|plugin|\.so|/lib|/usr|/etc|cifs-utils|idmap' | head -20

echo ""
echo "=== 7. WRITABLE LD.SO DIRS ==="
for d in $(cat /etc/ld.so.conf.d/*.conf 2>/dev/null | grep ^/); do
    test -w "$d" && echo "WRITABLE: $d" || echo "not writable: $d"
done

echo ""
echo "=== DONE ==="
