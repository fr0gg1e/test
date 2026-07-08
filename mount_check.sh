#!/bin/bash
echo "=== 1. MOUNT.CIFS SUID CHECK ==="
ls -la /sbin/mount.cifs /usr/sbin/mount.cifs 2>&1
getcap /sbin/mount.cifs /usr/sbin/mount.cifs 2>/dev/null
file /sbin/mount.cifs 2>/dev/null

echo ""
echo "=== 2. AUTOMOUNT ==="
systemctl status autofs 2>&1 | head -10
rpm -q autofs 2>&1
cat /etc/auto.master /etc/auto.master.d/*.autofs 2>/dev/null
cat /etc/auto.cifs /etc/auto.smb /etc/auto.net 2>/dev/null
ls -la /etc/auto.* 2>/dev/null

echo ""
echo "=== 3. EXISTING CIFS MOUNTS ==="
mount | grep -i cifs 2>/dev/null
cat /proc/mounts | grep -i cifs 2>/dev/null
cat /etc/fstab | grep -i cifs 2>/dev/null

echo ""
echo "=== 4. SMB/CIFS TOOLS ==="
which smbclient kinit klist mount.cifs cifscreds smbcontrol 2>&1
rpm -qa | grep -iE 'samba|cifs|krb5-work' 2>&1

echo ""
echo "=== 5. ALTERNATIVES CHAIN ==="
ls -la /etc/alternatives/cifs-idmap-plugin 2>&1
readlink -f /etc/cifs-utils/idmap-plugin 2>&1
test -w /etc/alternatives/ && echo "WRITABLE: /etc/alternatives/" || echo "not writable: /etc/alternatives/"

echo ""
echo "=== 6. FSOPEN CIFS (new mount API no root) ==="
cat > /tmp/fsopen_test.c << 'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#ifndef __NR_fsopen
#define __NR_fsopen 430
#define __NR_fsconfig 431
#endif
#define FSCONFIG_SET_STRING 1
#define FSCONFIG_CMD_CREATE 6
int main(){
    errno=0;
    int fd=syscall(__NR_fsopen,"cifs",0);
    printf("fsopen(cifs)=%d e=%d %s\n",fd,errno,strerror(errno));
    if(fd<0){errno=0;fd=syscall(__NR_fsopen,"smb3",0);printf("fsopen(smb3)=%d e=%d %s\n",fd,errno,strerror(errno));}
    if(fd<0) return 1;
    struct{const char*k;const char*v;}o[]={
        {"source","//127.0.0.1/x"},{"ip","127.0.0.1"},{"port","4445"},
        {"username","a"},{"password","a"},{"sec","krb5"},{0,0}};
    for(int i=0;o[i].k;i++){
        errno=0;
        int r=syscall(__NR_fsconfig,fd,FSCONFIG_SET_STRING,o[i].k,o[i].v,0);
        printf("fsconfig(%s=%s)=%d e=%d %s\n",o[i].k,o[i].v,r,errno,strerror(errno));
        if(r<0)break;
    }
    errno=0;
    int r=syscall(__NR_fsconfig,fd,FSCONFIG_CMD_CREATE,0,0,0);
    printf("fsconfig(CREATE)=%d e=%d %s\n",r,errno,strerror(errno));
    char buf[4096]={};
    int n=read(fd,buf,sizeof(buf)-1);
    if(n>0)printf("fs_log: %s\n",buf);
    close(fd);
    printf("--- check /proc/keys for cifs.spnego ---\n");
    fflush(stdout);
    system("cat /proc/keys 2>/dev/null | grep -iE 'cifs|spnego'");
    return 0;
}
EOF
gcc -o /tmp/fsopen_test /tmp/fsopen_test.c 2>&1 && /tmp/fsopen_test

echo ""
echo "=== 7. MOUNT.CIFS AS USER (if SUID) ==="
mkdir -p /tmp/mnt_test_$$ 2>/dev/null
if [ -u /sbin/mount.cifs ] || [ -u /usr/sbin/mount.cifs ]; then
    echo "mount.cifs IS SUID - trying mount with sec=krb5..."
    timeout 5 mount.cifs //127.0.0.1/test /tmp/mnt_test_$$ -o sec=krb5,port=4445,user=a,pass=a 2>&1
    echo "--- keys after mount attempt ---"
    cat /proc/keys 2>/dev/null | grep -iE 'cifs|spnego'
else
    echo "mount.cifs NOT SUID"
    timeout 5 mount -t cifs //127.0.0.1/test /tmp/mnt_test_$$ -o sec=krb5,port=4445 2>&1
fi
rmdir /tmp/mnt_test_$$ 2>/dev/null

echo ""
echo "=== 8. KERBEROS STATE ==="
klist 2>&1
ls -la /tmp/krb5cc_* 2>/dev/null
cat /etc/krb5.conf 2>/dev/null | head -30

echo ""
echo "=== DONE ==="
