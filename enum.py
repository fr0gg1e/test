#!/usr/bin/env python3
"""Enumerate installed packages, SUID/SGID, capabilities, services, crons, timers."""
import os, subprocess, sys

OUT = "/tmp/enum_%d.txt" % os.getpid()

cmds = [
    ("RPM packages", "rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort"),
    ("SUID binaries", "find / -perm -4000 -type f -exec ls -la {} + 2>/dev/null"),
    ("SGID binaries", "find / -perm -2000 -type f -exec ls -la {} + 2>/dev/null"),
    ("File capabilities", "getcap -r / 2>/dev/null"),
    ("Running services", "systemctl list-units --type=service --state=running --no-pager 2>/dev/null"),
    ("All timers", "systemctl list-timers --all --no-pager 2>/dev/null"),
    ("Cron system", "ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /var/spool/cron/ 2>/dev/null"),
    ("Cron files content", "cat /etc/cron.d/* /var/spool/cron/* 2>/dev/null"),
    ("Listening ports", "ss -tlnp 2>/dev/null"),
    ("Sudo config", "sudo -l 2>/dev/null"),
    ("Kernel modules", "lsmod 2>/dev/null"),
    ("Writable /etc", "find /etc -writable -type f 2>/dev/null"),
    ("Writable /etc dirs", "find /etc -writable -type d 2>/dev/null"),
    ("World-writable dirs", "find / -maxdepth 3 -writable -type d ! -path '/proc/*' ! -path '/sys/*' ! -path '/tmp/*' ! -path '/dev/*' ! -path '/run/*' 2>/dev/null"),
    ("/opt /usr/local", "ls -laR /opt/ /usr/local/bin/ /usr/local/sbin/ 2>/dev/null"),
    ("Python/pip packages", "pip3 list 2>/dev/null || python3 -m pip list 2>/dev/null"),
    ("Env vars", "env 2>/dev/null"),
]

with open(OUT, "w") as f:
    for label, cmd in cmds:
        f.write("=== %s ===\n" % label)
        f.flush()
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            f.write(r.stdout)
            if r.stderr.strip():
                f.write(r.stderr)
        except:
            f.write("(timeout)\n")
        f.write("\n\n")

print("Done → %s" % OUT)
print("Wklej output: cat %s" % OUT)
