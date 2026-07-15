#!/usr/bin/env bash
[[ $# -eq 0 ]] && { echo "Uzycie: $0 <komenda z {} w miejscu hasla>" >&2; exit 1; }
read -rsp "Pass: " PASS; echo
export PYTHONUNBUFFERED=1
cmd=(); for a in "$@"; do [[ $a == '{}' ]] && a=$PASS; cmd+=("$a"); done
stdbuf -oL -eL "${cmd[@]}" 2>&1 | PASS="$PASS" perl -pe 'BEGIN{$|=1} s/\Q$ENV{PASS}\E/********/g'
exit "${PIPESTATUS[0]}"
