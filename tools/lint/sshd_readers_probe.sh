#!/bin/sh
set -eu
usage='usage: sh sshd_readers_probe.sh <cases directory>, as root in a throwaway container'
cases=${1:?$usage}
export LC_ALL=C
if command -v dpkg-query >/dev/null 2>&1; then
    printf '#sshd\t%s\n' "$(dpkg-query -W openssh-server | tr '\t' ' ')"
else
    printf '#sshd\t%s\n' "$(rpm -q openssh-server)"
fi
for file in "$cases"/*.conf; do
    name=$(basename "$file" .conf)
    for user in freesecdev-probe freesecdev-other; do
        status=0
        output=$(/usr/sbin/sshd -T -f "$file" -C "user=$user,host=probe.example,addr=192.0.2.10" 2>/dev/null) \
            || status=$?
        root=$(printf '%s\n' "$output" | sed -n 's/^permitrootlogin //p' | head -n 1)
        pubkey=$(printf '%s\n' "$output" | sed -n 's/^pubkeyauthentication //p' | head -n 1)
        printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$user" "$status" "$root" "$pubkey"
    done
done
