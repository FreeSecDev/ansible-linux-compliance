#!/bin/sh
set -eu
usage='usage: sh login_defs_readers_shadow.sh <states directory> <readers directory>, as root in a throwaway container'
states=${1:?$usage}
readers=${2:?$usage}
export LC_ALL=C
if command -v dpkg-query >/dev/null 2>&1; then
    printf '#shadow\t%s\n' "$(dpkg-query -W -f '${Package} ${Version}' passwd)"
else
    printf '#shadow\t%s\n' "$(rpm -q shadow-utils)"
    printf '#libeconf\t%s\n' "$(rpm -q libeconf)"
    printf '#util-linux\t%s\n' "$(rpm -q util-linux)"
fi
number=0
for directory in "$states"/*/; do
    key=$(basename "$directory")
    python3 "$readers/login_defs_readers.py" install "$directory"
    number=$((number + 1))
    account="ldr${number}m"
    minimum=error
    maximum=error
    warning=error
    mode=none
    if useradd -m "$account" >/dev/null 2>&1; then
        ages=$(chage -l "$account")
        minimum=$(printf '%s\n' "$ages" | sed -n 's/^Minimum number of days between password change[[:space:]]*:[[:space:]]*//p')
        maximum=$(printf '%s\n' "$ages" | sed -n 's/^Maximum number of days between password change[[:space:]]*:[[:space:]]*//p')
        warning=$(printf '%s\n' "$ages" | sed -n 's/^Number of days of warning before password expires[[:space:]]*:[[:space:]]*//p')
        if [ -d "/home/$account" ]; then
            mode=$(stat -c %a "/home/$account")
        fi
        userdel -r "$account" >/dev/null 2>&1 || true
    fi
    account="ldr${number}c"
    created=error
    if useradd "$account" >/dev/null 2>&1; then
        created=no
        if [ -d "/home/$account" ]; then
            created=yes
        fi
        userdel -r "$account" >/dev/null 2>&1 || true
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$key" "$minimum" "$maximum" "$warning" "$mode" "$created"
done
