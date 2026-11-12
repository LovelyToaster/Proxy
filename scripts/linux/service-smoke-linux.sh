#!/bin/bash
# Exercises real systemd with capture off; requires an otherwise absent proxyd unit.
set -Eeuo pipefail
[[ $EUID == 0 && $# == 1 && -x $1 ]] || { echo 'usage: sudo bash service-smoke-linux.sh /path/to/proxy' >&2; exit 2; }
[[ $(systemctl show --property=LoadState --value proxyd.service) == not-found ]] || { echo 'Existing proxyd.service: refusing smoke test' >&2; exit 1; }
testdir=$(mktemp -d /opt/proxy-service-smoke.XXXXXX)
chmod 755 "$testdir"
cp "$1" "$testdir/proxy"
chmod 755 "$testdir/proxy"
binary=$testdir/proxy
config=$testdir/proxy.yaml
upstream_pid=''
cleanup() {
    local result=$?
    if [[ $result != 0 ]]; then journalctl -u proxyd.service -n 40 --no-pager || true; fi
    if [[ -f /etc/systemd/system/proxyd.service ]] && grep -Fq "$testdir/proxy" /etc/systemd/system/proxyd.service; then
        "$binary" stop || true
    fi
    if [[ -n $upstream_pid ]]; then kill "$upstream_pid" 2>/dev/null || true; wait "$upstream_pid" 2>/dev/null || true; fi
    case $testdir in /opt/proxy-service-smoke.*) rm -rf -- "$testdir";; *) echo 'Unexpected smoke directory' >&2;; esac
}
trap cleanup EXIT
read -r upstream_port listener_port < <(python3 -c 'import socket; a=socket.socket(); b=socket.socket(); a.bind(("127.0.0.1",0)); b.bind(("127.0.0.1",0)); print(a.getsockname()[1],b.getsockname()[1])')
python3 -m http.server "$upstream_port" --bind 127.0.0.1 --directory "$testdir" >"$testdir/http.log" 2>&1 &
upstream_pid=$!
cat >"$config" <<EOF
capture: {mode: off}
service: {autostart: false}
listeners:
  - address: 127.0.0.1:$listener_port
    target: 127.0.0.1:$upstream_port
outbounds:
  direct: {type: direct}
routing:
  rules:
    - outbound: direct
EOF
chmod 644 "$config"
"$binary" --config "$config" start
systemctl is-active --quiet proxyd.service
[[ $(systemctl show --property=User --value proxyd.service) == proxyd ]]
[[ $(systemctl is-enabled proxyd.service || true) == disabled ]]
"$binary" status --json
for _ in {1..30}; do
    if curl -fsS --noproxy '*' --output /dev/null "http://127.0.0.1:$listener_port/"; then break; fi
    sleep .1
done
curl -fsS --noproxy '*' --output /dev/null "http://127.0.0.1:$listener_port/"
old_pid=$(systemctl show --property=MainPID --value proxyd.service)
"$binary" --config "$config" restart
[[ $(systemctl show --property=MainPID --value proxyd.service) != "$old_pid" ]]
echo 'PASS auto registration, dedicated UID, background forwarding and restart'
sed -i 's/autostart: false/autostart: true/' "$config"
"$binary" restart
[[ $(systemctl is-enabled proxyd.service) == enabled ]]
sed -i 's/autostart: true/autostart: false/' "$config"
"$binary" restart
[[ $(systemctl is-enabled proxyd.service || true) == disabled ]]
"$binary" stop
[[ ! -e /etc/systemd/system/proxyd.service ]]
[[ $(systemctl show --property=LoadState --value proxyd.service) == not-found ]]
"$binary" stop
echo 'PASS autostart toggles, stop unregisters, repeated stop is harmless'
# Startup must roll back the registration when the listener cannot bind.
sed -i -e "s/address: 127.0.0.1:$listener_port/address: 127.0.0.1:$upstream_port/" \
    -e "s/target: 127.0.0.1:$upstream_port/target: 127.0.0.1:$listener_port/" "$config"
if "$binary" --config "$config" start; then echo 'Expected failed start' >&2; exit 1; fi
[[ ! -e /etc/systemd/system/proxyd.service ]]
echo 'PASS failed start rolls back registration'
echo 'LINUX SERVICE SMOKE PASS'
