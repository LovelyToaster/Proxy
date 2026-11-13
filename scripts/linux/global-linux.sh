#!/bin/bash
# All network mutations occur inside linux-lab.sh's disposable namespaces.
set -Eeuo pipefail
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    [[ $# -ge 2 ]] || { echo "usage: sudo $0 m0 proxy" >&2; exit 2; }
    exec bash "$(dirname "$(readlink -f "$0")")/linux-lab.sh" "$0" "$1" "$(readlink -f "$2")"
fi
command -v setpriv >/dev/null
mkdir -p /run/global-bin /run/global-runtime
cp "$1" /run/global-bin/proxy
chmod 755 /run/global-bin/*
chown 65534:65534 /run/global-runtime
chmod 700 /run/global-runtime
runtime=/run/global-runtime
config=/run/global.yaml
service_user() {
    gateway setpriv --reuid=65534 --regid=65534 --clear-groups \
        --inh-caps=+net_admin --ambient-caps=+net_admin \
        env PROXY_CAPTURE_LOCK_DIR="$runtime" "$@"
}
control() { service_user /run/global-bin/proxy --config "$config" --runtime "$runtime" "$@"; }
snapshot() {
    gateway ip -4 rule show
    gateway ip -6 rule show
    gateway ip -4 route show table all
    gateway ip -6 route show table all
    gateway nft -s list ruleset
}
clean() {
    for _ in {1..80}; do
        if [[ ! -e $runtime/capture.json ]]; then
            snapshot >/run/global.after
            diff -u /run/global.before /run/global.after
            return
        fi
        sleep .1
    done
    echo 'global capture cleanup timed out' >&2
    return 1
}
ip -n m0c -6 addr add fd00:10::2/64 dev c0 nodad
ip -n m0g -6 addr add fd00:10::1/64 dev gc nodad
ip -n m0g -6 addr add fd00:20::1/64 dev gu nodad
ip -n m0u -6 addr add fd00:20::2/64 dev u0 nodad
ip -n m0c -6 route add fd00:20::/64 via fd00:10::1
ip -n m0u -6 route add fd00:10::/64 via fd00:20::1
snapshot >/run/global.before
launch m0g inbound-tcp4 echo tcp4 0.0.0.0:18081
launch m0g inbound-tcp6 echo tcp6 '[::]:18081'
for mode in local gateway; do
    cat >"$config" <<EOF
version: 1
network:
  udp_timeout: 1s
capture:
  mode: $mode
  scope: global
  ipv4: true
  ipv6: true
  port: 15080
  udp: true
outbounds:
  captured:
    type: direct
routing:
  rules:
    - outbound: captured
EOF
    if [[ $mode == gateway ]]; then
        sed -i '/scope: global/a\  interfaces: [gc]' "$config"
    fi
    control config check
    [[ $(ip netns exec m0g readlink /proc/self/ns/net) == "$gateway_ns" ]]
    ip netns exec m0g setpriv --reuid=65534 --regid=65534 --clear-groups \
        --inh-caps=+net_admin --ambient-caps=+net_admin \
        env PROXY_CAPTURE_LOCK_DIR="$runtime" /run/global-bin/proxy \
        run --config "$config" --runtime "$runtime" >"/run/global-$mode.log" 2>&1 &
    daemon_pid=$!
    for _ in {1..80}; do
        if grep -q 'proxyd ready' "/run/global-$mode.log"; then break; fi
        kill -0 "$daemon_pid" 2>/dev/null || exit 1
        sleep .1
    done
    # Both scopes must capture actual traffic, not merely allow DIRECT bypass.
    probe_all
    # Local servers must still reply directly while OUTPUT capture is active.
    ip netns exec m0u "$binary" probe tcp4 198.18.20.1:18081
    ip netns exec m0u "$binary" probe tcp6 '[2001:2:0:20::1]:18081'
    connected_before=$(control status --json | grep -o '"connected":{[^}]*}')
    [[ $connected_before == *'"captured":'* ]]
    gateway nft list ruleset | grep -q 'fc00::/7'
    gateway nft list ruleset | grep -q '192.168.0.0/16'
    bypass_ns=$mode
    if [[ $bypass_ns == local ]]; then bypass_ns=m0g; else bypass_ns=m0c; fi
    ip netns exec "$bypass_ns" "$binary" probe tcp6 '[fd00:20::2]:18080'
    [[ $(control status --json | grep -o '"connected":{[^}]*}') == "$connected_before" ]]
    gateway nft list ruleset | grep -q tproxy
    if gateway nft list ruleset | grep -q redirect; then exit 1; fi
    # No namespace was configured: cleanup must use the resolved exact identity.
    grep -Fq "$gateway_ns" "$runtime/capture.json"
    if [[ $mode == local ]]; then
        control stop
        wait "$daemon_pid"
    else
        kill -KILL "$daemon_pid"
        wait "$daemon_pid" || true
    fi
    clean
    probe_all
    echo "Global $mode dual-stack TCP/UDP and cleanup OK"
done
