#!/bin/bash
set -Eeuo pipefail
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    [[ $# -ge 2 ]] || { echo "usage: sudo $0 /path/to/m0 /path/to/proxy" >&2; exit 2; }
    exec bash "$(dirname "$(readlink -f "$0")")/linux-lab.sh" "$0" "$1" "$(readlink -f "$2")"
fi
[[ $# -ge 1 && -x $1 ]]
cli=$1
runtime=/run/proxy
config=/run/proxy.yaml

control() { gateway "$cli" --runtime "$runtime" --config "$config" "$@"; }
snapshot() {
    gateway ip -4 rule show
    gateway ip -6 rule show
    gateway ip -4 route show table all
    gateway ip -6 route show table all
    gateway nft -s list ruleset
}
snapshot >/run/udp-gateway.before

for mode in local gateway; do
    ingress=''
    if [[ $mode == gateway ]]; then ingress='  interfaces: [gc]'; fi
    cat >"$config" <<EOF
version: 1
network:
  connect_timeout: 3s
  udp_timeout: 2s
capture:
  mode: $mode
  udp: true
  namespace: "$gateway_ns"
  ipv4: true
  ipv6: true
  port: 15080
  cidrs: ["198.18.20.0/24", "fd00:20::/64"]
  ports: [18080]
$ingress
outbounds:
  tcp-direct:
    type: direct
  udp-direct:
    type: direct
routing:
  rules:
    - network: udp
      outbound: udp-direct
    - outbound: tcp-direct
EOF
    control config check
    ip netns exec m0g "$cli" run --config "$config" --runtime "$runtime" >"/run/udp-$mode.log" 2>&1 &
    daemon_pid=$!
    for _ in {1..80}; do
        if grep -q 'proxyd ready' "/run/udp-$mode.log"; then break; fi
        kill -0 "$daemon_pid" 2>/dev/null || exit 1
        sleep .1
    done

    probe_all
    status=$(control status --json)
    grep -q '"tcp-direct":2' <<<"$status"
    grep -q '"udp-direct":6' <<<"$status"
    for _ in {1..40}; do
        status=$(control status --json)
        if grep -q '"udp":{"active":0' <<<"$status"; then break; fi
        sleep .1
    done
    grep -q '"udp":{"active":0' <<<"$status"
    control stop --json | grep -q '"state":"stopping"'
    wait "$daemon_pid"
    [[ ! -e $runtime/capture.json ]]
    snapshot >/run/udp-gateway.after
    diff -u /run/udp-gateway.before /run/udp-gateway.after
    probe_all
    echo "M2 $mode dual-stack UDP capture, multi-target replies, timeout and cleanup OK"
done
