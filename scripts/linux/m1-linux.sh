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

write_config() {
    local mode=$1 interface_config=''
    if [[ $mode == gateway ]]; then interface_config='  interfaces: [gc]'; fi
    cat >"$config" <<EOF
version: 1
network:
  connect_timeout: 3s
  idle_timeout: 10s
capture:
  mode: $mode
  namespace: "$gateway_ns"
  ipv4: true
  ipv6: true
  port: 15080
  cidrs: ["198.18.20.0/24", "fd00:20::/64"]
  ports: [18080]
$interface_config
outbounds:
  cidr:
    type: direct
  private:
    type: direct
  fallback:
    type: direct
routing:
  rules:
    - cidr: "198.18.20.0/24"
      port: 18080-18081
      network: tcp
      outbound: cidr
    - geoip: private
      outbound: private
    - outbound: fallback
EOF
}

control() { gateway "$cli" --runtime "$runtime" --config "$config" "$@"; }
snapshot() {
    gateway ip -4 rule show
    gateway ip -6 rule show
    gateway ip -4 route show table all
    gateway ip -6 route show table all
    gateway nft -s list ruleset
}
ip -n m0c -6 addr add fd00:10::2/64 dev c0 nodad
ip -n m0g -6 addr add fd00:10::1/64 dev gc nodad
ip -n m0g -6 addr add fd00:20::1/64 dev gu nodad
ip -n m0u -6 addr add fd00:20::2/64 dev u0 nodad
ip -n m0c -6 route add fd00:20::/64 via fd00:10::1
ip -n m0u -6 route add fd00:10::/64 via fd00:20::1
snapshot >/run/gateway.before

start_proxy() {
    local label=$1
    ip netns exec m0g "$cli" run --config "$config" --runtime "$runtime" >"/run/$label.log" 2>&1 &
    proxy_pid=$!
    for _ in {1..50}; do
        if grep -q 'proxyd ready' "/run/$label.log"; then break; fi
        kill -0 "$proxy_pid" 2>/dev/null || return 1
        sleep .1
    done
    control status --json | grep -q '"generation":1'
    if ! test -f "$runtime/capture.json"; then return 1; fi
}
tcp() {
    local ns=$1
    ip netns exec "$ns" "$binary" probe tcp4 198.18.20.2:18080
    ip netns exec "$ns" "$binary" probe tcp6 '[fd00:20::2]:18080'
}
clean() {
    for _ in {1..80}; do
        if [[ ! -e $runtime/capture.json ]]; then
            snapshot >/run/gateway.after
            diff -u /run/gateway.before /run/gateway.after
            return
        fi
        sleep .1
    done
    echo 'capture journal was not cleared' >&2
    return 1
}

write_config local
control config check
start_proxy local
tcp m0g
ip netns exec m0g "$binary" probe tcp6 '[fd00:20::2]:18080'
probe_all
status=$(control status --json)
grep -q '"cidr":2' <<<"$status"
grep -q '"private":2' <<<"$status"
control connections list --json
cp "$config" /run/valid.yaml
printf '\nunknown: true\n' >>"$config"
if control config check || control reload; then exit 1; fi
control status --json | grep -q '"generation":1'
cp /run/valid.yaml "$config"
sed -i 's/outbound: cidr/outbound: fallback/' "$config"
control reload --json | grep -q '"generation":2'
tcp m0g
control status --json | grep -q '"fallback":1'
control stop --json | grep -q '"state":"stopping"'
wait "$proxy_pid"
clean
probe_all
echo 'M1 local capture, rule reload, stop and bypass OK'

write_config gateway
gateway ip -4 route add local 203.0.113.30/32 dev lo table 100
if gateway "$daemon" --config "$config" --runtime "$runtime" >/run/conflict.log 2>&1; then exit 1; fi
grep -q 'policy route table is occupied' /run/conflict.log
gateway ip -4 route show table 100 | grep -q '203.0.113.30'
gateway ip -4 route del local 203.0.113.30/32 dev lo table 100
clean

start_proxy gateway
ip netns exec m0c "$binary" probe tcp6 '[fd00:20::2]:18080'
probe_all
status=$(control status --json)
grep -q '"cidr":1' <<<"$status"
grep -q '"private":1' <<<"$status"
kill -KILL "$proxy_pid"
wait "$proxy_pid" || true
clean
probe_all
echo 'M1 gateway dual stack and crash cleanup OK'

start_proxy lease
kill -STOP "$proxy_pid"
clean
probe_all
kill -KILL "$proxy_pid"
wait "$proxy_pid" || true
control capture-cleanup
echo 'M1 lease expiration and idempotent cleanup OK'
