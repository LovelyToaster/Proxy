#!/bin/bash
set -Eeuo pipefail
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    [[ $EUID == 0 && $# == 3 ]] || { echo 'usage: sudo bash upstream-bypass-linux.sh m0 proxy capture-test' >&2; exit 2; }
    cg=/sys/fs/cgroup/proxy-upstream-lab-$$.service
    nextcg=/sys/fs/cgroup/proxy-upstream-next-$$.service
    mkdir "$cg"
    mkdir "$nextcg"
    trap 'rmdir -- "$cg" "$nextcg"' EXIT
    export PROXY_UPSTREAM_TEST_CGROUP=$cg
    export PROXY_UPSTREAM_TEST_NEXT_CGROUP=$nextcg
    bash "$(dirname "$(readlink -f "$0")")/linux-lab.sh" "$0" "$1" "$(readlink -f "$2")" "$(readlink -f "$3")"
    exit
fi
mkdir -p /run/upstream-bin /run/upstream-runtime
cp "$1" /run/upstream-bin/proxy
cp "$2" /run/upstream-bin/capture-test
chmod 755 /run/upstream-bin/*
chown 65534:65534 /run/upstream-runtime
chmod 700 /run/upstream-runtime
runtime=/run/upstream-runtime
config=/run/upstream.yaml
cg=$PROXY_UPSTREAM_TEST_CGROUP
gateway() {
    [[ $(nsenter --net=/run/netns/m0g readlink /proc/self/ns/net) == "$gateway_ns" ]]
    nsenter --net=/run/netns/m0g "$@"
}
service_user() { gateway setpriv --reuid=65534 --regid=65534 --clear-groups env PROXY_CAPTURE_LOCK_DIR="$runtime" "$@"; }
control() { service_user /run/upstream-bin/proxy --config "$config" --runtime "$runtime" "$@"; }
start_upstream() {
    nsenter --net=/run/netns/m0g bash -ec 'echo $$ >"$1/cgroup.procs"; exec env PROXY_UPSTREAM_FIXTURE=127.0.0.1:17891 /run/upstream-bin/capture-test -test.run "^TestLocalUpstreamFixture$" -test.v' -- "$cg" >/run/upstream.log 2>&1 &
    upstream_pid=$!
    for _ in {1..50}; do
        if grep -q 'upstream fixture ready' /run/upstream.log; then return; fi
        kill -0 "$upstream_pid"; sleep .1
    done
    return 1
}
snapshot() {
    gateway ip -4 rule show
    gateway ip -6 rule show
    gateway ip -4 route show table all
    gateway ip -6 route show table all
    gateway nft -s list ruleset
}
snapshot >/run/upstream.before
cat >"$config" <<EOF
capture:
  scope: global
  udp: true
outbounds:
  upstream: {type: socks5, address: '127.0.0.1:17891', udp: true}
routing:
  rules:
    - outbound: upstream
dns:
  enabled: true
  hijack: true
  upstreams:
    test: {type: udp, address: '198.18.20.2:53'}
  rules:
    - upstream: test
EOF
launch m0u dns-udp4 echo udp4 198.18.20.2:53
launch m0u dns-tcp4 echo tcp4 198.18.20.2:53
launch m0u dns-udp6 echo udp6 '[fd00:20::2]:53'
launch m0u dns-tcp6 echo tcp6 '[fd00:20::2]:53'
start_upstream
start_proxy() {
    nsenter --net=/run/netns/m0g setpriv --reuid=65534 --regid=65534 --clear-groups \
        --inh-caps=+net_admin --ambient-caps=+net_admin env PROXY_CAPTURE_LOCK_DIR="$runtime" \
        /run/upstream-bin/proxy --config "$config" --runtime "$runtime" run >/run/proxy-upstream.log 2>&1 &
    proxy_pid=$!
    for _ in {1..50}; do
        if grep -q 'proxyd ready' /run/proxy-upstream.log; then return; fi
        kill -0 "$proxy_pid"; sleep .1
    done
    return 1
}
check_flows() {
    # Ordinary root clients must still use SOCKS5, despite the root upstream.
    gateway "$binary" probe tcp4 198.18.20.2:18080
    gateway "$binary" probe tcp6 '[fd00:20::2]:18080'
    control status --json | grep -Fq "\"upstream\":${1:-2}"
    # Root sockets in the upstream cgroup bypass UDP and both forms of DNS.
    for spec in 'udp4 198.18.20.2:18080' 'udp6 [fd00:20::2]:18080' 'udp4 198.18.20.2:53' 'tcp4 198.18.20.2:53' 'udp6 [fd00:20::2]:53' 'tcp6 [fd00:20::2]:53'; do
        read -r network target <<<"$spec"
        gateway bash -ec 'echo $$ >"$1/cgroup.procs"; shift; exec "$@"' -- "$cg" "$binary" probe "$network" "$target"
    done
    gateway nft list ruleset | grep -F "${cg#/sys/fs/cgroup/}"
}
start_proxy
check_flows
echo 'PASS local SOCKS5 upstream automatic cgroup bypass; other root clients still captured; IPv4/IPv6 TCP/UDP/DNS'
# Freeze only the guard while replacing the idle listener, to exercise a
# deterministic identity change rather than the missing-listener recovery path.
guard_pid=$(pgrep -P "$proxy_pid" -f 'capture-guard')
kill -STOP "$guard_pid"
kill "$upstream_pid"; wait "$upstream_pid" || true
oldcg=$cg
cg=$PROXY_UPSTREAM_TEST_NEXT_CGROUP
start_upstream
kill -CONT "$guard_pid"
for _ in {1..50}; do
    if grep -q 'bypass refreshed' /run/proxy-upstream.log; then break; fi
    kill -0 "$proxy_pid"; sleep .1
done
grep -q 'bypass refreshed' /run/proxy-upstream.log
if gateway nft list ruleset | grep -Fq "${oldcg#/sys/fs/cgroup/}"; then exit 1; fi
check_flows 4
echo 'PASS listener moves to a new cgroup: bypass refreshed atomically and old group removed'
kill "$upstream_pid"; wait "$upstream_pid" || true
for _ in {1..80}; do
    if [[ ! -e $runtime/capture.json ]] && ! kill -0 "$proxy_pid" 2>/dev/null; then break; fi
    sleep .1
done
wait "$proxy_pid" || true
[[ ! -e $runtime/capture.json ]]
snapshot >/run/upstream.after
diff -u /run/upstream.before /run/upstream.after
echo 'PASS upstream disappearance withdraws capture and restores routing'
start_upstream
start_proxy
check_flows
control stop
wait "$proxy_pid"
snapshot >/run/upstream.after
diff -u /run/upstream.before /run/upstream.after
echo 'PASS restarted upstream rediscovered; clean stop restores original rules'
