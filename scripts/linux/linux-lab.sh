#!/bin/bash
set -Eeuo pipefail

for tool in ip nft unshare timeout mount readlink sysctl; do
    command -v "$tool" >/dev/null
done

if [[ ${1:-} != --inside ]]; then
    [[ $# -ge 2 && $EUID == 0 ]] || { echo "usage: sudo $0 scenario m0-binary [scenario arguments]" >&2; exit 2; }
    script=$(readlink -f "$0")
    scenario=$(readlink -f "$1")
    binary=$(readlink -f "$2")
    shift 2
    [[ -f $scenario && $scenario != /run/* && -x $binary && $binary != /run/* ]]
    exec timeout --kill-after=5s 120s unshare --mount --propagation private --net --pid \
        --fork --kill-child --mount-proc bash "$script" --inside "$(readlink /proc/self/ns/net)" "$scenario" "$binary" "$@"
fi

[[ $# -ge 4 && $EUID == 0 && $$ == 1 && $(readlink /proc/self/ns/net) != "$2" ]] || exit 2
outside_ns=$2
scenario=$3
binary=$4
shift 4
mount -t tmpfs -o size=32m,mode=755 tmpfs /run
ip netns add m0c
ip netns add m0g
ip netns add m0u
gateway_ns=$(ip netns exec m0g readlink /proc/self/ns/net)
[[ $gateway_ns != "$outside_ns" ]]
for ns in m0c m0g m0u; do ip -n "$ns" link set lo up; done
ip -n m0c link add c0 type veth peer name gc netns m0g
ip -n m0g link add gu type veth peer name u0 netns m0u

configure() {
    local ns=$1 interface=$2 ipv4=$3 ipv6=$4
    ip -n "$ns" addr add "$ipv4" dev "$interface"
    ip -n "$ns" -6 addr add "$ipv6" dev "$interface" nodad
    ip -n "$ns" link set "$interface" addrgenmode none
    ip -n "$ns" -6 addr add "fe80::${ipv6##*::}" dev "$interface" nodad
    ip -n "$ns" link set "$interface" up
}
configure m0c c0 198.18.10.2/24 fd00:10::2/64
configure m0g gc 198.18.10.1/24 fd00:10::1/64
configure m0g gu 198.18.20.1/24 fd00:20::1/64
configure m0u u0 198.18.20.2/24 fd00:20::2/64
ip -n m0u addr add 198.18.20.3/24 dev u0
ip -n m0u -6 addr add fd00:20::3/64 dev u0 nodad
ip -n m0c route add 198.18.20.0/24 via 198.18.10.1
ip -n m0c -6 route add fd00:20::/64 via fd00:10::1
ip -n m0u route add 198.18.10.0/24 via 198.18.20.1
ip -n m0u -6 route add fd00:10::/64 via fd00:20::1

gateway() {
    [[ $(ip netns exec m0g readlink /proc/self/ns/net) == "$gateway_ns" ]] || return 1
    ip netns exec m0g "$@"
}
gateway sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1

launch() {
    local ns=$1 name=$2
    shift 2
    ip netns exec "$ns" env PROXY_M0_NETNS="$gateway_ns" "$binary" "$@" >"/run/$name.log" 2>&1 &
    last_pid=$!
    for _ in {1..40}; do
        if grep -q 'ready ' "/run/$name.log"; then return; fi
        if ! kill -0 "$last_pid" 2>/dev/null; then break; fi
        sleep .05
    done
    cat "/run/$name.log" >&2
    return 1
}

cleanup() {
    local log
    for log in /run/*.log; do
        if [[ -f $log ]]; then echo "=== ${log##*/} ==="; cat "$log"; fi
    done
}
trap cleanup EXIT

launch m0u echo-tcp4 echo tcp4 0.0.0.0:18080
launch m0u echo-tcp6 echo tcp6 '[::]:18080'
probe_all() {
    for ns in m0c m0g; do
        echo "probe namespace $ns"
        ip netns exec "$ns" "$binary" probe tcp4 198.18.20.2:18080
        ip netns exec "$ns" "$binary" probe tcp6 '[fd00:20::2]:18080'
        ip netns exec "$ns" "$binary" probe udp4 198.18.20.2:18080
        ip netns exec "$ns" "$binary" probe udp6 '[fd00:20::2]:18080'
        ip netns exec "$ns" "$binary" probe-pair udp4 198.18.20.2:18080 198.18.20.3:18080
        ip netns exec "$ns" "$binary" probe-pair udp6 '[fd00:20::2]:18080' '[fd00:20::3]:18080'
    done
}
launch m0u echo-udp6a echo udp6 '[fd00:20::2]:18080'
launch m0u echo-udp6b echo udp6 '[fd00:20::3]:18080'
launch m0u echo-udp4a echo udp4 198.18.20.2:18080
launch m0u echo-udp4b echo udp4 198.18.20.3:18080
probe_all
echo "baseline OK"
source "$scenario"

