#!/bin/bash
set -Eeuo pipefail
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    [[ $# == 1 ]] || { echo "usage: sudo $0 /path/to/proxy-m0" >&2; exit 2; }
    exec bash "$(dirname "$(readlink -f "$0")")/linux-lab.sh" "$0" "$1"
fi

launch m0g redirect4 redirect tcp4 0.0.0.0:15080
redirect4_pid=$last_pid
launch m0g redirect6 redirect tcp6 '[::]:15080'
redirect6_pid=$last_pid
launch m0g tcp4 transparent tcp4 0.0.0.0:15081
tcp4_pid=$last_pid
launch m0g tcp6 transparent tcp6 '[::]:15081'
tcp6_pid=$last_pid
launch m0g udp4 transparent udp4 0.0.0.0:15081
udp4_pid=$last_pid
launch m0g udp6 transparent udp6 '[::]:15081'
udp6_pid=$last_pid
gateway ip -4 rule add priority 100 fwmark 1/3 table 100
gateway ip -6 rule add priority 100 fwmark 1/3 table 100
gateway ip -4 route add local 0.0.0.0/0 dev lo table 100
gateway ip -6 route add local ::/0 dev lo table 100

cat > /run/m0.nft <<'EOF'
table inet m0 {
    chain output_route {
        type route hook output priority mangle; policy accept;
        meta mark & 2 != 0 return
        ip daddr 198.18.20.0/24 udp dport 18080 meta mark set 1
        ip6 daddr fd00:20::/64 udp dport 18080 meta mark set 1
    }
    chain output_nat {
        type nat hook output priority dstnat; policy accept;
        meta mark & 2 != 0 return
        ip daddr 198.18.20.0/24 tcp dport 18080 redirect to :15080
        ip6 daddr fd00:20::/64 tcp dport 18080 redirect to :15080
    }
    chain input_capture {
        type filter hook prerouting priority mangle; policy accept;
        iifname "gc" ip daddr 198.18.20.0/24 tcp dport 18080 tproxy ip to :15081 meta mark set 1 accept
        iifname "gc" ip6 daddr fd00:20::/64 tcp dport 18080 tproxy ip6 to :15081 meta mark set 1 accept
        iifname { "gc", "lo" } ip daddr 198.18.20.0/24 udp dport 18080 tproxy ip to :15081 meta mark set 1 accept
        iifname { "gc", "lo" } ip6 daddr fd00:20::/64 udp dport 18080 tproxy ip6 to :15081 meta mark set 1 accept
    }
}
EOF
gateway nft -c -f /run/m0.nft
gateway nft -f /run/m0.nft
(
    listeners_alive() {
        local pid
        for pid in "$redirect4_pid" "$redirect6_pid" "$tcp4_pid" "$tcp6_pid" "$udp4_pid" "$udp6_pid"; do
            kill -0 "$pid" 2>/dev/null || return 1
        done
    }
    while listeners_alive; do
        sleep .1
    done
    gateway nft delete table inet m0
    gateway ip -4 rule del priority 100 fwmark 1/3 table 100
    gateway ip -6 rule del priority 100 fwmark 1/3 table 100
    gateway ip -4 route del local 0.0.0.0/0 dev lo table 100
    gateway ip -6 route del local ::/0 dev lo table 100
) &
watchdog_pid=$!
probe_all
grep -Fq 'capture tcp4 target=198.18.20.2:18080' /run/redirect4.log /dev/null
grep -Fq 'capture tcp6 target=[fd00:20::2]:18080' /run/redirect6.log /dev/null
grep -Fq 'capture tcp4 target=198.18.20.2:18080' /run/tcp4.log /dev/null
grep -Fq 'capture tcp6 target=[fd00:20::2]:18080' /run/tcp6.log /dev/null
[[ $(grep -c '^.*capture udp4 target=' /run/udp4.log) == 8 ]]
[[ $(grep -c '^.*capture udp6 target=' /run/udp6.log) == 8 ]]
echo "dual-stack capture OK"

recovery_started=$SECONDS
kill -KILL "$redirect4_pid"
wait "$watchdog_pid"
probe_all
if gateway nft list table inet m0 2>/dev/null; then exit 1; fi
recovery_elapsed=$((SECONDS - recovery_started))
(( recovery_elapsed <= 10 ))
echo "crash recovery OK in ${recovery_elapsed}s"
