#!/bin/bash
set -Eeuo pipefail
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    if [[ $# == 3 ]]; then
        exec bash "$(dirname "$(readlink -f "$0")")/linux-lab.sh" "$0" "$1" "$(readlink -f "$2")" "$(readlink -f "$3")"
    elif [[ $# == 4 ]]; then
        exec bash "$(dirname "$(readlink -f "$0")")/linux-lab.sh" "$0" "$1" "$(readlink -f "$2")" "$(readlink -f "$4")"
    else
        echo "usage: sudo $0 m0 proxy dns-test" >&2
        exit 2
    fi
fi
[[ $# == 2 && -x $1 && -x $2 ]]
cli=$1
fixture=$2
runtime=/run/proxy
config=/run/proxy.yaml
cp "$cli" /run/proxy-client
chmod 0755 /run/proxy-client
printf 'nameserver 198.18.20.2\n' >/run/resolv.test
mount --bind /run/resolv.test /etc/resolv.conf

for number in 2 3; do
    ip netns exec m0u env PROXY_M3_DNS_FIXTURE="198.18.20.$number:53" "$fixture" -test.v -test.run '^TestM3LabUpstream$' >"/run/dns-$number.log" 2>&1 &
    pid=$!
    for _ in {1..50}; do
        if grep -q 'DNS fixture ready' "/run/dns-$number.log"; then break; fi
        kill -0 "$pid" 2>/dev/null || exit 1
        sleep .1
    done
    grep -q 'DNS fixture ready' "/run/dns-$number.log"
done

snapshot() {
    gateway ip -4 rule show
    gateway ip -6 rule show
    gateway ip -4 route show table all
    gateway ip -6 route show table all
    gateway nft -s list ruleset
}
control() { gateway "$cli" --runtime "$runtime" --config "$config" "$@"; }
snapshot >/run/dns.before
start_daemon() {
    local label=$1
    ip netns exec m0g "$cli" run --runtime "$runtime" --config "$config" >"/run/dns-$label.log" 2>&1 &
    daemon_pid=$!
    for _ in {1..80}; do
        if grep -q 'proxyd ready' "/run/dns-$label.log"; then return; fi
        kill -0 "$daemon_pid" 2>/dev/null || return 1
        sleep .1
    done
    return 1
}
probe_dns() {
    local ns=$1 expected=$2
    local endpoint transport
    for endpoint in 198.18.20.4:53 '[fd00:20::4]:53'; do
        for transport in udp tcp; do
            flags=()
            if [[ $transport == tcp ]]; then flags+=(--tcp); fi
            echo "M3 probe namespace=$ns transport=$transport endpoint=$endpoint"
            ip netns exec "$ns" setpriv --reuid=65534 --regid=65534 --clear-groups \
                /run/proxy-client dns test probe.test --server "$endpoint" --type TXT "${flags[@]}" | grep -F "$expected"
        done
    done
}

for mode in local gateway; do
    source_ns=m0g
    ingress=''
    if [[ $mode == gateway ]]; then source_ns=m0c; ingress='  interfaces: [gc]'; fi
    printf 'nameserver 198.18.20.2\n' >/run/resolv.test
    cat >"$config" <<EOF
version: 1
service:
  status_group: nogroup
capture:
  mode: $mode
  namespace: "$gateway_ns"
  port: 15080
  cidrs: ["198.18.20.0/24", "fd00:20::/64"]
$ingress
outbounds:
  direct:
    type: direct
routing:
  rules:
    - outbound: direct
dns:
  enabled: true
  hijack: true
  timeout: 1s
  upstreams:
    discovered:
      type: system
  rules:
    - upstream: discovered
EOF
    control config check
    start_daemon "$mode"
    probe_dns "$source_ns" '198.18.20.2:53'
    control dns status --json | grep -q '"queries":4'
    ip netns exec m0g setpriv --reuid=65534 --regid=65534 --clear-groups \
        /run/proxy-client --runtime "$runtime" dns status --json | grep -q '"queries":4'
    if ip netns exec m0g setpriv --reuid=65534 --regid=65534 --clear-groups \
        /run/proxy-client --runtime "$runtime" reload; then exit 1; fi
    printf 'nameserver 198.18.20.3\n' >/run/resolv.test
    sleep 3.2
    probe_dns "$source_ns" '198.18.20.3:53'
    sed -i '/type: system/c\      type: udp\n      address: "198.18.20.2:53"' "$config"
    control reload --json | grep -q '"generation":2'
    probe_dns "$source_ns" '198.18.20.2:53'
    control stop --json | grep -q '"state":"stopping"'
    wait "$daemon_pid"
    [[ ! -e $runtime/capture.json ]]
    snapshot >/run/dns.after
    diff -u /run/dns.before /run/dns.after
    echo "M3 $mode DNS capture, system DNS refresh and cleanup OK"
done

start_daemon crash
kill -KILL "$daemon_pid"
wait "$daemon_pid" || true
for _ in {1..80}; do
    if [[ ! -e $runtime/capture.json ]]; then break; fi
    sleep .1
done
[[ ! -e $runtime/capture.json ]]
snapshot >/run/dns.after
diff -u /run/dns.before /run/dns.after
ip netns exec m0c /run/proxy-client dns test probe.test --server 198.18.20.2:53 --type TXT | grep -q '198.18.20.2:53'
echo 'M3 DNS capture crash cleanup and original DNS path OK'
