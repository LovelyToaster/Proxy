#!/bin/bash
set -Eeuo pipefail
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    [[ $# -ge 2 ]] || { echo "usage: sudo $0 m0 proxy" >&2; exit 2; }
    exec bash "$(dirname "$(readlink -f "$0")")/linux-lab.sh" "$0" "$1" "$(readlink -f "$2")"
fi
command -v python3 >/dev/null
command -v setpriv >/dev/null
fixture=$(dirname "$scenario")/throughput-linux.py
mkdir -p /run/bench-bin /run/bench-runtime
cp "$1" /run/bench-bin/proxy
cp "$fixture" /run/bench-bin/fixture.py
chmod 755 /run/bench-bin/*
chown 65534:65534 /run/bench-runtime
chmod 700 /run/bench-runtime
runtime=/run/bench-runtime
config=/run/bench.yaml
for host in 198.18.20.2 2001:2:0:20::2; do
    ip netns exec m0u python3 /run/bench-bin/fixture.py server "$host" 18443 >"/run/bench-server-${host//:/_}.log" 2>&1 &
done
sleep .3
snapshot() {
    gateway ip -4 rule show
    gateway ip -6 rule show
    gateway ip -4 route show table all
    gateway ip -6 route show table all
    gateway nft -s list ruleset
}
snapshot >/run/bench.before
control() {
    gateway setpriv --reuid=65534 --regid=65534 --clear-groups \
        env PROXY_CAPTURE_LOCK_DIR="$runtime" /run/bench-bin/proxy \
        --config "$config" --runtime "$runtime" "$@"
}
# One invocation measures a single family and topology to keep the lab bounded.
family=${PROXY_BENCH_FAMILY:-4}
mode=${PROXY_BENCH_MODE:-local}
[[ $family == 4 || $family == 6 ]]
[[ $mode == local || $mode == gateway ]]
host=198.18.20.2
[[ $family == 4 ]] || host=2001:2:0:20::2
client=m0g
[[ $mode == local ]] || client=m0c
ip netns exec "$client" python3 /run/bench-bin/fixture.py client "$host" 18443 "direct-$mode-v$family"
cat >"$config" <<EOF
capture:
  scope: global
  udp: true
outbounds:
  captured: {type: direct}
routing:
  rules:
    - outbound: captured
EOF
if [[ $mode == gateway ]]; then sed -i '/scope: global/a\  interfaces: [gc]' "$config"; fi
[[ $(ip netns exec m0g readlink /proc/self/ns/net) == "$gateway_ns" ]]
ip netns exec m0g setpriv --reuid=65534 --regid=65534 --clear-groups \
    --inh-caps=+net_admin --ambient-caps=+net_admin \
    env PROXY_CAPTURE_LOCK_DIR="$runtime" /run/bench-bin/proxy \
    run --config "$config" --runtime "$runtime" >/run/bench-proxy.log 2>&1 &
daemon_pid=$!
for _ in {1..80}; do
    if grep -q 'proxyd ready' /run/bench-proxy.log; then break; fi
    kill -0 "$daemon_pid" 2>/dev/null || exit 1
    sleep .1
done
echo "BENCH_NATIVE_MODE=$mode FAMILY=$family"
read_proc_cpu() { awk '{print $14+$15}' "/proc/$1/stat"; }
read_sys_cpu() { awk '/^cpu /{busy=$2+$3+$4+$6+$7+$8; total=busy+$5; print busy, total; exit}' /proc/stat; }
clk_tck=$(getconf CLK_TCK)
cores=$(nproc)
t0=$(date +%s%N)
p0=$(read_proc_cpu "$daemon_pid")
read -r sb0 st0 < <(read_sys_cpu)
ip netns exec "$client" python3 /run/bench-bin/fixture.py client "$host" 18443 "tproxy-$mode-v$family"
t1=$(date +%s%N)
p1=$(read_proc_cpu "$daemon_pid")
read -r sb1 st1 < <(read_sys_cpu)
awk -v t0="$t0" -v t1="$t1" -v p0="$p0" -v p1="$p1" -v sb0="$sb0" -v sb1="$sb1" -v st0="$st0" -v st1="$st1" -v hz="$clk_tck" -v cores="$cores" \
    'BEGIN { wall=(t1-t0)/1e9; pcpu=(p1-p0)/hz; pcores=(wall>0?pcpu/wall:0); ppct=(wall>0?pcpu/(wall*cores)*100:0); spct=(st1>st0?(sb1-sb0)/(st1-st0)*100:0); printf "CPU_STATS wall_s=%.2f proxy_cpu_s=%.2f proxy_cores=%.2f/%d proxy_cpu_pct=%.2f%% sys_cpu_pct=%.2f%%\n", wall, pcpu, pcores, cores, ppct, spct }'
control status --json
grep -E 'VmRSS|VmHWM' "/proc/$daemon_pid/status"
control stop
wait "$daemon_pid"
[[ ! -e $runtime/capture.json ]]
snapshot >/run/bench.after
diff -u /run/bench.before /run/bench.after
probe_all
echo 'BENCH_CLEANUP_OK'
