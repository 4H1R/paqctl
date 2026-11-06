#!/bin/bash
# Real-kernel test of the egress guard (src/lib/egress.sh).
#
#   sudo bash tests/egress-integration.sh
#
# Needs root, systemd, cgroup v2, iptables with the cgroup match, python3 and
# curl. Uses throwaway units, chains and a dummy interface (all removed on
# exit); the host's own firewall rules are not touched. Exits 0 with SKIP when
# the environment cannot run it.
#
# shellcheck disable=SC2034  # EGRESS_* / _EGRESS_* are read by the sourced guard functions

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UNIT=paqctl-egress-test.service
PRE_UNIT=paqctl-egress-pre.service
W=$(mktemp -d)
pass=0; fail=0
ok()   { echo "  PASS  $*"; pass=$((pass + 1)); }
bad()  { echo "  FAIL  $*"; fail=$((fail + 1)); }
skip() { echo "SKIP: $*"; rm -rf "$W"; exit 0; }
expect() {
    local want="$1" desc="$2" got; shift 2
    if "$@" >/dev/null 2>&1; then got=open; else got=blocked; fi
    if [ "$got" = "$want" ]; then ok "$desc ($got)"; else bad "$desc (want $want, got $got)"; fi
}

[ "$(id -u)" -eq 0 ] || skip "needs root"
[ -d /run/systemd/system ] || skip "needs systemd"
[ -f /sys/fs/cgroup/cgroup.controllers ] || skip "needs cgroup v2"
for c in iptables ip6tables python3 curl ss systemd-run journalctl; do
    command -v "$c" >/dev/null || skip "needs $c"
done
modprobe xt_cgroup 2>/dev/null || true
iptables -w -N PQT_PROBE 2>/dev/null
if ! iptables -w -A PQT_PROBE -m cgroup --path system.slice -j RETURN 2>/dev/null; then
    iptables -w -X PQT_PROBE 2>/dev/null
    skip "iptables cgroup match unavailable"
fi
iptables -w -F PQT_PROBE; iptables -w -X PQT_PROBE

"$ROOT/tests/extract-management.sh" "$ROOT/paqctl.sh" "$W/opt" > "$W/paqctl"
cat > "$W/env.sh" << EOF
export PAQCTL_SOURCE_ONLY=1
# shellcheck disable=SC1091
source "$W/paqctl"
_EGRESS_CHAIN=PQT_EGRESS; _EGRESS_DENY=PQT_EGRESS_DENY; _EGRESS_TAG=paqctl-egress-test
BACKEND=paqet ROLE=server EGRESS_GUARD=true EGRESS_ALLOW=""
EOF
# shellcheck disable=SC1091
source "$W/env.sh"
_EGRESS_CGROUP="system.slice/$UNIT"
CG="/sys/fs/cgroup/$_EGRESS_CGROUP"

cleanup() {
    _egress_guard_remove 2>/dev/null
    iptables -w -t nat -D OUTPUT -d 203.0.113.10 -p tcp --dport 8080 -j DNAT --to-destination 10.99.0.1:18081 2>/dev/null
    ip link del pqtest0 2>/dev/null
    local u
    for u in "$UNIT" "$PRE_UNIT"; do
        systemctl stop "$u" 2>/dev/null; systemctl reset-failed "$u" 2>/dev/null
    done
    # shellcheck disable=SC2046
    kill $(jobs -p) 2>/dev/null
    rm -rf "$W"
}
trap cleanup EXIT

# Listeners: loopback TCP (two ports), IPv6 loopback, loopback UDP echo, and a
# "private network" on a dummy interface
python3 -m http.server 18080 --bind 127.0.0.1 >/dev/null 2>&1 &
python3 -m http.server 18083 --bind 127.0.0.1 >/dev/null 2>&1 &
python3 -m http.server 18084 --bind ::1 >/dev/null 2>&1 &
ip link add pqtest0 type dummy && ip addr add 10.99.0.1/24 dev pqtest0 && ip link set pqtest0 up
python3 -m http.server 18081 --bind 10.99.0.1 >/dev/null 2>&1 &
python3 - << 'PY' &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 18082))
while True:
    d, a = s.recvfrom(100)
    s.sendto(d, a)
PY
sleep 1.5

# Run a command inside the test unit's cgroup, i.e. as paqet would
# shellcheck disable=SC2016
incg() { bash -c 'echo $BASHPID > "$0/cgroup.procs" && "$@"' "$CG" "$@"; }
tcp()  { curl -s -o /dev/null --max-time 4 "$@"; }
udp()  { python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
s.connect((sys.argv[1], int(sys.argv[2]))); s.send(b"x"); s.recv(10)' "$@"; }
export -f tcp udp
have_internet=false; tcp https://1.1.1.1/ && have_internet=true
have_dns=false; getent hosts github.com >/dev/null && have_dns=true

systemd-run --quiet --unit="$UNIT" --property=Type=exec sleep 600
sleep 0.5
[ -d "$CG" ] && ok "test unit cgroup exists" || { bad "no cgroup $CG"; exit 1; }

echo "== baseline: no guard"
expect open "loopback tcp from paqet's cgroup" incg tcp http://127.0.0.1:18080/
expect open "private tcp from paqet's cgroup"  incg tcp http://10.99.0.1:18081/

echo "== guard on"
_egress_guard_apply; rc=$?
[ "$rc" -eq 0 ] && ok "_egress_guard_apply rc=0" || bad "_egress_guard_apply rc=$rc"
_egress_guard_active && ok "_egress_guard_active" || bad "_egress_guard_active"
t0=$(date +%s%N)
expect blocked "loopback tcp" incg tcp http://127.0.0.1:18080/
ms=$(( ($(date +%s%N) - t0) / 1000000 ))
[ "$ms" -lt 1500 ] && ok "rejected fast (${ms} ms, tcp-reset rather than a timeout)" || bad "slow reject: ${ms} ms"
expect blocked "private 10.99.0.1"           incg tcp http://10.99.0.1:18081/
expect blocked "metadata 169.254.169.254"    incg tcp http://169.254.169.254/
expect blocked "0.0.0.0 (means localhost)"   incg tcp http://0.0.0.0:18080/
expect blocked "loopback udp"                incg udp 127.0.0.1 18082
if [ "$have_internet" = true ]; then expect open "public https" incg tcp https://1.1.1.1/; else echo "  (no internet: public check skipped)"; fi
if [ "$have_dns" = true ]; then expect open "DNS lookups" incg getent hosts github.com; else echo "  (no DNS: lookup check skipped)"; fi
echo "   other processes are not affected:"
expect open "loopback tcp"  tcp http://127.0.0.1:18080/
expect open "private tcp"   tcp http://10.99.0.1:18081/
expect open "loopback udp"  udp 127.0.0.1 18082

echo "== published port (DNAT) stays reachable"
iptables -w -t nat -A OUTPUT -d 203.0.113.10 -p tcp --dport 8080 -j DNAT --to-destination 10.99.0.1:18081
expect open "203.0.113.10:8080 DNATed to 10.99.0.1:18081" incg tcp http://203.0.113.10:8080/

echo "== self-test and kernel log"
st=$(_egress_selftest); [ "$st" = blocked ] && ok "_egress_selftest = blocked" || bad "_egress_selftest = $st"
sleep 1
blk=$(_egress_recent_blocks "5 minutes ago")
grep -q "127.0.0.1:18080 (TCP)" <<< "$blk" && ok "log summary has 127.0.0.1:18080 (TCP)" || bad "log summary: $(head -3 <<< "$blk" | tr '\n' ';')"
grep -q "169.254.169.254:80 (TCP)" <<< "$blk" && ok "log summary has 169.254.169.254:80" || bad "no metadata line in the log summary"

echo "== allow-list"
EGRESS_ALLOW="127.0.0.1:18080, 10.99.0.0/24"
_egress_guard_apply || bad "apply with allow-list"
expect open    "allowed 127.0.0.1:18080"   incg tcp http://127.0.0.1:18080/
expect blocked "other loopback port"       incg tcp http://127.0.0.1:18083/
expect open    "allowed 10.99.0.0/24"      incg tcp http://10.99.0.1:18081/
expect blocked "metadata still blocked"    incg tcp http://169.254.169.254/
[ "$(_egress_selftest)" = skipped ] && ok "self-test skips when loopback is allow-listed" || bad "self-test did not skip"
EGRESS_ALLOW=""
_egress_guard_apply

echo "== restart: a rule bound to the old cgroup goes stale; rebuilding fixes it"
systemctl stop "$UNIT"; systemd-run --quiet --unit="$UNIT" --property=Type=exec sleep 600; sleep 0.5
expect open "stale rule no longer matches (why every start rebuilds)" incg tcp http://127.0.0.1:18080/
[ "$(_egress_selftest)" = open ] && ok "self-test detects the stale guard" || bad "self-test missed the stale guard"
_egress_guard_apply
expect blocked "after rebuild" incg tcp http://127.0.0.1:18080/
n=$(iptables -w -S OUTPUT | grep -c "$_EGRESS_CHAIN")
[ "$n" -eq 1 ] && ok "exactly one OUTPUT jump after rebuilds" || bad "$n OUTPUT jumps"

echo "== apply while the service is stopped"
systemctl stop "$UNIT"; sleep 0.3
_egress_guard_apply; rc=$?
[ "$rc" -eq 2 ] && ok "rc=2 (installed at the next start)" || bad "rc=$rc"
_egress_guard_active && bad "guard active without a cgroup" || ok "no guard without a running service"

echo "== switched off / removed"
systemd-run --quiet --unit="$UNIT" --property=Type=exec sleep 600; sleep 0.5
_egress_guard_apply
EGRESS_GUARD=false _egress_guard_apply
_egress_guard_active && bad "still active with EGRESS_GUARD=false" || ok "EGRESS_GUARD=false removes it"
expect open "loopback reachable again" incg tcp http://127.0.0.1:18080/
_egress_guard_apply; _egress_guard_remove
left=$( { iptables -w -S; ip6tables -w -S; } 2>/dev/null | grep -c PQT_EGRESS)
[ "$left" -eq 0 ] && ok "remove leaves no chains or rules (v4+v6)" || bad "$left leftover lines"

echo "== IPv6"
_egress_guard_apply
ip6tables -w -S "$_EGRESS_CHAIN" 2>/dev/null | grep -q -- "-d fe80::/10 -j $_EGRESS_DENY" && ok "IPv6 chain built" || bad "IPv6 chain missing"
ip6tables -w -S OUTPUT | grep -q "$_EGRESS_CHAIN" && ok "IPv6 OUTPUT jump" || bad "IPv6 OUTPUT jump missing"
expect open    "::1 from another process" curl -s -o /dev/null --max-time 3 "http://[::1]:18084/"
expect blocked "::1 from paqet's cgroup"  incg curl -s -o /dev/null --max-time 3 "http://[::1]:18084/"
_egress_guard_remove

echo "== service lifecycle: ExecStartPre builds it, ExecStopPost removes it"
# shellcheck disable=SC2016
systemd-run --quiet --unit="$PRE_UNIT" \
    -p "ExecStartPre=/bin/bash -c 'source $W/env.sh; _EGRESS_CGROUP=system.slice/$PRE_UNIT; _egress_guard_apply; echo pre-rc=\$?'" \
    -p "ExecStopPost=/bin/bash -c 'source $W/env.sh; _EGRESS_CGROUP=system.slice/$PRE_UNIT; _egress_guard_remove'" \
    /bin/bash -c 'curl -s -o /dev/null --max-time 2 http://127.0.0.1:18080/ && echo "main: loopback open" || echo "main: loopback blocked"; sleep 60'
sleep 3
out=$(journalctl -u "$PRE_UNIT" --no-pager -o cat 2>/dev/null)
grep -q "pre-rc=0" <<< "$out" && ok "ExecStartPre installed the guard" || bad "ExecStartPre: $(grep pre-rc <<< "$out")"
grep -q "main: loopback blocked" <<< "$out" && ok "main process is blocked from its first connection" || bad "main process: $(grep main: <<< "$out")"
systemctl stop "$PRE_UNIT"; sleep 0.5
left=$(iptables -w -S | grep -c PQT_EGRESS)
[ "$left" -eq 0 ] && ok "ExecStopPost removed the guard" || bad "$left lines left after stop"

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
