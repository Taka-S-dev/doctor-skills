"""Create real network faults with a known cause in Docker and check the analysis.

Usage: python evals/netlab/run.py [scenario ...]
Requires Docker with a Linux engine and Wireshark's tshark on the host. Containers run on an
isolated bridge network and are removed afterwards. Captures stay in evals/netlab/out/.
"""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from packet_doctor.investigation import analyze, latest  # noqa: E402
from packet_doctor.models import read_json  # noqa: E402
from packet_doctor.twopoint import two_point  # noqa: E402

LAB = Path(__file__).resolve().parent
OUT = LAB / "out"
IMAGE, NETWORK = "packet-netlab:1", "packet-netlab-net"
DOCKERFILE = """FROM python:3.10
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump iproute2 iptables ethtool
"""
DROP_INPUT = "iptables -A INPUT -p tcp --dport 5000 -j DROP"

# name: symptom, server program, firewall/netem commands on the server, client program, expected causes, expected finding codes, forbidden causes
SCENARIOS = {
    "refused": ("接続できない", None, [], "connect", {"no_listener"}, {"tcp_refused"}, {"silent_drop"}),
    "silent_drop": ("接続できない", "echo", [DROP_INPUT], "connect", {"silent_drop", "peer_down"}, {"tcp_no_reply", "tcp_syn_retry_pattern"}, {"no_listener"}),
    "admin_prohibited": ("接続できない", "echo", ["iptables -A INPUT -p tcp --dport 5000 -j REJECT --reject-with icmp-admin-prohibited"], "connect",
                         {"active_reject"}, {"administratively_prohibited"}, {"no_listener"}),
    "loss": ("転送が遅い", "echo", ["tc qdisc add dev eth0 root netem loss 15%"], "bulk", {"path_loss"}, {"tcp_repeated_data"}, set()),
    "slow_application": ("応答が遅い", "slow", [], "slow", {"server_app_delay"}, {"app_response_slow"}, {"path_loss"}),
    "zero_window": ("通信が止まる", "flood", [], "noread", {"receiver_stall"}, {"tcp_zero_window"}, set()),
    "reconnect_wait": ("再接続が遅い", "close", [], "reconnect", {"application_restart_wait"}, {"reconnect_interval_regular"}, set()),
    "mtu_blackhole": ("大きいデータだけ止まる", "echo", ["iptables -A INPUT -p tcp --dport 5000 -m length --length 1000:65535 -j DROP"], "bigsend",
                      {"mtu_blackhole"}, {"tcp_large_segment_loss"}, set()),
}
VANISH = ("突然切れる", "echo", [], "vanish", {"peer_down"}, {"tcp_unanswered_tail"}, set())
SCENARIOS["peer_vanishes"] = VANISH


def docker(*arguments, check=True, capture=True):
    return subprocess.run(["docker", *arguments], check=check, capture_output=capture, text=True, encoding="utf-8", errors="replace")


def execute(container, command, check=True):
    return docker("exec", container, "sh", "-c", command, check=check)


def start_container(name, directory):
    docker("run", "-d", "--rm", "--name", name, "--hostname", name, "--network", NETWORK, "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
           "-v", f"{LAB}:/lab:ro", "-v", f"{directory}:/out", IMAGE, "sleep", "300")
    execute(name, "ethtool -K eth0 tso off gso off gro off >/dev/null 2>&1 || true")


def cleanup():
    docker("rm", "-f", "server", "client", check=False)


def run_scenario(name, specification):
    symptom, server_mode, faults, client_mode, expected, codes, forbidden = specification
    directory = OUT / name
    shutil.rmtree(directory, ignore_errors=True)
    directory.mkdir(parents=True)
    cleanup()
    start_container("server", directory)
    start_container("client", directory)
    for role in ("server", "client"):
        docker("exec", "-d", role, "tcpdump", "-U", "-n", "-i", "eth0", "-s", "0", "-w", f"/out/{role}.pcap", "not port 53")
    time.sleep(1)
    if server_mode:
        docker("exec", "-d", "server", "python", "/lab/lab.py", "server", "--mode", server_mode)
        time.sleep(1)
    for command in faults:
        execute("server", command)
    if client_mode == "vanish":
        docker("exec", "-d", "client", "python", "/lab/lab.py", "client", "--mode", "vanish", "--pause", "5")
        time.sleep(3)
        execute("server", "iptables -A INPUT -p tcp --dport 5000 -j DROP; iptables -A OUTPUT -p tcp --sport 5000 -j DROP")
        time.sleep(13)
    else:
        execute("client", f"python /lab/lab.py client --mode {client_mode}", check=False)
    time.sleep(1)
    for role in ("server", "client"):
        execute(role, "pkill -INT tcpdump; sleep 1", check=False)
    server_ip = docker("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", "server").stdout.strip()
    cleanup()
    case = directory / "case"
    analyze(case, [directory / "client.pcap"], symptom=symptom, target=server_ip, port=5000, observation="クライアントコンテナ")
    _, run, _, analysis = latest(case)
    hypotheses = read_json(run / "hypotheses.json")
    causes = {h.get("cause") for h in hypotheses}
    found = {f["code"] for f in analysis["diagnostics"]["findings"]}
    problems = []
    if not expected <= causes:
        problems.append(f"原因候補が不足: {sorted(expected - causes)}")
    if forbidden & causes:
        problems.append(f"出てはいけない候補: {sorted(forbidden & causes)}")
    if not codes <= found:
        problems.append(f"所見が不足: {sorted(codes - found)}")
    comparison = two_point(directory / "client.pcap", directory / "server.pcap", port=5000)
    return {"scenario": name, "ok": not problems, "problems": problems, "frames": analysis["captures"][0]["packet_count"], "quality": analysis["quality"]["status"],
            "causes": [h.get("cause") for h in hypotheses], "findings": sorted(found),
            "two_point": {"flows": comparison["flows_matched"], "clock_offset_ms": comparison["clock_offset_ms"], "codes": sorted({f["code"] for f in comparison["findings"]})}}


def main():
    names = sys.argv[1:] or list(SCENARIOS)
    OUT.mkdir(parents=True, exist_ok=True)
    (LAB / "Dockerfile.generated").write_text(DOCKERFILE, encoding="utf-8")
    docker("build", "-q", "-t", IMAGE, "-f", str(LAB / "Dockerfile.generated"), str(LAB))
    (LAB / "Dockerfile.generated").unlink()
    docker("network", "create", "--internal", NETWORK, check=False)
    results = []
    try:
        for name in names:
            result = run_scenario(name, SCENARIOS[name])
            results.append(result)
            print(json.dumps(result, ensure_ascii=False), flush=True)
    finally:
        cleanup()
        docker("network", "rm", NETWORK, check=False)
    (OUT / "results.json").write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    failed = [r["scenario"] for r in results if not r["ok"]]
    print(f"{len(results) - len(failed)}/{len(results)} scenarios passed", "failed: " + ", ".join(failed) if failed else "")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
