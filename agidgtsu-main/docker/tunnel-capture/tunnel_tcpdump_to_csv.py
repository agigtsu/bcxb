#!/usr/bin/env python3
import argparse
import csv
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

TCPDUMP_BINARY = shutil.which("tcpdump")
IPV4_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")
ADDRESS_RE = re.compile(r"\[(?P<ipv6>[0-9a-fA-F:]+)\](?::\d+)?$|(?P<ipv4>\d+\.\d+\.\d+\.\d+)(?:\.\d+)?$")


def parse_args():
    parser = argparse.ArgumentParser(description="Capture Cloudflare tunnel traffic and update tunnels.csv with discovered edge IPs.")
    parser.add_argument("--csv", required=True, help="Path to tunnels.csv")
    parser.add_argument("--filter", default="tcp port 443 or udp port 7844", help="tcpdump filter expression")
    parser.add_argument("--duration", type=int, default=20, help="Capture duration in seconds")
    parser.add_argument("--active-status", default="active", help="CSV status value to update")
    return parser.parse_args()


def normalize_address(token):
    token = token.strip("[](),;\n")
    if token.endswith(":"):
        token = token[:-1]

    if token.startswith("[") and token.endswith("]"):
        token = token[1:-1]

    if token.startswith("::ffff:"):
        token = token[7:]

    match = ADDRESS_RE.search(token)
    if match:
        if match.group("ipv4"):
            return match.group("ipv4")
        if match.group("ipv6"):
            return match.group("ipv6")

    return token


def is_public_edge_ip(ip):
    if not (IPV4_RE.fullmatch(ip) or IPV6_RE.fullmatch(ip)):
        return False
    if ip in {"::1", "localhost"}:
        return False
    if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."):
        return False
    if re.match(r"^172\.(1[6-9]|2\d|3[0-1])\.", ip):
        return False
    if ip.startswith("fe80:") or ip.startswith("fc00:") or ip.startswith("fd00:"):
        return False
    return True


def extract_ips_from_line(line):
    if "IP " not in line and "IP6 " not in line:
        return []

    candidates = set()
    for match in re.finditer(r"(?P<src>\S+)\s+>\s+(?P<dst>\S+):", line):
        for token in (match.group("src"), match.group("dst")):
            ip = normalize_address(token)
            if is_public_edge_ip(ip):
                candidates.add(ip)

    if candidates:
        return sorted(candidates)

    for token in re.findall(r"\S+", line):
        ip = normalize_address(token)
        if is_public_edge_ip(ip):
            candidates.add(ip)

    return sorted(candidates)


def run_tcpdump(filter_expr, duration):
    if TCPDUMP_BINARY is None:
        raise SystemExit("tcpdump binary not found in PATH")

    args = [TCPDUMP_BINARY, "-nn", "-l", "-U", "-s", "0", "-i", "any", filter_expr]
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

    edge_ips = set()
    start = time.monotonic()
    try:
        while True:
            if proc.stdout is None:
                break
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break
                continue
            edge_ips.update(extract_ips_from_line(line))
            if time.monotonic() - start >= duration:
                break
    finally:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    return edge_ips


def update_csv(csv_path, edge_ips, active_status):
    csv_path = Path(csv_path)
    if not csv_path.exists():
        raise SystemExit(f"CSV file does not exist: {csv_path}")

    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = list(csv.reader(f))

    if not reader:
        raise SystemExit("CSV file is empty")

    header = reader[0]
    expected_fields = ["tunnel_id", "tunnel_name", "domain", "token", "status", "redirect_port", "edge_ips", "routes", "clients", "latency_ms", "created_date", "notes"]
    if header[: len(expected_fields)] != expected_fields[: len(header)]:
        # Allow header to be a superset, but preserve all columns
        pass

    edge_ips_value = ";".join(sorted(edge_ips))
    temp_file = csv_path.parent / f"{csv_path.name}.tmp"

    with tempfile.NamedTemporaryFile("w", delete=False, dir=csv_path.parent, newline="", encoding="utf-8") as tmp:
        writer = csv.writer(tmp)
        writer.writerow(reader[0])

        for row in reader[1:]:
            if len(row) < 7:
                row.extend([""] * (7 - len(row)))
            status = row[4].strip() if len(row) > 4 else ""
            if status.lower() == active_status.lower() and row[6].strip() == "":
                row[6] = edge_ips_value
            elif status.lower() == active_status.lower() and row[6].strip() != "":
                existing = set(x.strip() for x in row[6].split(";") if x.strip())
                merged = sorted(existing.union(edge_ips))
                row[6] = ";".join(merged)
            writer.writerow(row)

    os.replace(tmp.name, temp_file)
    os.replace(temp_file, csv_path)


def main():
    args = parse_args()
    edge_ips = run_tcpdump(args.filter, args.duration)
    if not edge_ips:
        print("No new edge IPs detected during capture period.")
        return 0

    print(f"Discovered {len(edge_ips)} unique edge IP(s): {', '.join(edge_ips)}")
    update_csv(args.csv, edge_ips, args.active_status)
    print(f"Updated {args.csv} with discovered edge_ips.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
