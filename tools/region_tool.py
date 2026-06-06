#!/usr/bin/env python3
"""Local region metadata and firewall command helper."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGIONS_JSON = ROOT / "data" / "regions.json"
DEFAULT_DATA_DIR = ROOT / "data"
SET_PREFIX = "wl_"
CHAIN_PREFIX = "WL_"
ENTRY_CHAINS = ("INPUT", "FORWARD")


def load_metadata(regions_json: Path) -> dict:
    return json.loads(regions_json.read_text(encoding="utf-8"))


def list_provinces(metadata: dict) -> list[tuple[int, str, str]]:
    return [
        (index, str(province["code"]), str(province["name"]))
        for index, province in enumerate(metadata["provinces"], 1)
    ]


def find_province(metadata: dict, code: str) -> dict:
    for province in metadata["provinces"]:
        if str(province["code"]) == code:
            return province
    raise SystemExit(f"Unknown province code: {code}")


def resolve_province(metadata: dict, selector: str) -> dict:
    selector = selector.strip()
    normalized = normalize_name(selector)
    matches = []
    for index, province in enumerate(metadata["provinces"], 1):
        province_name = str(province["name"])
        if (
            selector == str(index)
            or selector == str(province["code"])
            or selector == province_name
            or normalized == normalize_name(province_name)
        ):
            matches.append(province)
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise SystemExit(f"未找到省份：{selector}")
    raise SystemExit(f"省份名称不唯一：{selector}")


def resolve_city(metadata: dict, province_selector: str, city_selector: str) -> dict:
    province = resolve_province(metadata, province_selector)
    city_selector = city_selector.strip()
    normalized = normalize_name(city_selector)
    for index, city in enumerate(province.get("cities", []), 1):
        city_name = str(city["name"])
        if (
            city_selector == str(index)
            or city_selector == str(city["code"])
            or city_selector == city_name
            or normalized == normalize_name(city_name)
        ):
            return city
    raise SystemExit(f"在 {province['name']} 中未找到城市：{city_selector}")


def normalize_name(name: str) -> str:
    suffixes = [
        "特别行政区",
        "维吾尔自治区",
        "壮族自治区",
        "回族自治区",
        "自治区",
        "省",
        "市",
        "地区",
        "盟",
    ]
    result = name.strip()
    for suffix in suffixes:
        if result.endswith(suffix):
            result = result[: -len(suffix)]
            break
    return result


def list_cities(metadata: dict, province_code: str) -> list[tuple[int, str, str]]:
    province = find_province(metadata, province_code)
    return [
        (index, str(city["code"]), str(city["name"]))
        for index, city in enumerate(province.get("cities", []), 1)
    ]


def find_region_file(metadata: dict, code: str) -> str:
    for province in metadata["provinces"]:
        if str(province["code"]) == code:
            return str(province["file"])
        for city in province.get("cities", []):
            if str(city["code"]) == code:
                return str(city["file"])
    raise SystemExit(f"Unknown region code: {code}")


def collect_cidrs(metadata: dict, data_dir: Path, codes: list[str]) -> tuple[list[str], list[str]]:
    """Collect CIDRs from region codes and manual IPs. Returns (all_cidrs, manual_ips)."""
    seen: set[str] = set()
    cidrs: list[str] = []
    manual_ips: list[str] = []

    for code in codes:
        # 检查是否为手动输入的 IP/CIDR（包含点号）
        if "." in code:
            # 验证并添加手动 IP/CIDR
            try:
                ipaddress.ip_network(code, strict=False)
                if code not in seen:
                    seen.add(code)
                    cidrs.append(code)
                    manual_ips.append(code)
            except ValueError:
                raise SystemExit(f"Invalid IP/CIDR: {code}")
            continue

        # 处理地区代码
        region_file = data_dir / find_region_file(metadata, code)
        if not region_file.exists():
            raise SystemExit(f"Missing region file: {region_file}")
        for raw_line in region_file.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            ipaddress.ip_network(line, strict=False)
            if line not in seen:
                seen.add(line)
                cidrs.append(line)

    return cidrs, manual_ips


def parse_ports(raw: str) -> list[str]:
    tokens = [token for token in re.split(r"[\s,，、]+", raw.strip()) if token]
    if not tokens:
        raise argparse.ArgumentTypeError("ports are required")

    seen: set[str] = set()
    ports: list[str] = []
    for token in tokens:
        if not token.isdigit():
            raise argparse.ArgumentTypeError(f"invalid port: {token}")
        port = int(token)
        if port < 1 or port > 65535:
            raise argparse.ArgumentTypeError(f"port out of range: {token}")
        normalized = str(port)
        if normalized not in seen:
            seen.add(normalized)
            ports.append(normalized)
    return ports


def set_name_for_port(port: str) -> str:
    return f"{SET_PREFIX}{port}"


def chain_name_for_port(port: str) -> str:
    return f"{CHAIN_PREFIX}{port}"


def render_apply_commands(cidrs: list[str], ports: list[str], client_ip: str = "", manual_ips: list[str] | None = None) -> list[str]:
    if client_ip:
        ipaddress.ip_address(client_ip)

    if manual_ips is None:
        manual_ips = []

    commands: list[str] = []

    # 在 INPUT 和 FORWARD 链最前面放行 lo 接口流量
    for chain in ENTRY_CHAINS:
        lo_rule = f"-i lo -j ACCEPT"
        commands.append(
            f"iptables -C {chain} {lo_rule} 2>/dev/null || "
            f"iptables -I {chain} 1 {lo_rule}"
        )

    for port in ports:
        set_name = set_name_for_port(port)
        chain_name = chain_name_for_port(port)
        commands.append(f"ipset create {set_name} hash:net family inet -exist")
        for cidr in cidrs:
            commands.append(f"ipset add {set_name} {cidr} -exist")
        for manual_ip in manual_ips:
            commands.append(f"ipset add {set_name} {manual_ip} -exist")
        if client_ip:
            commands.append(f"ipset add {set_name} {client_ip} -exist")

        commands.append(f"iptables -N {chain_name} 2>/dev/null || true")
        commands.append(
            f"iptables -C INPUT -j {chain_name} 2>/dev/null || "
            f"iptables -I INPUT 1 -j {chain_name}"
        )
        commands.append(
            f"while iptables -C FORWARD -j {chain_name} 2>/dev/null; "
            f"do iptables -D FORWARD -j {chain_name}; done"
        )
        forward_jump = f"-m conntrack --ctstate DNAT -j {chain_name}"
        commands.append(
            f"iptables -C FORWARD {forward_jump} 2>/dev/null || "
            f"iptables -I FORWARD 1 {forward_jump}"
        )
        for protocol in ("tcp", "udp"):
            port_match = f"-p {protocol} --dport {port}"
            accept_rule = f"{port_match} -m set --match-set {set_name} src -j ACCEPT"
            reject_rule = f"{port_match} -j REJECT"
            commands.extend(
                [
                    f"iptables -C {chain_name} {accept_rule} 2>/dev/null || iptables -A {chain_name} {accept_rule}",
                    f"iptables -C {chain_name} {reject_rule} 2>/dev/null || iptables -A {chain_name} {reject_rule}",
                ]
            )
    return commands


def list_managed_ports() -> list[str]:
    """List all ports currently managed by whitelist rules."""
    try:
        result = subprocess.run(
            ["iptables", "-S"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return []

        ports = []
        for line in result.stdout.splitlines():
            if f"-N {CHAIN_PREFIX}" in line:
                parts = line.split()
                if len(parts) >= 2:
                    chain_name = parts[1]
                    if chain_name.startswith(CHAIN_PREFIX):
                        port = chain_name[len(CHAIN_PREFIX):]
                        if port and port not in ports:
                            ports.append(port)
        return sorted(ports, key=lambda p: int(p) if p.isdigit() else 999999)
    except Exception:
        return []


def render_clear_commands(ports: list[str] | None = None) -> list[str]:
    """Render commands to clear whitelist rules. If ports is None, clear all."""
    commands = []

    if ports is None:
        commands.append(
            f"for chain in $(iptables -S | awk '/^-N {CHAIN_PREFIX}/ {{print $2}}'); do "
            f"while iptables -C INPUT -j $chain 2>/dev/null; do iptables -D INPUT -j $chain; done; "
            f"while iptables -C FORWARD -j $chain 2>/dev/null; do iptables -D FORWARD -j $chain; done; "
            f"while iptables -C FORWARD -m conntrack --ctstate DNAT -j $chain 2>/dev/null; do iptables -D FORWARD -m conntrack --ctstate DNAT -j $chain; done; done"
        )
        commands.extend(
            [
                f"for chain in $(iptables -S | awk '/^-N {CHAIN_PREFIX}/ {{print $2}}'); do iptables -F $chain 2>/dev/null || true; iptables -X $chain 2>/dev/null || true; done",
                f"for set_name in $(ipset list -name 2>/dev/null | awk '/^{SET_PREFIX}/'); do ipset destroy $set_name 2>/dev/null || true; done",
            ]
        )
    else:
        for port in ports:
            chain_name = chain_name_for_port(port)
            set_name = set_name_for_port(port)
            commands.extend(
                [
                    f"while iptables -C INPUT -j {chain_name} 2>/dev/null; do iptables -D INPUT -j {chain_name}; done",
                    f"while iptables -C FORWARD -j {chain_name} 2>/dev/null; do iptables -D FORWARD -j {chain_name}; done",
                    f"while iptables -C FORWARD -m conntrack --ctstate DNAT -j {chain_name} 2>/dev/null; do iptables -D FORWARD -m conntrack --ctstate DNAT -j {chain_name}; done",
                    f"iptables -F {chain_name} 2>/dev/null || true",
                    f"iptables -X {chain_name} 2>/dev/null || true",
                    f"ipset destroy {set_name} 2>/dev/null || true",
                ]
            )
    return commands


def build_cidr_to_region_map(data_dir: Path) -> dict[str, str]:
    """Build reverse mapping from CIDR to region code."""
    cidr_to_region: dict[str, str] = {}
    regions_dir = data_dir / "regions"
    if not regions_dir.exists():
        return cidr_to_region

    for region_file in regions_dir.glob("*.txt"):
        region_code = region_file.stem
        try:
            cidrs = region_file.read_text(encoding="utf-8").strip().split("\n")
            for cidr in cidrs:
                cidr = cidr.strip()
                if cidr and not cidr.startswith("#"):
                    cidr_to_region[cidr] = region_code
                    # ipset normalizes /32 to IP without suffix, so map both forms
                    if cidr.endswith("/32"):
                        ip_without_suffix = cidr[:-3]
                        cidr_to_region[ip_without_suffix] = region_code
        except Exception:
            continue

    return cidr_to_region


def get_ipset_members(set_name: str) -> list[str]:
    """Get list of CIDR members from an ipset."""
    try:
        result = subprocess.run(
            ["ipset", "list", set_name, "-output", "plain"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return []

        members = []
        in_members = False
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Members:"):
                in_members = True
                continue
            if in_members and line:
                members.append(line)

        return members
    except Exception:
        return []


def lookup_region_name(metadata: dict, code: str) -> str:
    """Look up region name by code (province or city)."""
    for province in metadata["provinces"]:
        if str(province["code"]) == code:
            return str(province["name"])
        for city in province.get("cities", []):
            if str(city["code"]) == code:
                return f"{province['name']} > {city['name']}"
    return f"未知地区 ({code})"


def render_status_command(metadata: dict, data_dir: Path, metadata_dir: Path | None = None) -> int:
    """Render human-readable status of current whitelist rules."""
    try:
        result = subprocess.run(
            ["ipset", "list", "-name"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            print("无法读取 ipset 列表")
            return 1

        set_names = [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip().startswith(SET_PREFIX)
        ]

        if not set_names:
            print("未配置任何白名单规则")
            return 0

        cidr_to_region = build_cidr_to_region_map(data_dir)

        for set_name in sorted(set_names):
            port = set_name[len(SET_PREFIX):]
            members = get_ipset_members(set_name)

            if not members:
                print(f"端口 {port} (TCP/UDP): (空)")
                print()
                continue

            # 读取手动添加的 IP
            manual_ips_set = set()
            if metadata_dir:
                manual_ips_file = metadata_dir / f"manual_ips_{port}.txt"
                if manual_ips_file.exists():
                    manual_ips_set = set(manual_ips_file.read_text(encoding="utf-8").strip().split("\n"))
                    manual_ips_set.discard("")

            region_codes = set()
            manual_cidrs = []
            unknown_cidrs = []

            for cidr in members:
                if cidr in manual_ips_set:
                    manual_cidrs.append(cidr)
                elif cidr in cidr_to_region:
                    region_codes.add(cidr_to_region[cidr])
                else:
                    unknown_cidrs.append(cidr)

            print(f"端口 {port} (TCP/UDP):")

            for code in sorted(region_codes):
                region_name = lookup_region_name(metadata, code)
                print(f"  - {region_name}")

            if manual_cidrs:
                print(f"  - 手动添加: {', '.join(manual_cidrs[:5])}")
                if len(manual_cidrs) > 5:
                    print(f"    ... 及其他 {len(manual_cidrs) - 5} 个")

            if unknown_cidrs:
                print(f"  - 未知来源: {', '.join(unknown_cidrs[:5])}")
                if len(unknown_cidrs) > 5:
                    print(f"    ... 及其他 {len(unknown_cidrs) - 5} 个")

            print()

        return 0

    except Exception as e:
        print(f"错误: {e}")
        return 1


def print_rows(rows: list[tuple[int, str, str]]) -> None:
    for index, code, name in rows:
        print(f"{index}\t{code}\t{name}")


def show_provinces(metadata: dict) -> None:
    print("可选省份：")
    for index, _code, name in list_provinces(metadata):
        print(f"{index}.{name}")


def show_cities(metadata: dict, province_selector: str) -> None:
    province = resolve_province(metadata, province_selector)
    print(f"{province['name']} 可选城市：")
    print("0.全市" if str(province["name"]).endswith("市") else "0.全省")
    cities = list_cities(metadata, str(province["code"]))
    if not cities:
        print("   该地区暂无市级细分，请选择全省。")
        return
    for index, _code, name in cities:
        print(f"{index}.{name}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--regions-json", type=Path, default=DEFAULT_REGIONS_JSON)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list-provinces")

    subparsers.add_parser("show-provinces")

    cities = subparsers.add_parser("list-cities")
    cities.add_argument("province_code")

    show_cities_parser = subparsers.add_parser("show-cities")
    show_cities_parser.add_argument("province_selector")

    resolve_province_parser = subparsers.add_parser("resolve-province")
    resolve_province_parser.add_argument("selector")

    resolve_city_parser = subparsers.add_parser("resolve-city")
    resolve_city_parser.add_argument("province_selector")
    resolve_city_parser.add_argument("city_selector")

    cidrs = subparsers.add_parser("collect-cidrs")
    cidrs.add_argument("codes", nargs="+")

    render = subparsers.add_parser("render-apply")
    render.add_argument("--client-ip", default="")
    render.add_argument("--ports", required=True, type=parse_ports)
    render.add_argument("--manual-ips", default="")
    render.add_argument("--metadata-dir", default="")
    render.add_argument("codes", nargs="*")

    clear_parser = subparsers.add_parser("render-clear")
    clear_parser.add_argument("--ports", type=parse_ports, default=None)

    status_parser = subparsers.add_parser("render-status")
    status_parser.add_argument("--metadata-dir", default="")

    subparsers.add_parser("list-managed-ports")

    return parser


def main() -> int:
    args = build_parser().parse_args()
    metadata = load_metadata(args.regions_json)

    if args.command == "list-provinces":
        print_rows(list_provinces(metadata))
    elif args.command == "show-provinces":
        show_provinces(metadata)
    elif args.command == "list-cities":
        print_rows(list_cities(metadata, args.province_code))
    elif args.command == "show-cities":
        show_cities(metadata, args.province_selector)
    elif args.command == "resolve-province":
        print(resolve_province(metadata, args.selector)["code"])
    elif args.command == "resolve-city":
        print(resolve_city(metadata, args.province_selector, args.city_selector)["code"])
    elif args.command == "collect-cidrs":
        cidrs, _ = collect_cidrs(metadata, args.data_dir, args.codes)
        print("\n".join(cidrs))
    elif args.command == "render-apply":
        cidrs, manual_ips_from_codes = collect_cidrs(metadata, args.data_dir, args.codes)

        # 合并从 --manual-ips 和 codes 中提取的手动 IP
        all_manual_ips = list(manual_ips_from_codes)
        if args.manual_ips:
            extra_manual_ips = [ip.strip() for ip in args.manual_ips.split(",") if ip.strip()]
            all_manual_ips.extend(extra_manual_ips)

        # 验证至少有一个 IP 来源
        extra_manual_ips = [ip.strip() for ip in args.manual_ips.split(",") if ip.strip()] if args.manual_ips else []
        if not cidrs and not extra_manual_ips and not args.client_ip:
            raise SystemExit("No CIDR ranges, manual IPs, or client IP provided")

        # 保存手动 IP 元数据
        if args.metadata_dir and all_manual_ips:
            metadata_dir = Path(args.metadata_dir)
            metadata_dir.mkdir(parents=True, exist_ok=True)
            for port in args.ports:
                port_metadata_file = metadata_dir / f"manual_ips_{port}.txt"
                existing_ips = set()
                if port_metadata_file.exists():
                    existing_ips = set(line.strip() for line in port_metadata_file.read_text(encoding="utf-8").splitlines() if line.strip())
                existing_ips.update(all_manual_ips)
                port_metadata_file.write_text("\n".join(sorted(existing_ips)) + "\n", encoding="utf-8")

        # 如果有 client_ip 且指定了元数据目录，也记录为手动添加
        if args.metadata_dir and args.client_ip:
            metadata_dir = Path(args.metadata_dir)
            metadata_dir.mkdir(parents=True, exist_ok=True)
            for port in args.ports:
                port_metadata_file = metadata_dir / f"manual_ips_{port}.txt"
                existing_ips = set()
                if port_metadata_file.exists():
                    existing_ips = set(line.strip() for line in port_metadata_file.read_text(encoding="utf-8").splitlines() if line.strip())
                existing_ips.add(args.client_ip)
                port_metadata_file.write_text("\n".join(sorted(existing_ips)) + "\n", encoding="utf-8")

        print("\n".join(render_apply_commands(cidrs, args.ports, args.client_ip, extra_manual_ips)))
    elif args.command == "render-clear":
        print("\n".join(render_clear_commands(args.ports)))
    elif args.command == "render-status":
        metadata_dir = Path(args.metadata_dir) if args.metadata_dir else None
        return render_status_command(metadata, args.data_dir, metadata_dir)
    elif args.command == "list-managed-ports":
        ports = list_managed_ports()
        if ports:
            print("\n".join(ports))
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
