#!/usr/bin/env python3
"""
MSSQL CVE Version Validator
===========================

Non-intrusive MSSQL validation script.

What it does:
  - Connects to MSSQL TCP port 1433
  - Sends a TDS Pre-Login packet
  - Reads the SQL Server version from the response
  - Compares the version against known affected CVE ranges
  - Reports VULNERABLE / NOT VULNERABLE based on version range

What it does NOT do:
  - Does not exploit SQL Server
  - Does not authenticate
  - Does not run SQL queries
  - Does not modify the target

Usage:
  python3 poc_mssql_validate.py
  python3 poc_mssql_validate.py 10.147.34.213
  python3 poc_mssql_validate.py 10.147.34.213 10.147.34.254
  python3 poc_mssql_validate.py 10.147.34.213 --json

Default targets:
  10.147.34.213
  10.147.34.254
"""

import argparse
import json
import socket
import struct
import sys
from datetime import datetime


DEFAULT_TARGETS = [
    "10.147.34.213",
    "10.147.34.254",
]

DEFAULT_PORT = 1433
DEFAULT_TIMEOUT = 10


# Vulnerable ranges use:
#   start inclusive, end exclusive
# If detected version is:
#   start <= version < end
# then it is considered vulnerable.
CVE_DATABASE = {
    "CVE-2026-20803": {
        "description": (
            "Missing authentication for critical function in SQL Server allows "
            "an authorized attacker to elevate privileges over a network."
        ),
        "severity": "HIGH",
        "cvss": "7.2",
        "cwe": "CWE-306",
        "source": "PwC Item 31",
        "published": "2026-01-13",
        "fix_kb": "KB5072936 / Jan 2026 SQL Server 2022 CU22",
        "ranges": {
            "SQL Server 2022 GDR": ((16, 0, 1000, 6), (16, 0, 1165, 1)),
            "SQL Server 2022 CU":  ((16, 0, 4003, 1), (16, 0, 4230, 2)),
        },
    },
    "CVE-2025-59499": {
        "description": (
            "SQL injection in SQL Server allows an authorized attacker "
            "to elevate privileges over a network."
        ),
        "severity": "HIGH",
        "cvss": "8.8",
        "cwe": "CWE-89",
        "source": "PwC Item 31",
        "published": "2025-11-11",
        "fix_kb": "Nov 2025 SQL Server security update",
        "ranges": {
            "SQL Server 2019 GDR": ((15, 0, 2000, 5), (15, 0, 2155, 2)),
            "SQL Server 2019 CU":  ((15, 0, 4003, 23), (15, 0, 4455, 2)),
            "SQL Server 2022 GDR": ((16, 0, 1000, 6), (16, 0, 1160, 1)),
            "SQL Server 2022 CU":  ((16, 0, 4003, 1), (16, 0, 4222, 2)),
        },
    },
    "CVE-2026-21262": {
        "description": (
            "Improper access control in SQL Server allows an authorized "
            "attacker to elevate privileges over a network."
        ),
        "severity": "HIGH",
        "cvss": "8.8",
        "cwe": "CWE-284",
        "source": "Nessus Plugin 301981 / KB5077464",
        "published": "2026-03-10",
        "fix_kb": "KB5077464 / Mar 2026 SQL Server 2022 CU23",
        "ranges": {
            "SQL Server 2019 GDR": ((15, 0, 2000, 5), (15, 0, 2160, 4)),
            "SQL Server 2019 CU":  ((15, 0, 4003, 23), (15, 0, 4460, 4)),
            "SQL Server 2022 GDR": ((16, 0, 1000, 6), (16, 0, 1170, 5)),
            "SQL Server 2022 CU":  ((16, 0, 4003, 1), (16, 0, 4240, 4)),
        },
    },
    "CVE-2026-26115": {
        "description": (
            "Improper validation of specified type of input in SQL Server "
            "allows an authorized attacker to elevate privileges."
        ),
        "severity": "HIGH",
        "cvss": "8.8",
        "cwe": "CWE-1287",
        "source": "Nessus Plugin 301981 / KB5077464",
        "published": "2026-03-10",
        "fix_kb": "KB5077464 / Mar 2026 SQL Server 2022 CU23",
        "ranges": {
            "SQL Server 2019 GDR": ((15, 0, 2000, 5), (15, 0, 2160, 4)),
            "SQL Server 2019 CU":  ((15, 0, 4003, 23), (15, 0, 4460, 4)),
            "SQL Server 2022 GDR": ((16, 0, 1000, 6), (16, 0, 1170, 5)),
            "SQL Server 2022 CU":  ((16, 0, 4003, 1), (16, 0, 4240, 4)),
        },
    },
    "CVE-2026-26116": {
        "description": "Privilege escalation vulnerability in SQL Server.",
        "severity": "HIGH",
        "cvss": "8.8",
        "cwe": "N/A",
        "source": "Nessus Plugin 301981 / KB5077464",
        "published": "2026-03-10",
        "fix_kb": "KB5077464 / Mar 2026 SQL Server 2022 CU23",
        "ranges": {
            "SQL Server 2019 GDR": ((15, 0, 2000, 5), (15, 0, 2160, 4)),
            "SQL Server 2019 CU":  ((15, 0, 4003, 23), (15, 0, 4460, 4)),
            "SQL Server 2022 GDR": ((16, 0, 1000, 6), (16, 0, 1170, 5)),
            "SQL Server 2022 CU":  ((16, 0, 4003, 1), (16, 0, 4240, 4)),
        },
    },
}


def build_prelogin_packet() -> bytes:
    """Build a minimal TDS Pre-Login packet."""
    version_data = struct.pack(">BBHH", 0x00, 0x00, 0x0000, 0x0000)
    encryption_data = struct.pack("B", 0x02)  # ENCRYPT_NOT_SUP

    # OPTION token table:
    # VERSION    = 0x00
    # ENCRYPTION = 0x01
    # TERMINATOR = 0xFF
    header_size = 11
    version_offset = header_size
    version_length = 6
    encryption_offset = version_offset + version_length
    encryption_length = 1

    options = b""
    options += struct.pack(">BHH", 0x00, version_offset, version_length)
    options += struct.pack(">BHH", 0x01, encryption_offset, encryption_length)
    options += struct.pack("B", 0xFF)

    payload = options + version_data + encryption_data
    tds_length = 8 + len(payload)

    # TDS packet header:
    # type=0x12 Pre-Login, status=0x01 EOM
    tds_header = struct.pack(">BBHHBB", 0x12, 0x01, tds_length, 0x0000, 0x01, 0x00)
    return tds_header + payload


def parse_prelogin_response(data: bytes):
    """Parse SQL Server version from a TDS Pre-Login response."""
    if len(data) < 8:
        return None

    payload = data[8:]
    i = 0
    version_offset = None
    version_length = None

    while i < len(payload):
        token_type = payload[i]

        if token_type == 0xFF:
            break

        if i + 4 >= len(payload):
            break

        offset = struct.unpack(">H", payload[i + 1:i + 3])[0]
        length = struct.unpack(">H", payload[i + 3:i + 5])[0]

        if token_type == 0x00:
            version_offset = offset
            version_length = length

        i += 5

    if version_offset is None or version_length is None:
        return None

    ver_data = payload[version_offset:version_offset + version_length]

    if len(ver_data) < 6:
        return None

    major = ver_data[0]
    minor = ver_data[1]
    build = struct.unpack(">H", ver_data[2:4])[0]
    sub_build = struct.unpack(">H", ver_data[4:6])[0]

    return major, minor, build, sub_build


def get_mssql_version(ip: str, port: int, timeout: int):
    """Connect to MSSQL and retrieve version via TDS Pre-Login."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            sock.sendall(build_prelogin_packet())
            response = sock.recv(4096)

        version = parse_prelogin_response(response)
        if version is None:
            return "NO_VERSION_IN_RESPONSE"

        return version

    except socket.timeout:
        return "TIMEOUT"
    except ConnectionRefusedError:
        return "REFUSED"
    except OSError as exc:
        return f"ERROR: {exc}"


def version_str(version) -> str:
    if isinstance(version, tuple) and len(version) == 4:
        return f"{version[0]}.{version[1]}.{version[2]}.{version[3]}"
    return str(version)


def sql_product_name(version) -> str:
    products = {
        16: "SQL Server 2022",
        15: "SQL Server 2019",
        14: "SQL Server 2017",
        13: "SQL Server 2016",
    }

    if isinstance(version, tuple):
        return products.get(version[0], f"SQL Server major={version[0]}")

    return "Unknown"


def version_in_range(version, start, end) -> bool:
    return start <= version < end


def check_cve(version, cve_info):
    for branch_name, (start, end) in cve_info["ranges"].items():
        if version_in_range(version, start, end):
            return True, branch_name, end
    return False, None, None


def test_target(ip: str, port: int, timeout: int):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    version = get_mssql_version(ip, port, timeout)

    result = {
        "ip": ip,
        "port": port,
        "timestamp": timestamp,
        "method": "TDS Pre-Login version fingerprint + CVE range matching",
        "status": None,
        "version": None,
        "product": None,
        "cves": {},
    }

    if not isinstance(version, tuple):
        result["status"] = "unreachable_or_unverified"
        result["error"] = str(version)
        return result

    result["status"] = "tested"
    result["version"] = version_str(version)
    result["product"] = sql_product_name(version)

    for cve_id, cve_info in CVE_DATABASE.items():
        vulnerable, branch, fix_version = check_cve(version, cve_info)

        cve_result = {
            "vulnerable": vulnerable,
            "severity": cve_info["severity"],
            "cvss": cve_info["cvss"],
            "cwe": cve_info["cwe"],
            "source": cve_info["source"],
            "description": cve_info["description"],
            "published": cve_info["published"],
            "fix_kb": cve_info["fix_kb"],
        }

        if vulnerable:
            cve_result["branch"] = branch
            cve_result["fixed_version_required"] = version_str(fix_version)

        result["cves"][cve_id] = cve_result

    return result


def print_human(results):
    print("=" * 90)
    print("MSSQL CVE VERSION VALIDATION")
    print("Method: TDS Pre-Login version fingerprint + CVE range matching")
    print("=" * 90)

    total_vuln = 0
    total_pass = 0
    tested = 0
    failed = 0

    for result in results:
        print()
        print("-" * 90)
        print(f"TARGET: {result['ip']}:{result['port']}")
        print("-" * 90)

        if result["status"] != "tested":
            failed += 1
            print(f"CONNECTION: FAILED / UNVERIFIED ({result.get('error', 'unknown error')})")
            print("RESULT: Cannot verify remotely. Try on-host SQL version check if required.")
            continue

        tested += 1
        print(f"CONNECTION: SUCCESS")
        print(f"VERSION:    {result['version']} ({result['product']})")
        print()

        for cve_id, cve in result["cves"].items():
            if cve["vulnerable"]:
                total_vuln += 1
                print(f"❌ {cve_id} — VULNERABLE")
                print(f"   Branch:      {cve['branch']}")
                print(f"   Severity:    {cve['severity']} / CVSS {cve['cvss']}")
                print(f"   CWE:         {cve['cwe']}")
                print(f"   Source:      {cve['source']}")
                print(f"   Fix:         Upgrade to >= {cve['fixed_version_required']} ({cve['fix_kb']})")
                print()
            else:
                total_pass += 1
                print(f"✅ {cve_id} — NOT VULNERABLE by version range")

    print()
    print("=" * 90)
    print("SUMMARY")
    print("=" * 90)
    print(f"Hosts tested:       {tested}")
    print(f"Hosts unverified:   {failed}")
    print(f"CVE checks failed:  {total_vuln}")
    print(f"CVE checks passed:  {total_pass}")

    if total_vuln > 0:
        print()
        print("RESULT: Remediation may NOT be complete on one or more reachable hosts.")
        return 1

    if tested > 0 and total_vuln == 0:
        print()
        print("RESULT: No reachable host matched the vulnerable version ranges.")
        return 0

    return 2


def main():
    parser = argparse.ArgumentParser(
        description="MSSQL CVE version validator using TDS Pre-Login."
    )

    parser.add_argument(
        "targets",
        nargs="*",
        help=(
            "Target IP(s). Example: python3 poc_mssql_validate.py 10.147.34.213 "
            "If omitted, defaults to 10.147.34.213 and 10.147.34.254."
        ),
    )

    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"MSSQL port. Default: {DEFAULT_PORT}",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Socket timeout in seconds. Default: {DEFAULT_TIMEOUT}",
    )

    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="Print JSON output.",
    )

    args = parser.parse_args()

    targets = args.targets if args.targets else DEFAULT_TARGETS

    results = [
        test_target(ip=target, port=args.port, timeout=args.timeout)
        for target in targets
    ]

    if args.json:
        output = {
            "scan_type": "MSSQL CVE Version Validation",
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "default_targets": DEFAULT_TARGETS,
            "results": results,
        }
        print(json.dumps(output, indent=2))
        return 1 if any(
            cve["vulnerable"]
            for result in results
            for cve in result.get("cves", {}).values()
        ) else 0

    return print_human(results)


if __name__ == "__main__":
    sys.exit(main())
