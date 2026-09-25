#!/usr/bin/env python3
"""
Genki Scanner - CLI Entry Point
Custom Web Vulnerability Scanner for authorized security testing.

Usage:
  python -m genki_scanner.run -u https://target.com/page?id=1
  python -m genki_scanner.run -u https://target.com -m sqli,xss,lfi
  python -m genki_scanner.run -f urls.txt -m all --delay 2
  python -m genki_scanner.run -u https://target.com --curl-test "curl -sk https://target.com"

Genki Tech Labs / Anbu Black Ops
"""
import argparse
import sys
import os

from .core.config import ScanConfig
from .core.scanner import GenkiScanner, ALL_MODULES


def banner():
    print(r"""
   ___            _    _   ___
  / __|___ _ _   | |__(_) / __| __ __ _ _ _  _ _  ___ _ _
 | (_ / -_) ' \  | / /| | \__ \/ _/ _` | ' \| ' \/ -_) '_|
  \___\___|_||_| |_\_\|_| |___/\__\__,_|_||_|_||_\___|_|

  v1.0 - Genki Tech Labs / Anbu Black Ops
  Custom Web Vulnerability Scanner
  For authorized security testing only.
""")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Genki Scanner - Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://target.com/search?q=test
  %(prog)s -u https://target.com -m sqli,xss --delay 2
  %(prog)s -f urls.txt -m all -o results.json
  %(prog)s -u https://target.com --scope target.com,api.target.com
  %(prog)s --curl-test "curl -sk https://target.com/api/v1/users"

Modules: """ + ", ".join(ALL_MODULES.keys()),
    )

    target_group = parser.add_argument_group("target")
    target_group.add_argument("-u", "--url", help="Target URL")
    target_group.add_argument("-f", "--file", help="File with URLs (one per line)")

    scan_group = parser.add_argument_group("scan options")
    scan_group.add_argument(
        "-m", "--modules",
        default="all",
        help="Modules to run (comma-separated, or 'all'). Available: " + ", ".join(ALL_MODULES.keys()),
    )
    scan_group.add_argument(
        "-p", "--params",
        help="Extra params to test (key=value,key2=value2)",
    )
    scan_group.add_argument(
        "--scope",
        help="Scope domains (comma-separated). Only scan URLs matching these domains.",
    )

    http_group = parser.add_argument_group("http options")
    http_group.add_argument("--delay", type=float, default=1.0, help="Delay between requests in seconds (default: 1.0)")
    http_group.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    http_group.add_argument("--proxy", help="HTTP proxy (e.g., http://127.0.0.1:8080)")
    http_group.add_argument("--cookie", help="Cookies (name=value;name2=value2)")
    http_group.add_argument("--header", action="append", help="Extra header (Name: Value). Can be used multiple times.")
    http_group.add_argument("--user-agent", help="Custom User-Agent string")
    http_group.add_argument("--follow-redirects", action="store_true", help="Follow HTTP redirects")

    output_group = parser.add_argument_group("output")
    output_group.add_argument("-o", "--output", help="Save results to JSON file")
    output_group.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    curl_group = parser.add_argument_group("curl")
    curl_group.add_argument(
        "--curl-test",
        help="Run a raw curl command for manual testing (quote the full curl command)",
    )

    return parser.parse_args()


def main():
    banner()
    args = parse_args()

    if args.curl_test:
        import subprocess
        import shlex
        print(f"[CURL] {args.curl_test}")
        print("-" * 40)
        try:
            cmd = shlex.split(args.curl_test)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            print(result.stdout)
            if result.stderr:
                print(f"[STDERR] {result.stderr}")
        except Exception as e:
            print(f"[ERROR] {e}")
        return

    if not args.url and not args.file:
        print("[ERROR] Provide -u URL or -f FILE")
        sys.exit(1)

    urls = []
    if args.url:
        urls.append(args.url)
    if args.file:
        if not os.path.exists(args.file):
            print(f"[ERROR] File not found: {args.file}")
            sys.exit(1)
        with open(args.file) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)

    config = ScanConfig(
        delay=args.delay,
        timeout=args.timeout,
        proxy=args.proxy,
        follow_redirects=args.follow_redirects,
        verbose=args.verbose,
        output_file=args.output,
    )

    if args.user_agent:
        config.user_agent = args.user_agent

    if args.cookie:
        config.cookies = {}
        for pair in args.cookie.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                config.cookies[k.strip()] = v.strip()

    if args.header:
        config.headers = {}
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                config.headers[k.strip()] = v.strip()

    if args.scope:
        config.scope_domains = [d.strip() for d in args.scope.split(",")]

    modules = None
    if args.modules != "all":
        modules = [m.strip() for m in args.modules.split(",")]

    params = None
    if args.params:
        params = {}
        for pair in args.params.split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k.strip()] = v.strip()

    scanner = GenkiScanner(config)

    try:
        scanner.scan(urls, modules, params)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted")
        scanner.reporter.summary(scanner.http.request_count)


if __name__ == "__main__":
    main()
