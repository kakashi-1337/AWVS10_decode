"""
Shell CLI - Command-line interface for AWVS10 shell mode.
Full pipeline: just enter a URL, everything runs automatically.
"""
import argparse
import os
import sys
import json

from .runner import ShellOrchestrator
from .colors import BRED, BGRN, CYN, YLW, DIM, RST, BOLD, MAG, RED


def find_scripts_dir():
    """Locate the AWVS10 Scripts directory."""
    candidates = [
        os.path.join(os.path.dirname(__file__), "..", "..", "Scripts"),
        os.path.join(os.getcwd(), "Scripts"),
        os.path.expanduser("~/AWVS10_decode/Scripts"),
    ]
    for c in candidates:
        if os.path.isdir(c) and os.path.isdir(os.path.join(c, "PerServer")):
            return os.path.abspath(c)
    return None


def banner():
    print(f"""
{RED}   ___            _    _   ___ _        _ _{RST}
{RED}  / __|___ _ _   | |__(_) / __| |_  ___| | |{RST}
{RED} | (_ / -_) ' \\  | / /| | \\__ \\ ' \\/ -_) | |{RST}
{RED}  \\___\\___|_||_| |_\\_\\|_| |___/_||_\\___|_|_|{RST}

  {BOLD}v1.1{RST} {DIM}- AWVS10 Script Runtime Shell{RST}
  {MAG}Genki Tech Labs{RST} / {RED}Anbu Black Ops{RST}
  {DIM}Tech ID -> Crawl -> Dir Enum -> Scan -> Report{RST}
""")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Genki Shell - AWVS10 Script Runtime (Full Pipeline)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://target.com
  %(prog)s -u https://target.com --full
  %(prog)s -u https://target.com --phase PerServer
  %(prog)s -u https://target.com --phase PerServer,PerScheme -o results.json
  %(prog)s -f urls.txt --scripts-dir /path/to/Scripts
  %(prog)s -u https://target.com --list-scripts PerServer
  %(prog)s -u https://target.com --browser --full
""",
    )

    target_group = parser.add_argument_group("target")
    target_group.add_argument("-u", "--url", help="Target URL")
    target_group.add_argument("-f", "--file", help="File with URLs (one per line)")

    scan_group = parser.add_argument_group("scan options")
    scan_group.add_argument(
        "--full", action="store_true",
        help="Full pipeline: tech detect + port scan + crawl + dir enum + all scan phases (default when no --phase set)",
    )
    scan_group.add_argument(
        "--phase",
        help="Run specific phases (comma-separated: PerServer,PerFolder,PerFile,PerScheme,PostCrawl,PostScan,WebApps,ports,dirs)",
    )
    scan_group.add_argument(
        "--script",
        help="Run a single specific script (e.g., WAF_Detection.script)",
    )
    scan_group.add_argument(
        "--scripts-dir",
        help="Path to AWVS10 Scripts directory (auto-detected if not set)",
    )
    scan_group.add_argument(
        "--list-scripts",
        metavar="PHASE",
        help="List available scripts in a phase and exit",
    )
    scan_group.add_argument(
        "--no-ports", action="store_true",
        help="Skip port scanning",
    )
    scan_group.add_argument(
        "--no-dirs", action="store_true",
        help="Skip directory enumeration",
    )

    browser_group = parser.add_argument_group("browser crawl")
    browser_group.add_argument(
        "--browser", action="store_true",
        help="Use stealth browser for crawling (anti-fingerprint, CF bypass)",
    )
    browser_group.add_argument(
        "--max-depth", type=int, default=3,
        help="Browser crawl depth (default: 3)",
    )
    browser_group.add_argument(
        "--max-pages", type=int, default=100,
        help="Max pages to crawl (default: 100)",
    )
    browser_group.add_argument(
        "--headed", action="store_true",
        help="Run browser in visible mode",
    )

    http_group = parser.add_argument_group("http options")
    http_group.add_argument("--delay", type=float, default=1.0, help="Delay between requests (default: 1.0)")
    http_group.add_argument("--timeout", type=int, default=15, help="Request timeout (default: 15)")
    http_group.add_argument("--proxy", help="HTTP proxy (e.g., http://127.0.0.1:8080)")
    http_group.add_argument("--header", action="append", help="Extra header (Name: Value)")
    http_group.add_argument("--cookie", help="Cookies (name=value;name2=value2)")

    oob_group = parser.add_argument_group("OOB callbacks")
    oob_group.add_argument(
        "--oob-domain", default="6u.gg",
        help="OOB callback domain (default: 6u.gg)",
    )

    output_group = parser.add_argument_group("output")
    output_group.add_argument("-o", "--output", help="Save results to JSON file")
    output_group.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    return parser.parse_args()


def main():
    banner()
    args = parse_args()

    scripts_dir = args.scripts_dir or find_scripts_dir()
    if not scripts_dir:
        print(f"{BRED}[ERROR]{RST} Cannot find AWVS10 Scripts directory.")
        print(f"        Use {BOLD}--scripts-dir /path/to/Scripts{RST}")
        sys.exit(1)

    print(f"{CYN}[SCRIPTS]{RST} {scripts_dir}")

    if args.list_scripts:
        phase_dir = os.path.join(scripts_dir, args.list_scripts)
        if not os.path.isdir(phase_dir):
            print(f"{BRED}[ERROR]{RST} Phase directory not found: {args.list_scripts}")
            sys.exit(1)
        scripts = sorted(f for f in os.listdir(phase_dir) if f.endswith(".script"))
        print(f"\n{MAG}[{args.list_scripts}]{RST} {BOLD}{len(scripts)}{RST} scripts:\n")
        for i, s in enumerate(scripts, 1):
            print(f"  {DIM}{i:3d}.{RST} {s}")
        return

    if not args.url and not args.file:
        print(f"{BRED}[ERROR]{RST} Provide {BOLD}-u URL{RST} or {BOLD}-f FILE{RST}")
        sys.exit(1)

    urls = []
    if args.url:
        urls.append(args.url)
    if args.file:
        if not os.path.exists(args.file):
            print(f"{BRED}[ERROR]{RST} File not found: {args.file}")
            sys.exit(1)
        with open(args.file) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)

    config = {
        "delay": args.delay,
        "timeout": args.timeout,
        "proxy": args.proxy,
        "verbose": args.verbose,
        "headers": {},
        "oob_domain": args.oob_domain,
    }

    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                config["headers"][k.strip()] = v.strip()

    if args.cookie:
        config["headers"]["Cookie"] = args.cookie

    if args.browser:
        config["browser"] = True
        config["headless"] = not args.headed
        config["max_depth"] = args.max_depth
        config["max_pages"] = args.max_pages

    phases = None
    if args.phase:
        phases = [p.strip() for p in args.phase.split(",")]
    if args.no_ports and phases:
        phases = [p for p in phases if p != "ports"]
    elif args.no_ports and not phases:
        phases = [p[0] for p in [
            ("PerServer",), ("PerFolder",), ("PerFile",),
            ("PerScheme",), ("PostCrawl",), ("PostScan",),
            ("WebApps",), ("dirs",),
        ]]
    if args.no_dirs and phases:
        phases = [p for p in phases if p != "dirs"]

    orchestrator = ShellOrchestrator(scripts_dir, config)

    if args.script:
        script_path = None
        for phase_dir in ["PerServer", "PerFolder", "PerFile", "PerScheme", "PostCrawl", "PostScan", "WebApps", "Network"]:
            candidate = os.path.join(scripts_dir, phase_dir, args.script)
            if os.path.exists(candidate):
                script_path = candidate
                break
        if not script_path:
            print(f"{BRED}[ERROR]{RST} Script not found: {args.script}")
            sys.exit(1)

        print(f"{CYN}[SINGLE]{RST} Running {BOLD}{args.script}{RST}")
        orchestrator.runtime.start()
        orchestrator.runtime.init(scripts_dir, config)

        target = urls[0]
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        server_info = orchestrator._detect_server(target)
        context = orchestrator._build_context(target, server_info)

        result, findings = orchestrator.runtime.execute_script_full(
            script_path, context, callback=orchestrator._on_script_event
        )

        orchestrator.runtime.stop()
        print(f"\n{BGRN}[DONE]{RST} {BOLD}{len(findings)}{RST} findings")

        if args.output:
            orchestrator.all_findings = findings
            orchestrator.save_results(args.output)
        return

    try:
        orchestrator.run(urls, phases)
    except KeyboardInterrupt:
        print(f"\n{YLW}[!] Scan interrupted{RST}")
    finally:
        if args.output and orchestrator.all_findings:
            orchestrator.save_results(args.output)


if __name__ == "__main__":
    main()
