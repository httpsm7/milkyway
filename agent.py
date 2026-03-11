#!/usr/bin/env python3
"""
AUTONOMOUS PENTEST AGENT
For authorized security research only.
Usage: python3 agent.py -u https://target.com --creds user:pass
"""

import argparse
import asyncio
import json
import os
import sys
import time
import warnings
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

warnings.filterwarnings("ignore")

# Add project root to path
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from core.database import Database
from core.logger import Logger
from core.ai_brain import AIBrain, ContextBuilder
from core.agent_loop import AgentLoop
from core.chain_detector import ChainDetector
from modules.report import generate_report
from protocols.http_client import HTTPClient
from engines.engines import ReconEngine, EndpointDiscoveryEngine


def parse_args():
    parser = argparse.ArgumentParser(
        description="Autonomous Pentest Agent — Authorized Security Research Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 agent.py -u https://target.com
  python3 agent.py -u https://target.com --creds admin:password --deep
  python3 agent.py -u https://target.com --creds-file creds.txt --tor
  python3 agent.py -f targets.txt --quick
  python3 agent.py -u https://target.com --groq-key YOUR_KEY --deep

DISCLAIMER: Use only on systems you own or have explicit written permission to test.
"""
    )

    # Input
    inp = parser.add_mutually_exclusive_group(required=True)
    inp.add_argument("-u", "--url", help="Single target URL")
    inp.add_argument("-f", "--file", help="File with target URLs (one per line)")

    # Credentials
    creds = parser.add_argument_group("Credentials")
    creds.add_argument("--creds", metavar="USER:PASS",
                       help="Login credentials (e.g. admin:password)")
    creds.add_argument("--creds-file", metavar="FILE",
                       help="Multi-role creds file: role:user:pass per line")
    creds.add_argument("--cookie", metavar="COOKIE", help="Pre-auth cookie string")
    creds.add_argument("--token", metavar="TOKEN", help="Pre-auth JWT/Bearer token")

    # AI
    ai = parser.add_argument_group("AI Configuration")
    ai.add_argument("--ollama-model", default="llama3:8b", help="Ollama model (default: llama3:8b)")
    ai.add_argument("--ollama-url", default="http://localhost:11434", help="Ollama URL")
    ai.add_argument("--groq-key", help="Groq API key for cloud AI fallback")
    ai.add_argument("--no-ai", action="store_true", help="Rule-based only (no AI)")

    # Scan profile
    profile = parser.add_argument_group("Scan Profile")
    profile.add_argument("--quick", action="store_true", help="Quick scan (recon + auth + IDOR)")
    profile.add_argument("--deep", action="store_true", help="Deep scan (all engines)")
    profile.add_argument("--stealth", action="store_true", help="Stealth mode (slow + Tor)")
    profile.add_argument("--api-only", action="store_true", help="API testing only")

    # Scope
    scope = parser.add_argument_group("Scope")
    scope.add_argument("--scope", metavar="DOMAIN", help="Restrict to domain")
    scope.add_argument("--exclude", metavar="PATH", nargs="+", help="Exclude paths")
    scope.add_argument("--max-depth", type=int, default=3, help="Max crawl depth")
    scope.add_argument("--max-endpoints", type=int, default=200, help="Max endpoints to test")

    # Safety
    safety = parser.add_argument_group("Safety Limits")
    safety.add_argument("--max-time", type=int, default=120, help="Max time minutes (default: 120)")
    safety.add_argument("--max-iter", type=int, default=200, help="Max AI iterations (default: 200)")

    # Network
    net = parser.add_argument_group("Network")
    net.add_argument("--tor", action="store_true", help="Enable Tor IP rotation")
    net.add_argument("--proxy", metavar="URL", help="Custom proxy URL")
    net.add_argument("--rate", type=int, default=5, help="Requests per second (default: 5)")

    # Output
    out = parser.add_argument_group("Output")
    out.add_argument("-o", "--output", help="Output directory")
    out.add_argument("--no-color", action="store_true", help="Disable colors")
    out.add_argument("--resume", action="store_true", help="Resume interrupted scan")

    return parser.parse_args()


def load_rules() -> dict:
    """Load all YAML rule files"""
    rules = {}
    rules_dir = os.path.join(ROOT, "rules")

    if not os.path.exists(rules_dir):
        return rules

    for rule_file in ["attack_patterns.yaml", "chain_patterns.yaml"]:
        path = os.path.join(rules_dir, rule_file)
        if os.path.exists(path) and HAS_YAML:
            try:
                with open(path) as f:
                    data = yaml.safe_load(f)
                    rules[rule_file.replace(".yaml", "")] = data
            except Exception as e:
                print(f"[!] Could not load {rule_file}: {e}")
        elif not HAS_YAML:
            # Basic rules without pyyaml
            rules["attack_patterns"] = {"patterns": {}}

    return rules


def setup_output_dir(target_url: str, base_dir: str = None) -> str:
    """Create timestamped output directory"""
    parsed = urlparse(target_url)
    domain = parsed.netloc.replace(".", "_").replace(":", "_") or "target"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder_name = f"{domain}_{timestamp}"

    if base_dir:
        output_dir = os.path.join(base_dir, folder_name)
    else:
        output_dir = os.path.join(ROOT, "results", folder_name)

    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(os.path.join(output_dir, "poc"), exist_ok=True)

    return output_dir


async def run_scan(target: str, args, rules: dict, log: Logger):
    """Run full scan on a single target"""

    log.banner(target, "deep" if args.deep else "quick" if args.quick else "standard")

    # Setup output directory (timestamped, unique per target)
    output_dir = setup_output_dir(target, args.output)
    log.info(f"Output directory: {output_dir}")

    # Config
    config = {
        "target": target,
        "output_dir": output_dir,
        "mode": "deep" if args.deep else "quick" if args.quick else "standard",
        "use_ai": not args.no_ai,
        "ollama_model": args.ollama_model,
        "ollama_url": args.ollama_url,
        "groq_key": args.groq_key,
        "use_tor": args.tor or args.stealth,
        "rate_limit": 2 if args.stealth else args.rate,
        "max_time_minutes": args.max_time,
        "max_iterations": args.max_iter,
        "max_endpoints": args.max_endpoints,
        "scope": args.scope or urlparse(target).netloc,
    }

    # Init database (in output dir with timestamp in name)
    db_path = os.path.join(output_dir, f"scan.db")
    db = Database(db_path)
    log.info(f"Database: {db_path}")

    # Init HTTP client
    http = HTTPClient(config, logger=log, use_tor=config["use_tor"])

    # Add seed node
    db.add_node(target, node_type="NORMAL", priority=5)

    # ── PHASE 1: RECON ──────────────────────────────────────
    log.step("PHASE 1: RECONNAISSANCE")

    recon_engine = ReconEngine(http, db, rules, log)
    recon_result = await recon_engine.run({"url": target})

    if recon_result.info.get("tech_stack"):
        log.info(f"Tech stack: {recon_result.info['tech_stack']}")
    if http.waf_detected:
        log.warn(f"WAF detected: {http.waf_detected}")
        db.save_waf(target, http.waf_detected)

    # ── PHASE 2: ENDPOINT DISCOVERY ─────────────────────────
    log.step("PHASE 2: ENDPOINT DISCOVERY")

    disc_engine = EndpointDiscoveryEngine(http, db, rules, log)
    disc_result = await disc_engine.run({"url": target})
    log.info(f"Discovered {disc_result.info.get('endpoints_found', 0)} endpoints")

    # Add credentials as sessions
    if args.creds:
        try:
            user, passwd = args.creds.split(":", 1)
            # Try to login and get token
            login_token = await _try_login(target, user, passwd, http, log)
            if login_token:
                db.add_session("user_a", token=login_token, user_id=user)
                log.info(f"Session created for: {user}")
        except ValueError:
            log.warn("Invalid --creds format. Use user:pass")

    if args.token:
        db.add_session("user_a", token=args.token.replace("Bearer ", ""))

    if not args.quick:
        # Load creds file for multi-role testing
        if args.creds_file and os.path.exists(args.creds_file):
            with open(args.creds_file) as f:
                for line in f:
                    line = line.strip()
                    if ":" in line:
                        parts = line.split(":", 2)
                        if len(parts) == 3:
                            role, user, passwd = parts
                            tok = await _try_login(target, user, passwd, http, log)
                            if tok:
                                db.add_session(role, token=tok, user_id=user)
                                log.info(f"Session: {role}")

    # ── PHASE 3: AI AGENT LOOP ──────────────────────────────
    log.step("PHASE 3: AI AGENT LOOP")

    agent = AgentLoop(config, db, http, rules, log)

    if args.quick:
        agent.max_iterations = 30
    elif args.deep:
        agent.max_iterations = 300

    loop_result = await agent.run()

    # ── PHASE 4: REPORT GENERATION ──────────────────────────
    log.step("PHASE 4: GENERATING REPORT")

    report_path = generate_report(db, config, output_dir)
    log.info(f"Report: {report_path}")

    # Save findings JSON
    findings_path = os.path.join(output_dir, "findings.json")
    with open(findings_path, "w") as f:
        json.dump(db.get_findings(), f, indent=2)

    # Save AI action log
    actions_path = os.path.join(output_dir, "ai_actions.json")
    with open(actions_path, "w") as f:
        json.dump(db.get_recent_actions(limit=500), f, indent=2)

    stats = db.get_stats()

    log.info("")
    log.info("═" * 60)
    log.info(f"  SCAN COMPLETE: {target}")
    log.info(f"  Critical: {stats['critical']}  High: {stats['high']}  Medium: {stats['medium']}")
    log.info(f"  Attack chains: {stats['chains']}")
    log.info(f"  Report: {report_path}")
    log.info("═" * 60)

    db.close()
    return {"target": target, "stats": stats, "report": report_path, "output_dir": output_dir}


async def _try_login(target: str, username: str, password: str,
                     http: HTTPClient, log: Logger) -> str:
    """Attempt to login and extract token/session"""
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    login_endpoints = ["/api/login", "/login", "/api/auth/login",
                       "/auth/login", "/api/v1/login", "/user/login"]

    for ep in login_endpoints:
        url = base + ep
        try:
            resp = await http.request(
                "POST", url,
                json_body={"username": username, "password": password},
                timeout=8
            )
            if resp and resp.get("status") in [200, 201]:
                body = resp.get("body", "")
                # Try to extract token
                try:
                    data = json.loads(body)
                    for key in ["token", "access_token", "jwt", "auth_token",
                                "accessToken", "authToken"]:
                        if key in data:
                            log.info(f"Login successful at {ep}")
                            return data[key]
                        # Nested
                        for nested in data.values():
                            if isinstance(nested, dict) and key in nested:
                                return nested[key]
                except:
                    # Check response headers for token
                    auth_header = resp.get("headers", {}).get("authorization", "")
                    if auth_header:
                        return auth_header.replace("Bearer ", "")
        except Exception:
            continue

    log.warn(f"Could not auto-login for {username} — try providing --token directly")
    return None


async def main():
    args = parse_args()
    log = Logger(no_color=args.no_color)

    # Load rules
    rules = load_rules()
    log.info(f"Loaded rule sets: {list(rules.keys())}")

    # Collect targets
    targets = []
    if args.url:
        targets.append(args.url)
    elif args.file:
        if not os.path.exists(args.file):
            log.error(f"Target file not found: {args.file}")
            sys.exit(1)
        with open(args.file) as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    log.info(f"Targets: {len(targets)}")

    # Run scans
    results = []
    for i, target in enumerate(targets):
        if not target.startswith("http"):
            target = "https://" + target

        log.info(f"\n[{i+1}/{len(targets)}] Starting scan: {target}")

        try:
            result = await run_scan(target, args, rules, log)
            results.append(result)
        except KeyboardInterrupt:
            log.warn("Scan interrupted by user")
            break
        except Exception as e:
            log.error(f"Scan failed for {target}: {e}")
            import traceback
            log.debug(traceback.format_exc())

    # Summary for multi-target
    if len(results) > 1:
        log.info("\n" + "═" * 60)
        log.info("  MULTI-TARGET SUMMARY")
        log.info("═" * 60)
        for r in results:
            s = r["stats"]
            log.info(f"  {r['target']}: C={s['critical']} H={s['high']} M={s['medium']}")
        log.info("═" * 60)


if __name__ == "__main__":
    asyncio.run(main())
