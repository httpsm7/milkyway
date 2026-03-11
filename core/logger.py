"""
logger.py — Colored logger + step tracker (multi-language support)
"""
import sys
from datetime import datetime


class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    CYAN = '\033[0;36m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    WHITE = '\033[1;37m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

    @staticmethod
    def disable():
        for attr in ['RED','GREEN','YELLOW','CYAN','BLUE','MAGENTA','WHITE','BOLD','DIM','RESET']:
            setattr(Colors, attr, '')


class Logger:
    def __init__(self, name: str = "agent", no_color: bool = False):
        self.name = name
        self.step_count = 0
        if no_color:
            Colors.disable()

    def _ts(self):
        return datetime.now().strftime("%H:%M:%S")

    def _write(self, prefix: str, color: str, msg: str):
        line = f"{Colors.DIM}[{self._ts()}]{Colors.RESET} {color}{prefix}{Colors.RESET} {msg}"
        print(line, flush=True)

    def info(self, msg):    self._write("[+]", Colors.GREEN, msg)
    def warn(self, msg):    self._write("[!]", Colors.YELLOW, msg)
    def error(self, msg):   self._write("[-]", Colors.RED, msg)
    def debug(self, msg):   self._write("[~]", Colors.DIM, msg)
    def critical(self, msg):self._write("[★]", Colors.RED + Colors.BOLD, msg)

    def step(self, msg):
        self.step_count += 1
        print(f"\n{Colors.CYAN}{Colors.BOLD}{'═'*60}{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}  STEP {self.step_count}: {msg}{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}{'═'*60}{Colors.RESET}")

    def finding(self, vuln_type: str, severity: str, endpoint: str, detail: str = ""):
        colors = {
            "CRITICAL": Colors.RED + Colors.BOLD,
            "HIGH":     Colors.RED,
            "MEDIUM":   Colors.YELLOW,
            "LOW":      Colors.CYAN,
            "INFO":     Colors.BLUE
        }
        c = colors.get(severity, Colors.WHITE)
        badge = f"{c}[{severity}]{Colors.RESET}"
        print(f"\n{Colors.BOLD}{'▓'*50}{Colors.RESET}")
        print(f"  🔴 FINDING: {badge} {Colors.BOLD}{vuln_type}{Colors.RESET}")
        print(f"  📍 Endpoint: {Colors.CYAN}{endpoint}{Colors.RESET}")
        if detail:
            print(f"  📝 Detail: {detail}")
        print(f"{Colors.BOLD}{'▓'*50}{Colors.RESET}\n")

    def chain(self, chain_name: str, severity: str):
        print(f"\n{Colors.MAGENTA}{Colors.BOLD}{'◆'*50}{Colors.RESET}")
        print(f"  ⛓  CHAIN DETECTED: {Colors.BOLD}{chain_name}{Colors.RESET} [{severity}]")
        print(f"{Colors.MAGENTA}{Colors.BOLD}{'◆'*50}{Colors.RESET}\n")

    def ai_decision(self, action: str, engine: str, reason: str, confidence: int):
        c = Colors.GREEN if confidence >= 70 else Colors.YELLOW
        print(f"  {Colors.BLUE}[AI]{Colors.RESET} {Colors.BOLD}{action}:{Colors.RESET} {engine} "
              f"{c}(conf:{confidence}%){Colors.RESET} — {Colors.DIM}{reason[:80]}{Colors.RESET}")

    def phase(self, name: str):
        print(f"\n{Colors.MAGENTA}{Colors.BOLD}")
        print(f"  ██████╗ ██╗  ██╗ █████╗ ███████╗███████╗")
        print(f"  ██╔══██╗██║  ██║██╔══██╗██╔════╝██╔════╝")
        print(f"  ██████╔╝███████║███████║███████╗█████╗  ")
        print(f"  ██╔═══╝ ██╔══██║██╔══██║╚════██║██╔══╝  ")
        print(f"  ██║     ██║  ██║██║  ██║███████║███████╗")
        print(f"  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝")
        print(f"  {name}{Colors.RESET}\n")

    def banner(self, target: str, mode: str):
        print(f"""
{Colors.CYAN}{Colors.BOLD}
        /\\
       /  \\
      /    \\
     /  👁  \\     AUTONOMOUS PENTEST AGENT
    /________\\    Target: {target}
  ══════════════  Mode: {mode}

  ⚠  Authorized Security Research Only
{Colors.RESET}""")

    def stats(self, stats_dict: dict):
        print(f"\n{Colors.BOLD}{'─'*50}{Colors.RESET}")
        for k, v in stats_dict.items():
            print(f"  {Colors.CYAN}{k:25}{Colors.RESET}: {Colors.BOLD}{v}{Colors.RESET}")
        print(f"{Colors.BOLD}{'─'*50}{Colors.RESET}\n")
