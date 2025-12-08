#!/usr/bin/env python3
"""
cctv_scanner.py — persistent Shodan key + combined Shodan+TCP-port discovery.

Features added:
 - Saves Shodan API key once at ~/.cctv_scanner/config.json
 - If no explicit ports provided: uses Shodan ports AND runs a TCP connect probe
   over a configurable list of common ports to "auto-discover" reachable ports.
 - Optional --full-scan to scan 1-65535 (dangerous; requires --yes and explicit confirm).
 - Async TCP connect scanner for speed.

USAGE examples:
  python cctv_scanner.py                      # interactive
  python cctv_scanner.py --manual "1.2.3.4" --yes
  python cctv_scanner.py -f ips.txt --yes --full-scan
"""
from __future__ import annotations
import argparse
import asyncio
import csv
import ipaddress
import json
import logging
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Set, Tuple, Dict
import requests
import urllib3
from rich.console import Console, Group
from rich.panel import Panel
from rich.align import Align
from rich.text import Text
from rich.box import ROUNDED
from rich.table import Table
from rich.rule import Rule
from rich import box
from rich.markdown import Markdown
from pyfiglet import Figlet


# optional shodan import
try:
    import shodan
except Exception:
    shodan = None

# ---------------- CONFIG & CONSTANTS ----------------
CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".cctv_scanner")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
DEFAULT_CONCURRENCY = 10
SHODAN_RATE_SLEEP = 0.15
HTTP_TIMEOUT = 5
# default "common" ports: top useful ports including CCTV/web/rtsp etc.

# Ports commonly used for HTTP-style camera web UIs
HTTP_LIKE_PORTS = {80, 81, 88, 443, 7001, 8000, 8001, 8080, 8081, 8088, 8443, 8888}

COMMON_PORTS = sorted({
    80, 81, 82, 83, 84, 85, 443, 554, 7001, 8000, 8001, 8080, 8081, 8088, 8443, 8554, 9000,
    21, 22, 23, 25, 53, 110, 123, 135, 139, 143, 161, 389, 445, 500, 3306, 3389, 5900, 6379, 27017
})
# be explicit: scanning full range is dangerous/slow; user must opt-in
MAX_FAST_PORTS = 2000  # safety cap if user tries a huge custom list

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# Rich spinner helper imports
import time
from concurrent.futures import ThreadPoolExecutor, Future
from typing import Callable, Any, Optional
from rich.console import Console

# create a single console instance for the whole script
_console = Console()

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

URL_RE = re.compile(r'^(?:(?P<scheme>https?)://)?(?P<host>[^/:]+)(?::(?P<port>\d+))?/?')

def run_with_status(func: Callable[..., Any],
                    *args,
                    message: str = "Working...",
                    spinner_name: str = "dots",
                    timeout: Optional[float] = None,
                    poll_interval: float = 0.08,
                    **kwargs) -> Any:
    """
    Run `func(*args, **kwargs)` in a background thread while showing a Rich spinner message.
    Returns the function's return value, or re-raises the exception from func if it failed.

    - message: text shown next to spinner
    - spinner_name: Rich spinner style name (e.g., 'dots', 'bouncingBar', 'line')
    - timeout: optional seconds to wait before cancelling (None = wait forever)
    - poll_interval: how often to refresh spinner/subtext
    """
    with ThreadPoolExecutor(max_workers=1) as ex:
        fut: Future = ex.submit(func, *args, **kwargs)

        start = time.time()
        subtexts = ["initializing", "contacting Shodan", "authenticating", "fetching metadata", "readying probes"]
        i = 0

        with _console.status(f"[bold green]{message}[/] ", spinner=spinner_name) as status:
            while True:
                if fut.done():
                    break
                now = time.time()
                if timeout is not None and (now - start) > timeout:
                    try:
                        fut.cancel()
                    except Exception:
                        pass
                    raise TimeoutError(f"Operation timed out after {timeout} seconds")
                status.update(f"[bold green]{message}[/] [dim]{subtexts[i % len(subtexts)]}[/]")
                i += 1
                time.sleep(poll_interval)

        exc = fut.exception(timeout=0)
        if exc:
            raise exc
        return fut.result()
    # --- Banner / UI (uses Rich + pyfiglet) ---
# Required imports for banner (add at top if not present): 
# from rich.console import Console, Group
# from rich.panel import Panel
# from rich.align import Align
# from rich.text import Text
# from rich.box import ROUNDED
# from rich.table import Table
# from rich.rule import Rule
# from rich import box
# from rich.markdown import Markdown
# from pyfiglet import Figlet

def display_banner(console: Console, title: str = "Indian Cyber Chef", subtitle: str = "created by Indian Cyber Chef"):
    """
    Prints a colorful Figlet banner, rules/steps panels and quick-command box.
    Call once at program start (unless --no-banner passed).
    """
    # build Figlet title
    f = Figlet(font='slant')
    big = f.renderText(title)
    colors = ["bold red", "bright_yellow", "bright_green", "bright_cyan", "bright_magenta"]
    big_lines = big.splitlines()
    colored_lines = []
    for i, line in enumerate(big_lines):
        color = colors[i % len(colors)]
        txt = Text(line.rstrip(), style=color)
        colored_lines.append(txt)

    title_group = Group(*[Align.center(t) for t in colored_lines])
    title_panel = Panel(title_group, box=ROUNDED, padding=(0,2), style="bold white on black")

    subtitle_txt = Text(subtitle, style="italic bright_white")
    subtitle_panel = Align.center(subtitle_txt)

    rules_md = """\
[b]Quick Rules & Ethics[/b]
• Only test hosts you own or have permission for.
• Use --yes to skip interactive confirmation.
• Full-scan is noisy — avoid on public infra.
• Shodan key stored at ~/.cctv_scanner/config.json
"""
    steps_md = """\
[b]Quick Steps[/b]
1) Choose Manual (single target) or File (list).
2) Provide Shodan key once (saved).
3) Auto-discovery will use Shodan + TCP probe.
4) Use --full-scan only in labs.
"""

    rules = Panel(Markdown(rules_md), title="Rules", border_style="red", box=box.SQUARE)
    steps = Panel(Markdown(steps_md), title="Steps", border_style="green", box=box.SQUARE)

    commands = Table.grid(padding=1)
    commands.add_column(justify="left", ratio=1)
    commands.add_column(justify="left", ratio=3)
    commands.add_row("[bold cyan]Example[/bold cyan]", "[bold magenta]Usage[/bold magenta]")
    commands.add_row("Manual test", "`python cctv_scanner.py --manual 1.2.3.4 --yes`")
    commands.add_row("File test", "`python cctv_scanner.py -f ips.txt --yes`")
    commands.add_row("Fast run", "`python cctv_scanner.py -f ips.txt --yes --concurrency 30`")
    commands_panel = Panel(commands, title="Quick Commands", border_style="blue", box=box.SQUARE)

    footer = Text.assemble(("   » ", "dim"), (subtitle, "bold yellow"))

    console.print()
    console.print(title_panel)
    console.print(subtitle_panel)
    console.print(Rule(style="dim"))
    from rich.columns import Columns
    console.print(Columns([rules, steps, commands_panel]))
    console.print(Rule(style="dim"))
    console.print(Align.center(footer))
    console.print()
# --- end banner ---




def ensure_config_dir():
    if not os.path.isdir(CONFIG_DIR):
        os.makedirs(CONFIG_DIR, exist_ok=True)


def load_config() -> Dict:
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return {}
    return {}


def save_config(cfg: Dict):
    ensure_config_dir()
    with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)
    
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except Exception:
        pass


def get_or_prompt_shodan_key(existing_key: Optional[str]) -> Optional[str]:
    if existing_key:
        return existing_key
   
    env_key = os.getenv("SHODAN_API_KEY")
    if env_key:
        return env_key.strip()
    
    try:
        key = input("Enter your Shodan API key (will be saved to ~/.cctv_scanner/config.json): ").strip()
    except Exception:
        return None
    if not key:
        return None
    
    cfg = load_config()
    cfg["shodan_key"] = key
    save_config(cfg)
    logging.info("Shodan key saved to %s", CONFIG_PATH)
    return key


# ---------------- Parsing & targets ----------------
def parse_target(text: str) -> Tuple[Optional[str], Optional[Set[int]]]:
    """
    Accepts:
      - http://1.2.3.4:88/
      - 1.2.3.4:88
      - 1.2.3.4
    Returns (ip_or_None, ports_set_or_None). ports_set is None if not explicitly present.
    """
    if not text:
        return None, None
    m = URL_RE.match(text.strip())
    if not m:
        return None, None
    host = m.group("host")
    port = m.group("port")
    host = host.strip("[]")
    try:
        ip_obj = ipaddress.ip_address(host)
        ip = str(ip_obj)
    except Exception:
        return None, None
    if port:
        try:
            return ip, {int(port)}
        except ValueError:
            return ip, None
    return ip, None


def read_targets_from_file(path: str) -> List[Tuple[str, Optional[Set[int]]]]:
    path = os.path.expanduser(path)
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")
    targets: List[Tuple[str, Optional[Set[int]]]] = []
    if path.lower().endswith(".csv"):
        with open(path, newline="", mode="r", encoding="utf-8") as fh:
            reader = csv.reader(fh)
            for row in reader:
                for cell in row:
                    cell = cell.strip()
                    if not cell:
                        continue
                    ip, ports = parse_target(cell)
                    if ip:
                        targets.append((ip, ports))
                    else:
                        logging.warning("Skipping invalid entry: %s", cell)
    else:
        with open(path, mode="r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                ip, ports = parse_target(line)
                if ip:
                    targets.append((ip, ports))
                else:
                    logging.warning("Skipping invalid entry: %s", line)
    return targets


# ---------------- Shodan helpers ----------------
def get_shodan_client_or_none(key: Optional[str]):
    if not key:
        return None
    if shodan is None:
        logging.warning("python-shodan not installed; skipping Shodan lookup.")
        return None
    try:
        return shodan.Shodan(key)
    except Exception as e:
        logging.warning("Failed to create Shodan client: %s", e)
        return None


def shodan_host_ports(client, ip: str) -> Set[int]:
    if client is None:
        return set()
    try:
        host = client.host(ip)
        return {int(item.get("port")) for item in host.get("data", []) if "port" in item}
    except Exception as e:
        logging.debug("Shodan error for %s: %s", ip, e)
        return set()


# ---------------- Async TCP port scanner (fast connect) ----------------
async def _probe_port_tcp(host: str, port: int, timeout: float = 1.0) -> Tuple[int, bool]:
    """
    Try a TCP connect to host:port. Return (port, is_open).
    Uses asyncio.open_connection.
    """
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port, True
    except Exception:
        return port, False


async def _scan_ports_async(host: str, ports: List[int], timeout: float = 1.0, concurrency: int = 200) -> Dict[int, bool]:
    sem = asyncio.Semaphore(concurrency)

    async def sem_probe(p):
        async with sem:
            return await _probe_port_tcp(host, p, timeout=timeout)

    tasks = [asyncio.create_task(sem_probe(p)) for p in ports]
    results = await asyncio.gather(*tasks)
    return {p: ok for p, ok in results}


def scan_ports_tcp(host: str, ports: Set[int], timeout: float = 1.0, concurrency: int = 200) -> Dict[int, bool]:
    """
    Wrapper: runs the async scan and returns dict port->bool.
    """
    # limit ports size for safety
    ports_list = sorted(ports)
    if len(ports_list) > MAX_FAST_PORTS:
        raise ValueError(f"Refusing to scan more than {MAX_FAST_PORTS} ports in a single fast scan.")
    return asyncio.run(_scan_ports_async(host, ports_list, timeout=timeout, concurrency=concurrency))

# ---------------- Camera model detection (passive, non-intrusive) ----------------
import hashlib
from urllib.parse import urljoin
from bs4 import BeautifulSoup  # small optional dependency (install in requirements.txt)
from typing import Optional, Tuple, Dict, Any

# Mini signature DB: expand as you encounter devices. Keys are simple heuristics.
CAMERA_SIGNATURES = [
    {
        "vendor": "Axis Communications",
        "model_hint": "AXIS (webserver)",
        "match": {
            "server_header": ["axis-httpd", "Axis-Media-Server"],
            "body_contains": ["Axis Media Control", "AXIS", "axis-cgi"]
        },
        "default_login_doc": "https://help.axis.com/hc/en-us/articles/360017987918-Default-username-and-password-for-network-video-products",
        "notes": "Axis devices use /axis-cgi/ and axis-httpd server banners. Check firmware updates and change default creds."
    },
    {
        "vendor": "Dahua",
        "model_hint": "Dahua web UI",
        "match": {
            "body_contains": ["Dahua", "webs", "Dahua Technology"],
            "paths": ["/doc/page/login.asp", "/cgi-bin/magicBox.cgi"]
        },
        "default_login_doc": "https://www.dahuasecurity.com/support",
        "notes": "Dahua devices often have web UI patterns; ensure firmware up-to-date and change defaults."
    },
    {
        "vendor": "Hikvision",
        "model_hint": "Hikvision",
        "match": {
            "body_contains": ["Hikvision", "Web3.0", "Hikvision-"],
            "server_header": ["Hikvision-Webs"]
        },
        "default_login_doc": "https://www.hikvision.com/en/support/",
        "notes": "Hikvision default accounts and ports are common — patch and change passwords."
    },
    {
        "vendor": "Generic RTSP camera",
        "model_hint": "RTSP-enabled camera (Generic)",
        "match": {
            "body_contains": ["rtsp", "RTSP"],
            "paths": ["/stream", "/live"]
        },
        "default_login_doc": None,
        "notes": "Detected RTSP endpoints — check firmware and change default credentials."
    }
    
]


def fetch_favicon_md5(base_url: str, timeout: float = 3.0) -> Optional[str]:
    try:
        fav_url = urljoin(base_url, "/favicon.ico")
        r = requests.get(fav_url, timeout=timeout, verify=False)
        if r.status_code == 200 and r.content:
            h = hashlib.md5(r.content).hexdigest()
            return h
    except Exception:
        return None
    return None

def detect_camera_from_http(url: str, response: Optional[requests.Response]) -> Tuple[Optional[str], Optional[str], float, Dict[str, Any]]:
    """
    Returns: (vendor_name or None, model_hint or None, confidence:0.0-1.0, info dict)
    info dict contains: 'matched_signature', 'favicon_md5', 'title', 'server_header', 'notes', 'evidence'
    """
    info = {"matched_signature": None, "favicon_md5": None, "title": None, "server_header": None, "notes": None, "evidence": []}
    if response is None:
        return None, None, 0.0, info

    
    server = response.headers.get("Server", "") or response.headers.get("server", "")
    info["server_header"] = server

    
    title = None
    body_text = ""
    try:
        soup = BeautifulSoup(response.text, "html.parser")
        title_tag = soup.title
        if title_tag:
            title = title_tag.get_text().strip()
            info["title"] = title
        body_text = soup.get_text(separator=" ", strip=True)
    except Exception:
        body_text = response.text or ""

    try:
        base = url
        from urllib.parse import urlparse
        p = urlparse(url)
        base = f"{p.scheme}://{p.netloc}"
    except Exception:
        base = url
    fav_md5 = fetch_favicon_md5(base)
    info["favicon_md5"] = fav_md5

    best_conf = 0.0
    best_sig = None
    for sig in CAMERA_SIGNATURES:
        score = 0.0
        m = sig.get("match", {})
        for token in m.get("server_header", []):
            if token.lower() in (server or "").lower():
                score += 0.4
                info["evidence"].append(f"server_header contains '{token}'")
                
        for token in m.get("body_contains", []):
            if token.lower() in (body_text or "").lower():
                score += 0.3
                info["evidence"].append(f"body contains '{token}'")
                
        for path_token in m.get("paths", []):
            if path_token in url or (response is not None and path_token in response.url):
                score += 0.2
                info["evidence"].append(f"url/path contains '{path_token}'")

        if score > best_conf:
            best_conf = score
            best_sig = sig

    if best_sig and best_conf > 0.2:
        info["matched_signature"] = best_sig["vendor"]
        info["notes"] = best_sig.get("notes")
        return best_sig["vendor"], best_sig.get("model_hint"), min(1.0, best_conf), info
    
    logging.debug("No match for %s — title='%s' server='%s' body_snippet='%s...'",
              url, info.get("title"), info.get("server_header"),
              body_text[:200].replace("\n", " "))


    return None, None, 0.0, info


# ---------------- HTTP probe (same as before) ----------------
def probe_http(ip: str, port: int, timeout: int = HTTP_TIMEOUT) -> Tuple[bool, str]:
    candidates = [f"http://{ip}:{port}", f"https://{ip}:{port}"]
    s = requests.Session()
    s.headers.update({"User-Agent": "cctv-scanner/0.2 (educational)"})
    for url in candidates:
        try:
            r = s.get(url, timeout=timeout, verify=False)
            code = getattr(r, "status_code", 0)
            if 200 <= code < 400:
                return True, url
            if code in (401, 403):
                return True, url
        except requests.RequestException:
            continue
    return False, ""


# ---------------- Target scan orchestration ----------------
def scan_target(client_or_none, ip: str, explicit_ports: Optional[Set[int]], ports_of_interest: Set[int],
                do_tcp_scan_for_auto: bool, tcp_timeout: float, tcp_concurrency: int, full_scan: bool,
                detect_model: bool = True) -> List[Tuple[str,int,bool,str,Optional[str],Optional[str],float,Dict]]:
    """
    Scans a single target IP and returns list of tuples:
      (ip, port, accessible_bool, url, vendor_or_None, model_hint_or_None, confidence, info_dict)
    """
    results: List[Tuple[str,int,bool,str,Optional[str],Optional[str],float,Dict]] = []
    shodan_ports = set()

    if client_or_none:
        shodan_ports = shodan_host_ports(client_or_none, ip)

    # Determine candidate ports
    if explicit_ports:
        candidate_ports = set(explicit_ports)
    else:
        if full_scan:
            tcp_port_set = set(range(1, 65536))
        elif do_tcp_scan_for_auto:
            tcp_port_set = set(COMMON_PORTS)
        else:
            tcp_port_set = set()

        discovered = set()
        if tcp_port_set:
            try:
                logging.debug("Running TCP connect scan on %s (%d ports)...", ip, len(tcp_port_set))
                tcp_res = scan_ports_tcp(ip, tcp_port_set, timeout=tcp_timeout, concurrency=tcp_concurrency)
                discovered = {p for p, open_ in tcp_res.items() if open_}
                logging.debug("TCP discovered open ports for %s: %s", ip, sorted(discovered))
            except Exception as e:
                logging.warning("TCP scan error for %s: %s", ip, e)

        candidate_ports = (shodan_ports | discovered) if (shodan_ports or discovered) else set()

    # fallback if nothing found
    if not candidate_ports:
        logging.debug("No candidate ports for %s - falling back to COMMON_PORTS", ip)
        candidate_ports = set(COMMON_PORTS)

    # Probe each port (only HTTP-like to avoid noise)
    for port in sorted(candidate_ports):
        if port not in HTTP_LIKE_PORTS:
            logging.debug("Skipping non-HTTP port %s:%d", ip, port)
            continue

        ok, url = probe_http(ip, port)
        if ok and url:
            vendor = model_hint = None
            confidence = 0.0
            info = {}
            if detect_model:
                try:
                    resp = requests.get(url, timeout=HTTP_TIMEOUT, verify=False)
                    vendor, model_hint, confidence, info = detect_camera_from_http(url, resp)
                except Exception:
                    vendor, model_hint, confidence, info = (None, None, 0.0, {})
            results.append((ip, port, True, url, vendor, model_hint, confidence, info))
        else:
            results.append((ip, port, False, url or "", None, None, 0.0, {}))

    return results

# ---------------- Interactive helpers ----------------
def interactive_prompt() -> List[Tuple[str, Optional[Set[int]]]]:
    print("Choose input mode:")
    print("  1) Manual (enter a single IP, ip:port or a URL like http://1.2.3.4:88/)")
    print("  2) File with list of targets (each line can be IP, ip:port, or URL)")
    choice = input("Select 1 or 2: ").strip()
    if choice == "1":
        raw = input("Enter target to test: ").strip()
        ip, ports = parse_target(raw)
        if ip:
            return [(ip, ports)]
        else:
            logging.error("Invalid target format.")
            return []
    elif choice == "2":
        path = input("Enter path to IP list file: ").strip()
        try:
            return read_targets_from_file(path)
        except FileNotFoundError as e:
            logging.error(str(e))
            return []
    else:
        logging.error("Invalid choice.")
        return []


# ---------------- Main ----------------
def main():
    parser = argparse.ArgumentParser(description="CCTV-ish scanner: persistent Shodan key + TCP discovery.")
    parser.add_argument("--file", "-f", help="Path to target file (csv or txt). Lines can be IP, ip:port or URL")
    parser.add_argument("--manual", help="Single target (ip, ip:port or URL) to test non-interactively")
    parser.add_argument("--shodan-key", help="Shodan API key (overrides saved key)")
    parser.add_argument("--concurrency", "-c", type=int, default=DEFAULT_CONCURRENCY)
    parser.add_argument("--yes", action="store_true", help="Skip authorization prompt")
    parser.add_argument("--debug", action="store_true", help="Debug logging")
    parser.add_argument("--full-scan", action="store_true", help="Scan full port range 1-65535 (dangerous, slow)")
    parser.add_argument("--tcp-timeout", type=float, default=1.0, help="TCP connect timeout (seconds)")
    parser.add_argument("--tcp-concurrency", type=int, default=200, help="Concurrency for async TCP scanner")
    parser.add_argument("--no-banner", action="store_true", help="Skip the startup banner")
    parser.add_argument("--detect-model", action="store_true", help="Enable passive camera model detection (slow)")
    parser.add_argument("--json-output", help="Save scan results as JSON file")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.no_banner:
        display_banner(_console, title="Indian Cyber Chef", subtitle="created by Indian Cyber Chef")

    cfg = load_config()
    saved_key = cfg.get("shodan_key")

    # Determine input targets
    targets: List[Tuple[str, Optional[Set[int]]]] = []
    if args.manual:
        ip, ports = parse_target(args.manual.strip())
        if ip:
            targets.append((ip, ports))
        else:
            logging.error("Invalid manual target: %s", args.manual)
            return
    elif args.file:
        try:
            targets = read_targets_from_file(args.file)
        except FileNotFoundError as e:
            logging.error(str(e))
            return
    else:
        targets = interactive_prompt()

    if not targets:
        logging.error("No valid targets provided.")
        return

    # Get or prompt for Shodan key
    shodan_key = args.shodan_key or saved_key
    shodan_key = get_or_prompt_shodan_key(shodan_key)
    if not shodan_key:
        logging.info("No Shodan key provided. Script will still probe explicit ports or run TCP discovery.")

    # Ethics confirmation
    if not args.yes:
        print("WARNING: Only scan hosts you own or have explicit permission to test.")
        print("Targets (first 10):", [t[0] for t in targets[:10]])
        ok = input("Do you confirm authorization? [y/N]: ").strip().lower()
        if ok not in ("y", "yes"):
            logging.info("Authorization not confirmed. Exiting.")
            return

    # Full scan confirmation
    if args.full_scan and not args.yes:
        print("DANGER: You requested --full-scan (ports 1-65535). This is slow and may be intrusive.")
        ok = input("Are you absolutely sure and authorized to perform a full scan? [type 'I AGREE' to continue]: ").strip()
        if ok != "I AGREE":
            logging.info("Full scan not confirmed. Exiting.")
            return

    # Initialize Shodan
    try:
        client = run_with_status(
            get_shodan_client_or_none,
            shodan_key,
            message="Initializing Shodan",
            spinner_name="dots",
            timeout=12.0
        )
    except TimeoutError as te:
        logging.warning("Shodan init timed out: %s. Continuing without Shodan.", te)
        client = None
    except Exception as e:
        logging.warning("Shodan initialization failed (%s). Continuing without Shodan.", e)
        client = None

    # Initialize results
    results_all: List[Dict] = []

    # Submit scan tasks
    with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        fut_map = {}
        for ip, explicit_ports in targets:
            fut = ex.submit(
                scan_target,
                client,
                ip,
                explicit_ports,
                set(COMMON_PORTS),
                True,
                args.tcp_timeout,
                args.tcp_concurrency,
                args.full_scan,
                args.detect_model
            )
            fut_map[fut] = ip
            time.sleep(SHODAN_RATE_SLEEP)

        # Process results
        for fut in as_completed(fut_map):
            ip = fut_map[fut]
            try:
                res = fut.result()
                if not res:
                    logging.debug("No candidates for %s", ip)
                    continue
                for item in res:
                    try:
                        ip_t, port_t, ok_t, url_t, vendor, model_hint, confidence, info = item[:8]
                    except Exception:
                        logging.debug("Skipping malformed result for %s: %s", ip, item)
                        continue
                    
                    results_all.append({
                        "ip": ip_t,
                        "port": port_t,
                        "accessible": bool(ok_t),
                        "url": url_t or "",
                        "vendor": vendor,
                        "model_hint": model_hint,
                        "confidence": float(confidence or 0.0),
                        "detection_info": info or {}
                    })
                logging.info("Found %d candidate(s) for %s", len(res), ip)
            except Exception as e:
                logging.debug("Error scanning %s: %s", ip, e)

    # --- Reporting ---
    if results_all:
        print("\n=== Accessible endpoints ===")
        any_accessible = False
        for r in results_all:
            if r.get("accessible"):
                any_accessible = True
                print(f"{r['ip']}:{r['port']}\tACCESSIBLE -> {r['url']}")
                if r.get("vendor"):
                    print(f"  Detected: {r['vendor']} ({r['model_hint']}) — confidence {r['confidence']:.2f}")
                    if r['detection_info'].get("notes"):
                        print(f"  Notes: {r['detection_info']['notes']}")
        if not any_accessible:
            print("No accessible endpoints found (or no Shodan/tcp-discovery results).")

        print("\n=== All checked (including inaccessible) ===")
        for r in results_all:
            status = "OPEN" if r.get("accessible") else "closed"
            print(f"{r['ip']}:{r['port']}\t{status}\t{r['url']}")

        # --- Vendor summary ---
        from collections import Counter
        vendors = [r['vendor'] for r in results_all if r.get('vendor')]
        if vendors:
            counts = Counter(vendors)
            print("\n=== Vendor summary ===")
            for v, c in counts.items():
                print(f"{v}: {c} devices detected")

        # --- Optional JSON output (save results) ---
        if args.json_output:
            try:
                with open(args.json_output, "w", encoding="utf-8") as f:
                    json.dump(results_all, f, indent=2)
                print(f"\n[+] Results saved to {args.json_output}")
            except Exception as e:
                logging.warning("Failed to write JSON output %s: %s", args.json_output, e)

        else:
            print("No accessible endpoints found (or no Shodan/tcp-discovery results).")

    # --- Final Reporting (clean and unified) ---
    if results_all:
        print("\n=== Accessible endpoints ===")
        any_accessible = False
        for r in results_all:
            if r.get("accessible"):
                any_accessible = True
                vendor_str = f"  Detected: {r['vendor']} ({r['model_hint']}) — confidence {r['confidence']:.2f}" if r.get("vendor") else ""
                print(f"{r['ip']}:{r['port']}\tACCESSIBLE -> {r['url']}")
                if vendor_str:
                    print(vendor_str)
                    if r['detection_info'].get("notes"):
                        print(f"  Notes: {r['detection_info']['notes']}")
        if not any_accessible:
            print("No accessible endpoints found (or no Shodan/tcp-discovery results).")

        print("\n=== All checked (including inaccessible) ===")
        for r in results_all:
            status = "OPEN" if r.get("accessible") else "closed"
            vendor_tag = r.get("vendor") or ""
            print(f"{r['ip']}:{r['port']}\t{status}\t{r['url']}\t{vendor_tag}")

        # --- Vendor summary ---
        from collections import Counter
        vendors = [r['vendor'] for r in results_all if r.get('vendor')]
        if vendors:
            counts = Counter(vendors)
            total = len(vendors)
            print("\n=== Vendor summary ===")
            for v, c in counts.most_common():
                pct = (c / total) * 100
                print(f"{v}: {c} devices detected ({pct:.1f}%)")

        # --- Optional JSON output ---
        if args.json_output:
            try:
                with open(args.json_output, "w", encoding="utf-8") as f:
                    json.dump(results_all, f, indent=2)
                print(f"\n[+] Results saved to {args.json_output}")
            except Exception as e:
                logging.warning("Failed to write JSON output %s: %s", args.json_output, e)
    else:
        print("No accessible endpoints found (or no Shodan/tcp-discovery results).")

if __name__ == "__main__":
    main()

