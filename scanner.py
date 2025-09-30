import os
import subprocess
import json
import glob
from abc import ABC, abstractmethod
from openai import OpenAI
from urllib.parse import urlparse, unquote
import time
import atexit, signal, sys
import tldextract
from collections import defaultdict, Counter
from colorama import Fore, Style, init
init(autoreset=True)
import requests
from rich.console import Console
import re, jwt



def global_cleanup(report_file=None):
    keep = os.path.basename(report_file) if report_file else None
    for f in os.listdir("."):
        if keep and f == keep:
            continue
        if f.endswith((".json", ".txt", ".log")):
            try:
                os.remove(f)
            except Exception as e:
                pass

def cleanup_before_run():
    global_cleanup()

def handle_exit(*args):
    global_cleanup()
    sys.exit(0)

atexit.register(global_cleanup)
signal.signal(signal.SIGINT, handle_exit)
signal.signal(signal.SIGTERM, handle_exit)  

class Logger:
    stage_counter = 1
    @staticmethod
    def info(msg: str):
        print(Fore.CYAN + msg + Style.RESET_ALL)

    @staticmethod
    def success(msg: str):
        print(Fore.GREEN + msg + Style.RESET_ALL)

    @staticmethod
    def warning(msg: str):
        print(Fore.YELLOW + msg + Style.RESET_ALL)

    @staticmethod
    def inline_list(title: str, items: list[str], color=Fore.CYAN):
        if not items:
            return
        line = " | ".join(items)
        print(color + f"{title}: {line}" + Style.RESET_ALL)

    @staticmethod
    def stage(title: str):
        """Numaralı, büyük ayırıcı ve hangi aşamada olduğumuzu gösterir"""
        num = Logger.stage_counter
        Logger.stage_counter += 1
        print("\n" + "="*80)
        print(Fore.MAGENTA + f"[ STAGE {num} ] {title}" + Style.RESET_ALL)
        print("="*80 + "\n")

    @staticmethod
    def list(title: str, items: list[str], color=Fore.CYAN):
        if not items:
            return
        print(color + f"{title}:" + Style.RESET_ALL)
        for item in items:
            print(color + f"   • {item}" + Style.RESET_ALL)

# ---------------------------
# Observer Pattern
# ---------------------------
class Observer(ABC):
    @abstractmethod
    def update(self, event: str, data: str = ""):
        pass

class ConsoleObserver(Observer):
    def update(self, event, data=""):
        Logger.info(f"[Console] {event}: {data[:100]}")

class TelegramObserver(Observer):
    def __init__(self, token, chat_id):
        self.token = token
        self.chat_id = chat_id
        

    def update(self, event, data=""):
        import requests
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        msg = f"🔔 {event}\n{data[:500]}"
        requests.post(url, data={"chat_id": self.chat_id, "text": msg})

class LogFileObserver(Observer):
    def __init__(self, filename="pipeline.log"):
        self.filename = filename

    def update(self, event, data=""):
        with open(self.filename, "a") as f:
            f.write(f"{event}: {data}\n")


# ---------------------------
# Command Pattern
# ---------------------------
class Command(ABC):
    def __init__(self, domain):
        self.domain = domain
        self.result_file = None
    
    @abstractmethod
    def get_stage_name(self) -> str:
        """Human-readable stage name for logs/reports"""
        pass

    @abstractmethod
    def execute(self) -> tuple[str, str]:
        pass

    def _run(self, cmd, outfile=None):
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        output_lines = []
        with open(outfile, "w") if outfile else open(os.devnull, "w") as f:
            for line in process.stdout:
                f.write(line)             
                output_lines.append(line)
        process.wait()
        self.result_file = outfile
        return outfile, "".join(output_lines)



# ---------------------------
# Decorator Pattern: Timing
# ---------------------------
class TimingDecorator(Command):
    SILENT = {"KatanaCommand", "WhatwebCommand", "WappalyzerCommand", "WaybackCommand"}

    def __init__(self, command: Command):
        super().__init__(command.domain)
        self._command = command
        self.last_duration = None
    
    def get_stage_name(self) -> str:
        return self._command.get_stage_name()

    def execute(self) -> tuple[str, str]:
        start = time.time()
        file, output = self._command.execute()
        end = time.time()
        self.last_duration = end - start

        # Artık burada hiçbir şey yazdırmıyoruz.
        # Sadece süreyi saklıyoruz, ekrana basma işi CommandHandler'da yapılacak.
        return file, output

# ---------------------------
# Tool Commands
# ---------------------------
class SubfinderCommand(Command):

    def get_stage_name(self) -> str:
        return "Subfinder - Subdomain Enumeration"

    def execute(self):
        ext = tldextract.extract(self.domain)
        root_domain = ".".join([ext.domain, ext.suffix])

        if ext.subdomain:
            # Subdomain verilmiş → sadece dosyaya yaz
            with open("subdomains.txt", "w") as f:
                f.write(self.domain + "\n")
            self.result_file = "subdomains.txt"
            return "subdomains.txt", self.domain
        else:
            # Root domain verilmiş → subfinder çalıştır
            return self._run(
                f"subfinder -d {root_domain} -silent",
                "subdomains.txt"
            )


class HttpxCommand(Command):

    def get_stage_name(self) -> str:
        return "HTTPX - Alive Hosts"

    def execute(self):
        ext = tldextract.extract(self.domain)
        output_file = "alive.json"

        if ext.subdomain:
            # Subdomain → single target
            cmd = [
                "/root/go/bin/httpx", "-u", f"https://{self.domain}",
                "-nc", "-status-code", "-title", "-tech-detect",
                "-json", "-silent"
            ]
            with open(output_file, "w") as outfile:
                subprocess.run(cmd, stdout=outfile, stderr=subprocess.DEVNULL, text=True)
        else:
            # Root domain → all subdomains
            with open("subdomains.txt", "r") as infile, open(output_file, "w") as outfile:
                subprocess.run(
                    ["/root/go/bin/httpx", "-nc", "-status-code", "-title",
                     "-tech-detect", "-json", "-silent"],
                    stdin=infile,
                    stdout=outfile,
                    stderr=subprocess.DEVNULL,
                    text=True
                )

        # JSON'u oku → human-readable format bas
        count = 0
        output_text = ""
        if os.path.exists(output_file):
            with open(output_file) as f:
                for line in f:
                    if not line.strip():
                        continue
                    count += 1
                    output_text += line
                    try:
                        d = json.loads(line)
                        Logger.warning("🌍 Target Info")
                        Logger.info(f"- URL       : {d.get('url')}")
                        Logger.info(f"- Title     : {d.get('title')}")
                        Logger.info(f"- Host/IP   : {d.get('host')} ({', '.join(d.get('a', []))})")
                        Logger.info(f"- Server    : {d.get('webserver')}")
                        Logger.info(f"- Status    : {d.get('status_code')}")
                        Logger.info(f"- Resp Time : {d.get('time')}")
                        Logger.info(f"- Size      : {d.get('content_length')} bytes")
                        Logger.info(f"- Words     : {d.get('words')}, Lines: {d.get('lines')}")
                        if d.get("tech"):
                            Logger.success(f"[+] {len(d['tech'])} technologies detected")
                            Logger.inline_list("🛠 Technologies", d["tech"])
                    except Exception:
                        continue

        self.result_file = output_file
        return output_file, output_text



class SubzyCommand(Command):

    def get_stage_name(self) -> str:
        return "Subzy - Subdomain Takeover Detection"

    def execute(self):
        cmd = "subzy run --targets subdomains.txt"
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        findings = []
        if os.path.exists("subzy.txt"):
            with open("subzy.txt") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        findings.append(line)

        if findings:
            Logger.warning("🚨 Subzy Findings:")
            for f in findings:
                Logger.info(f"   • {f}")
        else:
            Logger.success("[+] No subdomain takeover issues found")

        self.result_file = "subzy.txt"
        return "subzy.txt", "\n".join(findings)


class FfufCommand(Command):

    def get_stage_name(self) -> str:
        return "FFUF - Endpoint Discovery"

    def execute(self):
        baseline_json = "/tmp/baseline.json"
        baseline_wordlist = "/usr/share/wordlists/onelistforallmicro.txt"

        # --- Baseline scan (fw / fs detection) ---
        subprocess.run(
            f"ffuf -u https://{self.domain}/FUZZ "
            f"-w {baseline_wordlist} "
            f"-mc all -of json -o {baseline_json} "
            f"-maxtime-job 5",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # --- Baseline filtering ---
        fw_vals, fs_vals = [], []
        try:
            with open(baseline_json) as f:
                data = json.load(f)
                for r in data.get("results", []):
                    if "words" in r:
                        fw_vals.append(r["words"])
                    if "length" in r:
                        fs_vals.append(r["length"])
        except Exception:
            pass

        from collections import Counter
        fw_base, fw_count = (0, 0)
        fs_base, fs_count = (0, 0)
        if fw_vals:
            fw_base, fw_count = Counter(fw_vals).most_common(1)[0]
        if fs_vals:
            fs_base, fs_count = Counter(fs_vals).most_common(1)[0]

        params = []
        if fw_vals and fs_vals and fw_count >= len(fw_vals) * 0.6 and fs_count >= len(fs_vals) * 0.6:
            params = [f"-fw {fw_base}", f"-fs {fs_base}"]
        elif fw_count >= fs_count and fw_count > 0:
            params = [f"-fw {fw_base}"]
        elif fs_count > 0:
            params = [f"-fs {fs_base}"]

        param_str = " ".join(params)
        Logger.warning(f"[*] Baseline scan finished → fw={fw_base}, fs={fs_base}")
        Logger.warning(f"[*] Applied filter params: {param_str or 'none'}")

        # --- Main Scan ---
        subprocess.run(
            f"ffuf -u https://{self.domain}/FUZZ "
            f"-w {baseline_wordlist} "
            f"-mc 200,201,202,203,204 {param_str} "
            f"-of json -o ffuf.json",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # --- Extract endpoints from ffuf.json ---
        endpoints = []
        try:
            with open("ffuf.json") as f:
                data = json.load(f)
                for r in data.get("results", []):
                    url = r.get("url")
                    if url:
                        endpoints.append(url)
        except Exception:
            pass

        with open("ffuf.txt", "w") as f:
            f.write("\n".join(endpoints))

        Logger.success(f"[+] Ffuf finished → {len(endpoints)} endpoints")
        Logger.list("[+] Ffuf Endpoints", endpoints, color=Fore.MAGENTA)

        self.result_file = "ffuf.txt"
        return "ffuf.txt", "\n".join(endpoints)
    
class KatanaCommand(Command):

    def get_stage_name(self) -> str:
        return "Katana - Content Discovery via Crawling"

    def execute(self):
        with open("katana.txt", "w") as outfile:
            subprocess.run(
                f"katana -silent -u https://{self.domain} -d 1 -rl 5",
                shell=True,
                stdout=outfile,
                stderr=subprocess.DEVNULL,
                text=True
            )
        self.result_file = "katana.txt"
        return "katana.txt", ""
    

class TechnologyAggregator:
    @staticmethod
    def collect():
        techs = set()

        # httpx
        if os.path.exists("alive.json"):
            with open("alive.json") as f:
                for line in f:
                    try:
                        d = json.loads(line.strip())
                        for t in d.get("tech", []):
                            techs.add(t)
                    except:
                        continue

        # whatweb
        if os.path.exists("whatweb.txt"):
            with open("whatweb.txt") as f:
                content = f.read()
                matches = re.findall(r"\[(.*?)\]", content)
                for m in matches:
                    techs.add(m.strip())

        # wappalyzer
        if os.path.exists("wappalyzer.json"):
            try:
                data = json.load(open("wappalyzer.json"))
                if isinstance(data, list):
                    for d in data:
                        for t in d.get("technologies", []):
                            techs.add(t.get("name"))
                elif isinstance(data, dict):
                    for t in data.get("technologies", []):
                        techs.add(t.get("name"))
            except:
                pass

        # ai extract
        if os.path.exists("tech_ai.json"):
            try:
                data = json.load(open("tech_ai.json"))
                for t in data.get("technologies", []):
                    techs.add(t)
            except:
                pass

        return sorted([t for t in techs if t])


class WhatwebCommand(Command):

    def get_stage_name(self) -> str:
        return "WhatWeb - Web Fingerprinting"

    def execute(self):
        return self._run(f"whatweb --max-threads=5 --open-timeout=20 --read-timeout=30 https://{self.domain}", "whatweb.txt")

class WappalyzerCommand(Command):

    def get_stage_name(self) -> str:
        return "Wappalyzer - Technology Detection"

    def execute(self):
        return self._run(
            f"/root/go/bin/wappalyzer --target https://{self.domain} --json",
            "wappalyzer.json"
        )

class BackupFinderCommand(Command):

    def get_stage_name(self) -> str:
        return "BackupFinder - High Risk Leak Snapshots"

    def execute(self):
        archive_url = (
            f'https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*'
            f'&output=txt&fl=original&collapse=urlkey&page=/'
        )

        # High-risk uzantılar (WayBackupFinder + refine)
        extensions = [
            ".sql", ".db", ".sqlite", ".sql.gz", ".sql.zip", ".sql.tar.gz",
            ".bak", ".backup", ".bkp", ".old", ".save",
            ".yml", ".yaml", ".config", ".conf", ".ini",
            ".pem", ".key", ".crt", ".pub", ".asc",
            ".secret", ".env", ".log", ".swp",
            ".tar", ".tar.gz", ".zip", ".rar", ".7z", ".gz", ".tgz"
        ]

        findings = []
        try:
            with requests.get(archive_url, stream=True, timeout=60) as r:
                r.raise_for_status()
                for raw_line in r.iter_lines(decode_unicode=True):
                    if not raw_line:
                        continue
                    url = raw_line.strip()
                    low = url.lower()

                    for ext in extensions:
                        if low.endswith(ext):
                            snapshot = ""
                            try:
                                snap_api = f'https://archive.org/wayback/available?url={url}'
                                resp = requests.get(snap_api, timeout=8)
                                if resp.ok:
                                    data = resp.json()
                                    snap_url = data.get("archived_snapshots", {}).get("closest", {}).get("url", "")
                                    if snap_url:
                                        try:
                                            # sadece erişilebilir snapshotları al
                                            head = requests.head(snap_url, timeout=10, allow_redirects=True)
                                            if head.status_code == 200:
                                                snapshot = snap_url
                                        except Exception:
                                            snapshot = ""
                            except Exception:
                                snapshot = ""

                            if snapshot:
                                findings.append({
                                    "url": url,          # orijinal URL
                                    "extension": ext,
                                    "snapshot": snapshot # erişilebilir snapshot
                                })
                                Logger.warning(f"[+] Leak: {snapshot}  ({ext})")
                            break
        except Exception as e:
            Logger.warning(f"[!] BackupFinder error: {e}")

        try:
            with open("backup_urls.json", "w") as fh:
                json.dump(findings, fh, indent=2)
        except Exception:
            pass

        self.result_file = "backup_urls.json"
        return "backup_urls.json", json.dumps(findings)

class JsHunterCommand(Command):
    def get_stage_name(self) -> str:
        return "JS Hunter - Gau/Wayback/Katana JS + Secrets"

    def execute(self):
        subprocess.run(f"gau {self.domain} > gau.txt", shell=True)
        subprocess.run(f"waybackurls {self.domain} > wayback.txt", shell=True)

        # Katana zaten ayrı Command → katana.txt hazır
        sources = ["gau.txt", "wayback.txt", "katana.txt"]
        merged = "allurls.txt"

        with open(merged, "w") as out:
            for src in sources:
                if os.path.exists(src):
                    with open(src) as f:
                        out.write(f.read())

        # .js filtrele
        subprocess.run("grep -Ei '\\.js(\\?|$)' allurls.txt | sort -u > js-urls.txt", shell=True)

        # canlı olanları bul
        subprocess.run(
            "cat js-urls.txt | /root/go/bin/httpx -silent -mc 200 -content-type "
            "| grep -E 'application/javascript|text/javascript' "
            "| cut -d' ' -f1 > live-js.txt",
            shell=True
        )

        findings = []
        with open("live-js.txt") as f:
            for url in f:
                url = url.strip()
                if not url:
                    continue
                try:
                    resp = requests.get(url, timeout=10)
                    matches = re.findall(r"(API_KEY|api_key|apikey|secret|token|password|AIza|AKIA|xox[baprs]-)", resp.text)
                    if matches:
                        findings.append({"url": url, "matches": list(set(matches))})
                        Logger.warning(f"[!] Secret found in {url}")
                        Logger.list("   Matches", list(set(matches)), color=Fore.RED)
                except Exception:
                    continue

        with open("js_secrets.json", "w") as f:
            json.dump(findings, f, indent=2)

        Logger.success(f"[+] JS Hunter finished → {len(findings)} secrets found")
        self.result_file = "js_secrets.json"
        return "js_secrets.json", json.dumps(findings)


class WaybackFetcher:
    def fetch(self, domain: str) -> list[str]:
        subprocess.run(f"waybackurls {domain} > wayback.txt", shell=True)
        return open("wayback.txt").read().splitlines()

class WaybackMatcher:
    def match(self, urls: list[str], wordlist: str) -> list[str]:
        with open(wordlist) as f:
            endpoints = [l.strip().lower() for l in f if l.strip()]

        matched = []
        for url in urls:
            try:
                parsed = urlparse(url)
                # path/query boşsa atla
                if not parsed.path or parsed.path == "/":
                    continue

                path_and_query = (parsed.path or "").lower()
                if parsed.query:
                    path_and_query += "?" + parsed.query.lower()

                if any(ep in path_and_query for ep in endpoints):
                    matched.append(url.strip())   
            except Exception:
                continue
        return matched


class WaybackReporter:
    def to_html(self, json_file: str) -> str:
        rows = []
        with open(json_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)  
                    rows.append(
                        f"<tr><td>{d.get('url','')}</td>"
                        f"<td>{d.get('status_code','')}</td>"
                        f"<td>{d.get('title','')}</td></tr>"
                    )
                except Exception:
                    continue

        return (
            "<table class='table table-bordered'>"
            "<thead><tr><th>URL</th><th>Status</th><th>Title</th></tr></thead>"
            "<tbody>" + "".join(rows) + "</tbody></table>"
        )

# ---------------------------
# Wayback (Only Passive Information)
# ---------------------------
class WaybackCommand(Command):

    def get_stage_name(self) -> str:
        return "Wayback - Historical URL Collection (No Live Check)"

    def execute(self):
        # 1) Fetch raw wayback URLs
        subprocess.run(f"waybackurls {self.domain} > wayback.txt", shell=True)

        urls = []
        if os.path.exists("wayback.txt"):
            with open("wayback.txt") as f:
                urls = f.read().splitlines()

        Logger.success(f"[+] Wayback total URLs: {len(urls)}")

        # 2) Filter out static assets
        subprocess.run(
            "grep -Ev '\\.(jpg|jpeg|png|gif|css|js|ico|svg|woff|ttf|mp4|avi|mov|mp3|wav)$' wayback.txt > wayback_urls.txt",
            shell=True
        )

        # Raporlama için sadece sayıyı logla
        if os.path.exists("wayback_urls.txt"):
            count = sum(1 for _ in open("wayback_urls.txt"))
            Logger.success(f"[+] Filtered Wayback URLs (non-static): {count}")
        else:
            Logger.warning("[!] wayback_urls.txt not found")

        self.result_file = "wayback_urls.txt"
        return "wayback_urls.txt", "\n".join(urls)


# ---------------------------
# Nuclei input builder
# ---------------------------

def normalize_url(url: str) -> str:
    """URL'leri normalize ederek duplicate sayısını azaltır"""
    try:
        parsed = urlparse(url.strip())
        scheme = parsed.scheme or "http"
        netloc = parsed.netloc
        path = parsed.path.rstrip("/")  
        return f"{scheme}://{netloc}{path or '/'}"
    except:
        return url.strip()

def build_nuclei_input():
    urls = []
    if os.path.exists("ffuf.txt"):
        with open("ffuf.txt") as f:
            for l in f:
                l = l.strip()
                if l and l.startswith("http"):
                    urls.append(l)

    
    with open("nuclei_urls.txt", "w") as f:
        f.write("\n".join(urls))

    Logger.warning(f"[*] Nuclei input size: {len(urls)} URLs (ffuf only)")
    return "nuclei_urls.txt"

# ---------------------------
# JWT Detection (Wayback URLs üzerinden)
# ---------------------------
class JwtScanCommand(Command):

    def get_stage_name(self) -> str:
        return "JWT Scan - Token Discovery (Wayback Only)"

    def execute(self):
        JWT_REGEX = re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}')
        juicy_fields = ["email", "username", "password", "api_key", "access_token", "session_id", "role", "scope"]

        findings = {}

        if os.path.exists("wayback_urls.txt"):
            with open("wayback_urls.txt") as f:
                for line in f:
                    url = line.strip()
                    if not url:
                        continue

                    decoded_url = unquote(url)
                    match = JWT_REGEX.search(decoded_url)
                    if match:
                        token = match.group(0)
                        try:
                            header, payload, sig = token.split(".")
                            decoded = jwt.decode(
                                token,
                                options={"verify_signature": False, "verify_aud": False}
                            )
                        except Exception:
                            decoded = {}

                        findings[url] = {
                            "jwt": token,
                            "decoded": decoded
                        }

        with open("jwt_results.json", "w") as f:
            json.dump(findings, f, indent=2)

        Logger.success(f"[+] JWT Scan finished → {len(findings)} tokens found")
        if findings:
            Logger.inline_list("[+] JWT URLs", list(findings.keys()), color=Fore.MAGENTA)

        self.result_file = "jwt_results.json"
        return "jwt_results.json", json.dumps(findings)

# ---------------------------
# AI Analyze JWT (Risky Claims)
# ---------------------------
class AiAnalyzeJwtCommand(Command):

    def get_stage_name(self) -> str:
        return "AI Analyze JWT - Risky Claims"

    def execute(self):
        OPENAI_KEY = os.getenv("OPENAI_KEY", "") 
        client = OpenAI(api_key=OPENAI_KEY)
        output_file = "jwt_ai_results.json"

        if not os.path.exists("jwt_results.json"):
            Logger.error("[!] jwt_results.json bulunamadı, AI analizi atlandı")
            with open(output_file, "w") as f:
                f.write("{}")
            return output_file, ""

        data = json.load(open("jwt_results.json"))
        if not data:
            Logger.warning("[!] jwt_results.json boş, AI analizi yapılmadı")
            with open(output_file, "w") as f:
                f.write("{}")
            return output_file, ""

        results_ai = {}
        for url, info in data.items():
            decoded = info.get("decoded")
            if not decoded:
                continue

            prompt = f"""
Analyze this JWT payload. Highlight risky claims only (admin=true, role=superuser, scope=write, tokens, keys).
Return JSON array only.
Payload: {json.dumps(decoded)}
"""
            resp = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                temperature=0
            )
            raw = resp.choices[0].message.content.strip()
            if raw.startswith("```"):
                raw = raw.strip("`").replace("json", "").strip()
            try:
                parsed = json.loads(raw)
            except Exception:
                parsed = []

            results_ai[url] = {
                "jwt": info["jwt"],
                "decoded": decoded,
                "risky": parsed
            }

        with open(output_file, "w") as f:
            json.dump(results_ai, f, indent=2)

        Logger.success(f"[+] AI Analyze JWT finished → {len(results_ai)} tokens analyzed")
        self.result_file = output_file
        return output_file, json.dumps(results_ai)



# ---------------------------
# AI Extract (inline, normalized)
# ---------------------------
class AiExtractCommand(Command):

    def get_stage_name(self) -> str:
        return "AI Extract - Technology Signals"


    def execute(self):
        OPENAI_KEY = ""  
        client = OpenAI(api_key=OPENAI_KEY)

        whatweb_out = open("whatweb.txt").read().strip() if os.path.exists("whatweb.txt") else ""
        wapp_out = open("wappalyzer.json").read().strip() if os.path.exists("wappalyzer.json") else ""
        ffuf_out = open("ffuf.txt").read().splitlines() if os.path.exists("ffuf.txt") else []
        katana_out = open("katana.txt").read().splitlines() if os.path.exists("katana.txt") else []

        # Backend signals
        def detect_backends(paths: list[str]) -> list[str]:
            backends = set()
            for p in paths:
                low = p.lower()
                if ".php" in low: backends.add("php")
                if ".asp" in low or ".aspx" in low: backends.add("asp.net")
                if ".jsp" in low: backends.add("java")
                if low.endswith(".py") or "/flask" in low or "/django" in low: backends.add("python")
                if ".rb" in low or "/rails" in low: backends.add("ruby")
            return list(backends)

        backend_signals = detect_backends(ffuf_out + katana_out)

        prompt = f"""
You are an expert security scanner.
Extract only technology names as lowercase JSON array.
Must include: {backend_signals}
WhatWeb: {whatweb_out}
Wappalyzer: {wapp_out}
"""

        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0
        )

        raw = resp.choices[0].message.content.strip()
        if raw.startswith("```"):
            raw = raw.strip("`").replace("json", "").strip()

        techs = []
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                techs = parsed
        except Exception:
            pass

        for b in backend_signals:
            if b not in techs:
                techs.append(b)

        with open("tech_ai.json", "w") as f:
            json.dump({"technologies": techs}, f, indent=2)

        Logger.success(f"[+] AI Extract finished → {len(techs)} technologies")
        Logger.inline_list("[+] AI Extract finished", techs, color=Fore.GREEN)


        self.result_file = "tech_ai.json"
        return "tech_ai.json", json.dumps({"technologies": techs})

# ---------------------------
# AI Select Templates (inline)
# ---------------------------
class AiSelectTemplatesCommand(Command):

    def get_stage_name(self) -> str:
        return "AI Select Templates - Smart Nuclei Coverage"

    def execute(self):
        OPENAI_KEY = ""  
        client = OpenAI(api_key=OPENAI_KEY)

        try:
            techs = json.load(open("tech_ai.json")).get("technologies", [])
        except:
            techs = []

        TEMPLATES_DIR = os.path.expanduser("~/.local/nuclei-templates")
        candidates = []
        for f in glob.glob(f"{TEMPLATES_DIR}/**/*.yaml", recursive=True):
            low = f.lower()
            if any(sig in low for sig in techs):
                candidates.append(f)

        prompt = f"Detected: {techs}\nCandidates: {candidates[:50]}\nReturn JSON array only."

        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0
        )

        raw = resp.choices[0].message.content.strip()
        if raw.startswith("```"):
            raw = raw.strip("`").replace("json", "").strip()

        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = []

        with open("selected_templates.json", "w") as f:
            json.dump(parsed, f, indent=2)

        Logger.success(f"[+] AI Select finished → {len(parsed)} templates")
        Logger.list("[+] AI Selected Templates", parsed, color=Fore.GREEN)



        self.result_file = "selected_templates.json"
        return "selected_templates.json", json.dumps(parsed)

    
# ---------------------------
# AI Select Endpoints (critical focus)
# ---------------------------
class AiSelectEndpointsCommand(Command):

    def get_stage_name(self) -> str:
        return "AI Select Endpoints - Suspicious Path Detection"

    def execute(self):
        OPENAI_KEY = "" 
        client = OpenAI(api_key=OPENAI_KEY)

        ffuf_out = open("ffuf.txt").read().splitlines() if os.path.exists("ffuf.txt") else []
        katana_out = open("katana.txt").read().splitlines() if os.path.exists("katana.txt") else []

        prompt = f"""
Select suspicious endpoints only (admin, login, upload, config, backup, wsdl, xml, php, test, dev, private, .git, .env, api, debug).
Return JSON array only.
Endpoints: {ffuf_out[:300] + katana_out[:100]}
"""

        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0
        )

        raw = resp.choices[0].message.content.strip()
        if raw.startswith("```"):
            raw = raw.strip("`").replace("json", "").strip()

        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = []

        endpoints = [str(ep).strip() for ep in parsed if str(ep).strip()]
        with open("ai_endpoints.txt", "w") as f:
            f.write("\n".join(endpoints))

        Logger.success(f"[+] AI Endpoints finished → {len(endpoints)} suspicious endpoints")
        Logger.list("[+] AI Endpoints", endpoints, color=Fore.GREEN)

        self.result_file = "ai_endpoints.txt"
        return "ai_endpoints.txt", "\n".join(endpoints)

def summarize_findings(findings):
    grouped = defaultdict(list)
    for f in findings:
        sev = (f.get("severity") or f.get("info", {}).get("severity", "info")).upper()
        name = f.get("info", {}).get("name", "Unknown")
        template = f.get("template", "unknown")
        grouped[(sev, name, template)].append(f.get("matched-at", ""))

    summary = []
    for (sev, name, template), urls in grouped.items():
        summary.append(f"[{sev}] {name} ({template}) → {len(urls)} occurrence(s)")
    return summary

# ---------------------------
# CVE Lookup via cves.json
# ---------------------------
def load_cves_json(path: str):
    """Load CVEs from cves.json (supports JSONL). Returns list of parsed objects."""
    items = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    items.append(obj)
                except json.JSONDecodeError as e:
                    # sadece problemli satırı atla, hepsini silme
                    Logger.warning(f"[cves.json] Skipped line {i}: {e}")
                    continue
    except FileNotFoundError:
        Logger.warning(f"[!] {path} not found")
    except Exception as e:
        Logger.warning(f"[!] Failed to read {path}: {e}")
    return items

def cves_json_lookup(techs, templates_root="~/.local/nuclei-templates"):
    """
    Map detected techs to nuclei CVE template paths using cves.json content.
    Supports entries with 'file' or 'file_path'. If vendor/product fields are not present,
    tries to match using Info.Name or ID heuristics.
    """
    root = os.path.expanduser(templates_root)
    cves_file = os.path.join(root, "cves.json")
    if not os.path.exists(cves_file):
        Logger.warning("[!] cves.json not found")
        return []

    raw_entries = load_cves_json(cves_file)
    if not raw_entries:
        Logger.warning("[!] cves.json empty or unreadable")
        return []

    matches = set()
    techs_lower = [t.lower() for t in techs]

    for entry in raw_entries:
        # support both keys
        file_rel = entry.get("file") or entry.get("file_path") or entry.get("filePath") or entry.get("template")
        if not file_rel:
            continue

        vendor = str(entry.get("vendor", "") or entry.get("Vendor", "")).lower()
        product = str(entry.get("product", "") or entry.get("Product", "")).lower()

        info_name = ""
        try:
            info = entry.get("Info") or entry.get("info") or {}
            info_name = str(info.get("Name", "") or info.get("name", "")).lower()
        except Exception:
            info_name = ""

        id_field = str(entry.get("ID", "") or entry.get("id", "")).lower()

        searchable = " ".join([vendor, product, info_name, id_field, file_rel]).lower()

        if any(sig in searchable for sig in techs_lower):
            full = os.path.join(root, file_rel)
            full = os.path.normpath(full)
            if os.path.exists(full):
                matches.add(full)
            else:
                alt = os.path.join(root, os.path.basename(file_rel))
                if os.path.exists(alt):
                    matches.add(alt)

    return sorted(matches)

class NucleiCriticalCommand(Command):

    def get_stage_name(self) -> str:
        return "Nuclei (Critical) - High/Severe Templates"

    def execute(self):
        urls_file = "ai_endpoints.txt" if os.path.exists("ai_endpoints.txt") else build_nuclei_input()

        # teknolojileri topla
        techs = TechnologyAggregator.collect()
        all_templates = cves_json_lookup(techs)

        # Template bulunduysa CVE'leri çalıştır
        if all_templates:
            Logger.success(f"[+] Resolved {len(all_templates)} CVE templates from cves.json")
            joined = " ".join([f"-t {t}" for t in all_templates])
            cmd = f"nuclei -l {urls_file} {joined} -severity critical,high -silent -jsonl -o nuclei_critical.json"
        else:
            Logger.warning("[!] No CVE templates matched in cves.json, falling back to default exposures/")
            cmd = (
                f"nuclei -l {urls_file} "
                f"-t exposures/ -t cves/ -t misconfiguration/ "
                f"-severity critical,high "
                f"-silent -jsonl -o nuclei_critical.json"
            )

        self._run(cmd, "nuclei_critical.json")

        findings = []
        try:
            with open("nuclei_critical.json") as f:
                for line in f:
                    try:
                        d = json.loads(line.strip())
                    except:
                        continue
                    sev = (d.get("severity") or d.get("info", {}).get("severity", "info")).upper()
                    name = d.get("info", {}).get("name", "Unknown")
                    template = d.get("template", "unknown")
                    findings.append(f"[{sev}] {name} ({template}) → {d.get('matched-at','')}")
        except:
            pass

        if findings:
            Logger.success(f"[+] {len(findings)} CVE-based nuclei findings")
            for f in findings:
                Logger.warning("   " + f)
        else:
            Logger.success("[+] No CVE-based nuclei findings")

        return "nuclei_critical.json", "\n".join(findings)


class NucleiAiCommand(Command):

    def get_stage_name(self) -> str:
        return "Nuclei (AI) - Targeted Vulnerability Scan"

    def execute(self):
        try:
            templates = json.load(open("selected_templates.json"))
        except:
            templates = []
        joined = " ".join([f"-t {t}" for t in templates])

        urls_file = build_nuclei_input()
        cmd = f"nuclei -l {urls_file} {joined} -jsonl -o nuclei_ai.json"
        # önce çalıştır
        self._run(cmd, "nuclei_ai.json")

        counts = {}
        try:
            with open("nuclei_ai.json") as f:
                for line in f:
                    try:
                        d = json.loads(line.strip())
                    except Exception:
                        continue
                    if not isinstance(d, dict):
                        continue
                    sev = (d.get("severity") or d.get("info", {}).get("severity", "info")).upper()
                    name = d.get("info", {}).get("name", "Unknown")
                    template = d.get("template", "unknown")
                    matched = d.get("matched-at", "") or d.get("matched-at") or d.get("matched_at", "")
                    key = (sev, name, template, matched)
                    counts[key] = counts.get(key, 0) + 1
        except Exception:
            pass

        grouped = {}
        for (sev, name, template, matched), cnt in counts.items():
            gkey = (sev, name, template)
            grouped.setdefault(gkey, []).append((matched, cnt))

        findings = []
        for (sev, name, template), items in grouped.items():
            total_occurrences = sum(c for _, c in items)
            example_urls = [u for u, _ in items][:5]
            url_part = ", ".join(example_urls)
            if total_occurrences > 1:
                findings.append(f"[{sev}] {name} ({template}) → {total_occurrences} occurrence(s); examples: {url_part}")
            else:
                findings.append(f"[{sev}] {name} ({template}) → {url_part}")

        if findings:
            Logger.success(f"[+] {len(findings)} nuclei findings from AI templates")
            for f in findings:
                Logger.warning("   " + f)
        else:
            Logger.success("[+] No nuclei findings from AI templates")


        return "nuclei_ai.json", "\n".join(findings)

# ---------------------------
# Strategy Pattern
# ---------------------------
class DomainStrategy(ABC):
    @abstractmethod
    def get_targets(self, domain: str) -> list[str]:
        pass

class RootDomainStrategy(DomainStrategy):
    def get_targets(self, domain: str) -> list[str]:
        subfinder = SubfinderCommand(domain)
        subfinder.execute()
        with open("subdomains.txt") as f:
            return [line.strip() for line in f if line.strip()]

class SubdomainStrategy(DomainStrategy):
    def get_targets(self, domain: str) -> list[str]:
        with open("subdomains.txt", "w") as f:
            f.write(domain + "\n")
        return [domain]


# ---------------------------
# Factory Method Pattern
# ---------------------------
class CommandFactory:
    mapping = {
        "subfinder": SubfinderCommand,
        "httpx": HttpxCommand,
        "subzy": SubzyCommand,
        "ffuf": FfufCommand,
        "katana": KatanaCommand,
        "whatweb": WhatwebCommand,
        "wappalyzer": WappalyzerCommand,
        "ai_extract": AiExtractCommand,
        "ai_select": AiSelectTemplatesCommand,
        "nuclei_ai": NucleiAiCommand,
        "js_hunter": JsHunterCommand,
        "nuclei_critical": NucleiCriticalCommand,
        "wayback": WaybackCommand,
        "backup": BackupFinderCommand,
        "jwt_scan": JwtScanCommand,
        "jwt_ai": AiAnalyzeJwtCommand,
    }

    @staticmethod
    def create(name, domain):
        cls = CommandFactory.mapping.get(name)
        if not cls:
            raise ValueError(f"Unknown command: {name}")
        return cls(domain)

# ---------------------------
# Chain of Responsibility + Invoker
# ---------------------------
class Handler(ABC):
    def __init__(self, next_handler=None):
        self.next_handler = next_handler

    @abstractmethod
    def handle(self, domain, builder, observers):
        if self.next_handler:
            return self.next_handler.handle(domain, builder, observers)


class CommandHandler(Handler):
    SILENT_COMMANDS = {"KatanaCommand", "WhatwebCommand", "WappalyzerCommand", "WaybackCommand"}

    def __init__(self, command: Command, next_handler=None):
        super().__init__(next_handler)
        self.command = command

    def handle(self, domain, builder, observers):
        # Eğer command bir TimingDecorator ise asıl komutu al
        inner = getattr(self.command, "_command", None)
        cls_name = inner.__class__.__name__ if inner is not None else self.command.__class__.__name__
        stage_name = (inner.get_stage_name() if inner is not None else self.command.get_stage_name())

        # Sadece sessiz olmayan komutlarda stage başlığı bas
        if cls_name not in self.SILENT_COMMANDS:
            Logger.stage(f"Starting {stage_name}")

        try:
            file, output = self.command.execute()
            builder.add_section(stage_name, file)

            # Duration al: TimingDecorator varsa onun last_duration'ını kullan
            duration_msg = ""
            last_dur = None
            # self.command olabilir TimingDecorator veya komutun kendisi
            if hasattr(self.command, "last_duration") and getattr(self.command, "last_duration"):
                last_dur = getattr(self.command, "last_duration")
            # ya da inner varsa inner'in last_duration'ını da kontrol et
            if last_dur is None and inner and hasattr(inner, "last_duration"):
                last_dur = getattr(inner, "last_duration")

            if last_dur:
                mins, secs = divmod(last_dur, 60)
                duration_msg = f" (took {int(mins)}m {secs:.2f}s)"

            # Sadece sessiz olmayan komutlarda success bas
            if cls_name not in self.SILENT_COMMANDS:
                Logger.success(f"[+] {stage_name} completed successfully{duration_msg}")

        except Exception as e:
            if cls_name not in self.SILENT_COMMANDS:
                Logger.warning(f"[!] {stage_name} failed: {e}")

        if self.next_handler:
            return self.next_handler.handle(domain, builder, observers)



class PipelineInvoker:
    def __init__(self, first_handler: Handler):
        self.first_handler = first_handler

    def run(self, domain, builder, observers):
        if self.first_handler:
            self.first_handler.handle(domain, builder, observers)


def build_chain(domain):
    return CommandHandler(TimingDecorator(HttpxCommand(domain)),
        CommandHandler(TimingDecorator(SubzyCommand(domain)),
        CommandHandler(TimingDecorator(FfufCommand(domain)),
        CommandHandler(TimingDecorator(KatanaCommand(domain)),
        CommandHandler(TimingDecorator(WhatwebCommand(domain)),
        CommandHandler(TimingDecorator(WappalyzerCommand(domain)),
        CommandHandler(TimingDecorator(WaybackCommand(domain)),
        CommandHandler(TimingDecorator(JsHunterCommand(domain)), 
        CommandHandler(TimingDecorator(BackupFinderCommand(domain)),
        CommandHandler(TimingDecorator(JwtScanCommand(domain)),
        CommandHandler(TimingDecorator(AiAnalyzeJwtCommand(domain)),
        CommandHandler(TimingDecorator(AiExtractCommand(domain)),
        CommandHandler(TimingDecorator(AiSelectTemplatesCommand(domain)),
        CommandHandler(TimingDecorator(NucleiAiCommand(domain)),
        CommandHandler(TimingDecorator(AiSelectEndpointsCommand(domain)),
        CommandHandler(TimingDecorator(NucleiCriticalCommand(domain))))))))))))))))))


# ---------------------------
# Builder Pattern: Report
# ---------------------------
# ---------------------------
# Builder Pattern: Report
# ---------------------------
class ReportBuilder:
    def __init__(self, domain):
        self.domain = domain
        self.sections = []

    def add_section(self, title, filename):
        if filename and os.path.exists(filename):
            with open(filename) as f:
                try:
                    if filename.endswith(".json"):
                        content = f.read()
                        try:
                            parsed = json.loads(content)
                            if isinstance(parsed, (dict, list)):
                                self.sections.append((title, filename, json.dumps(parsed, indent=2)))
                                return
                        except:
                            pass
                        f.seek(0)
                        content = f.read()
                    else:
                        content = f.read()
                except Exception:
                    content = "[error parsing]"
        else:
            content = "[missing]"
        self.sections.append((title, filename, content))

    def build_html(self):
        findings = []
        for title, filename, content in self.sections:
            if filename and filename.endswith(".json"):
                for line in content.splitlines():
                    try:
                        d = json.loads(line)
                        if isinstance(d, dict) and "matched-at" in d:
                            findings.append(d)
                    except Exception:
                        continue

        severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = (f.get("severity") or f.get("info", {}).get("severity", "info")).lower()
            if sev in severity_count:
                severity_count[sev] += 1
            else:
                severity_count["info"] += 1

        grouped = defaultdict(list)
        for f in findings:
            sev = (f.get("severity") or f.get("info", {}).get("severity", "info")).lower()
            template = f.get("template", "unknown")
            name = f.get("info", {}).get("name", "Unknown")
            key = (template, name, sev)
            grouped[key].append(f.get("matched-at", ""))

        severity_map = {
            "critical": "badge-critical",
            "high": "badge-high",
            "medium": "badge-medium",
            "low": "badge-low",
            "info": "badge-info"
        }

        techs = []
        try:
            for t in self.sections:
                if t[1] and t[1].endswith("tech_ai.json"):
                    techs = json.loads(t[2]).get("technologies", [])
        except Exception:
            pass

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Report - {self.domain}</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
    body {{ background:#f8f9fa; }}
    header {{ background:#212529; color:#fff; padding:20px; text-align:center; }}
    .badge-critical {{ background-color:#dc3545; }}
    .badge-high {{ background-color:#fd7e14; }}
    .badge-medium {{ background-color:#ffc107; color:#000; }}
    .badge-low {{ background-color:#198754; }}
    .badge-info {{ background-color:#0dcaf0; color:#000; }}
</style>
</head>
<body>
<header>
<h1>Security Assessment Report</h1>
<p>Target: <strong>{self.domain}</strong></p>
</header>
<div class="container my-4">
"""

        total = sum(severity_count.values())
        html += f"""
<section class="mb-4">
<h2>Executive Summary</h2>
<p><strong>Total Findings:</strong> {total}</p>
<ul>
    <li>Critical: {severity_count['critical']}</li>
    <li>High: {severity_count['high']}</li>
    <li>Medium: {severity_count['medium']}</li>
    <li>Low: {severity_count['low']}</li>
    <li>Info: {severity_count['info']}</li>
</ul>
</section>
"""

        # 🌍 Alive Hosts
        try:
            for t in self.sections:
                if t[1] and t[1].endswith("alive.json"):
                    alive = []
                    for line in t[2].splitlines():
                        try:
                            d = json.loads(line)
                            alive.append((d.get("url"), d.get("title", ""), d.get("status_code", "")))
                        except Exception:
                            continue
                    if alive:
                        html += """
<section class="mb-4">
<h2>🌍 Alive Hosts (HTTPX)</h2>
<table class="table table-bordered">
<thead><tr><th>URL</th><th>Status</th><th>Title</th></tr></thead><tbody>
"""
                        for url, title, status in alive:
                            html += f"<tr><td>{url}</td><td>{status}</td><td>{title}</td></tr>"
                        html += "</tbody></table></section>"
        except Exception:
            pass

        # 📂 FFUF Endpoints
        try:
            for t in self.sections:
                if t[1] and t[1].endswith("ffuf.txt"):
                    eps = t[2].splitlines()
                    if eps:
                        html += """
<section class="mb-4">
<h2>📂 FFUF Endpoints</h2>
<ul>
"""
                        for ep in eps:
                            html += f"<li>{ep}</li>"
                        html += "</ul></section>"
        except Exception:
            pass

        if techs:
            html += """
<section class="mb-4">
<h2>Detected Technologies (AI)</h2>
<ul>
"""
            for t in techs:
                html += f"<li>{t}</li>"
            html += "</ul></section>"""

        # 🚪 AI Endpoints
        try:
            for t in self.sections:
                if t[1] and t[1].endswith("ai_endpoints.txt"):
                    eps = t[2].splitlines()
                    if eps:
                        html += """
<section class="mb-4">
<h2>🚪 Suspicious Endpoints (AI)</h2>
<ul>
"""
                        for ep in eps:
                            html += f"<li>{ep}</li>"
                        html += "</ul></section>"
        except Exception:
            pass

        # 📂 AI Selected Templates
        try:
            for t in self.sections:
                if t[1] and t[1].endswith("selected_templates.json"):
                    templates = json.loads(t[2])
                    if templates:
                        html += """
<section class="mb-4">
<h2>📂 AI Selected Templates</h2>
<ul>
"""
                        for tpl in templates:
                            html += f"<li>{tpl}</li>"
                        html += "</ul></section>"
        except Exception:
            pass

        # 🧪 JWT AI Results
        try:
            for t in self.sections:
                if t[1] and t[1].endswith("jwt_ai_results.json"):
                    jwt_data = json.loads(t[2])
                    if jwt_data:
                        html += """
<section class="mb-4">
<h2>🧪 JWT Findings (AI)</h2>
<ul>
"""
                        for url, details in jwt_data.items():
                            risky = details.get("risky", [])
                            if risky:
                                html += f"<li><strong>{url}</strong>: {json.dumps(risky)}</li>"
                        html += "</ul></section>"
        except Exception:
            pass

        # 📦 Backup / Leak Files
        try:
            if os.path.exists("backup_urls.json"):
                with open("backup_urls.json") as f:
                    backup_data = json.load(f)
                if backup_data:
                    html += """
<section class="mb-4">
<h2>📦 Backup / Leak Files (Wayback)</h2>
<table class="table table-bordered">
<thead><tr><th>URL</th><th>Extension</th><th>Snapshot</th></tr></thead><tbody>
"""
                    for b in backup_data:
                        url = b.get("url", "")
                        ext = b.get("extension", "")
                        snap = b.get("snapshot", "") or ""
                        snap_html = f"<a href='{snap}' target='_blank'>View</a>" if snap else "—"
                        html += f"<tr><td>{url}</td><td>{ext}</td><td>{snap_html}</td></tr>"
                    html += "</tbody></table></section>"
        except Exception:
            pass

        if grouped:
            html += """
<section class="mb-4">
<h2>Findings Overview (Nuclei - Deduplicated)</h2>
<ul>
"""
            for (template, name, sev), urls in grouped.items():
                badge_class = severity_map.get(sev, "badge-info")
                html += f"""
<li>
  <span class="badge {badge_class}">{sev.upper()}</span>
  <strong>{name}</strong> ({template})<br>
  Found in {len(urls)} URLs:
  <ul>
    {''.join(f"<li>{u}</li>" for u in urls)}
  </ul>
</li>
"""
            html += "</ul></section>"

        html += """
</div>
<footer class="text-center p-3 text-muted">
Generated by ScannerPipeline
</footer>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body></html>
"""

        file = f"report-{self.domain}.html"
        with open(file, "w") as f:
            f.write(html)
        return file


# ---------------------------
# Pipeline
# ---------------------------
class ScannerPipeline:
    def __init__(self, domain, observers: list[Observer]):
        global_cleanup()
        self.domain = domain
        self.observers = observers
        ext = tldextract.extract(domain)
        self.strategy = SubdomainStrategy() if ext.subdomain else RootDomainStrategy()

    def run_single_pipeline(self, domain, builder: "ReportBuilder"):
        chain = build_chain(domain)              
        invoker = PipelineInvoker(chain)         
        invoker.run(domain, builder, self.observers)

    def run(self):
        builder = ReportBuilder(self.domain)
        targets = self.strategy.get_targets(self.domain)
        for target in targets:
            self.run_single_pipeline(target, builder)

        all_techs = TechnologyAggregator.collect()

        report_file = builder.build_html()

        def cleanup_after_report(report_file: str):
            keep = os.path.basename(report_file)
            for f in os.listdir("."):
                if f == keep:
                    continue
                if f.endswith((".json", ".txt", ".log")):
                    try:
                        os.remove(f)
                    except Exception as e:
                        pass

        cleanup_after_report(report_file)


        cleanup_after_report(report_file)

# ---------------------------
# Main
# ---------------------------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", required=True)
    args = parser.parse_args()
    ScannerPipeline(args.domain, [ConsoleObserver(), LogFileObserver()]).run()
