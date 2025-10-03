#!/usr/bin/env python3
from __future__ import annotations
import os, sys, subprocess, json, threading, signal, atexit, re, requests
from queue import Queue, Empty
from abc import ABC, abstractmethod
from urllib.parse import urlparse
import tldextract
from collections import Counter
from colorama import Fore, Style, init
init(autoreset=True)
import jwt

# ---------------------------
# Helpers
# ---------------------------
PRINT_LOCK = threading.Lock()

def sanitize_name(name: str) -> str:
    return re.sub(r'[^a-zA-Z0-9\-_.]', '_', name)

def safe_run(cmd, timeout=None, stdin=None):
    try:
        res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, timeout=timeout, stdin=stdin)
        return res.returncode, res.stdout, res.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"

# ---------------------------
# Cleanup
# ---------------------------
def global_cleanup(keep_files=None):
    keep = set(keep_files or [])
    for f in os.listdir("."):
        if f in ("scanner.py", "nonai.py", "README.md", "resume.cfg"):
            continue
        if f in keep:
            continue
        if any(f.lower().endswith(ext) for ext in (".json", ".txt", ".log", ".html")):
            try: os.remove(f)
            except Exception: pass

def cleanup_before_run(): global_cleanup()
def handle_exit(*a): global_cleanup(); sys.exit(0)
atexit.register(lambda: global_cleanup())
signal.signal(signal.SIGINT, handle_exit)
signal.signal(signal.SIGTERM, handle_exit)

# ---------------------------
# Logger
# ---------------------------
class Logger:
    @staticmethod
    def _print(color, msg):
        with PRINT_LOCK: print(color + msg + Style.RESET_ALL)
    @staticmethod
    def info(msg): Logger._print(Fore.CYAN, msg)
    @staticmethod
    def success(msg): Logger._print(Fore.GREEN, msg)
    @staticmethod
    def warning(msg): Logger._print(Fore.YELLOW, msg)
    @staticmethod
    def error(msg): Logger._print(Fore.RED, msg)
    @staticmethod
    def stage(title):
        with PRINT_LOCK:
            print("\n" + "="*80)
            print(Fore.MAGENTA + f"[ {title} ]" + Style.RESET_ALL)
            print("="*80 + "\n")
    @staticmethod
    def debug(msg): Logger._print(Fore.LIGHTBLACK_EX, f"[DEBUG] {msg}")

# ---------------------------
# Stage Buffer / Barrier
# ---------------------------
stage_outputs = {}
stage_barriers = {}
STAGE_ORDER = [
    "Subzy - Subdomain Takeover Detection",
    "FFUF - Endpoint Discovery",
    "Katana - Content Discovery via Crawling",
    "Wayback - Historical URL Collection (No Live Check)",
    "JS Hunter - .js URLs & secrets",
    "Secret Scan - JS sensitive data",
    "BackupFinder - Archive leak scan",   # ✅ eşleşti
    "JWT Scan - Heuristic token search"   # ✅ eşleşti
]




def register_barriers(n_workers):
    global stage_barriers
    stage_barriers = {s: threading.Barrier(n_workers+1) for s in STAGE_ORDER}

def record_stage_output(stage, domain, filename):
    """
    filename may be:
      - a string (path)
      - a tuple like (path, output_text) if command returned both
      - None
    We normalize to `content` (string) and store in stage_outputs[stage][domain].
    Then wait on the barrier for that stage.
    """
    content = ""

    # normalize filename param: allow tuple (fname, output_str)
    fname = None
    if isinstance(filename, tuple):
        # common pattern: (fname, output_str)
        if len(filename) >= 1 and isinstance(filename[0], str):
            fname = filename[0]
        # If second element exists and is a string, prefer that as content fallback
        if len(filename) >= 2 and isinstance(filename[1], str) and filename[1].strip():
            content = filename[1]

    elif isinstance(filename, str):
        fname = filename

    # If we have a file path and no inline content yet, try to read the file
    if fname and os.path.exists(fname) and not content:
        try:
            content = open(fname, "r", errors="ignore").read()
        except Exception:
            content = "[error reading]"

    # If still empty, keep content as empty string
    stage_outputs.setdefault(stage, {})[domain] = content

    # Wait on the barrier (will raise if stage not registered)
    if stage not in stage_barriers:
        # defensive: if stage missing, log and skip wait to avoid KeyError crash
        Logger.debug(f"[!] stage '{stage}' not found in barriers (skipping wait)")
        return
    stage_barriers[stage].wait()


def print_stage_results(stage: str):
    SILENT_STAGES = {
        "Wayback - Historical URL Collection (No Live Check)",
        "Katana - Content Discovery via Crawling",
        "JS Hunter - .js URLs & secrets"
    }

    domains_contents = stage_outputs.get(stage, {})
    if not domains_contents:
        return

    # Header sadece FFUF için
    if stage.startswith("FFUF"):
        Logger.stage(stage)

    for domain, content in domains_contents.items():
        if stage in SILENT_STAGES:
            continue

        # 🔴 Secret Scan özelleştirilmiş çıktı
        if stage.startswith("Secret Scan"):
            print(Fore.YELLOW + f"[{domain}]" + Style.RESET_ALL)
            try:
                findings = json.loads(content)
                for f in findings:
                    t = f.get("type")
                    u = f.get("url")
                    m = f.get("match", "")
                    print(Fore.RED + f"[!] {t} in {u} → {m[:60]}..." + Style.RESET_ALL)
            except Exception:
                print(content)
            print("\n" + "-"*40 + "\n")
            continue

        # 🟢 JWT Scan özelleştirilmiş çıktı
        if stage.startswith("JWT Scan"):
            print(Fore.YELLOW + f"[{domain}]" + Style.RESET_ALL)
            try:
                results = json.loads(content)
                for url, data in results.items():
                    juicy = data.get("juicy", {})
                    if juicy:
                        print(Fore.GREEN + f"[+] JWT in {url} → {juicy}" + Style.RESET_ALL)
                    else:
                        print(Fore.CYAN + f"[i] JWT in {url} (no juicy fields)" + Style.RESET_ALL)
            except Exception:
                print(content)
            print("\n" + "-"*40 + "\n")
            continue

        # FFUF: endpoints yeşil
        if stage.startswith("FFUF"):
            print(Fore.YELLOW + f"[{domain}]" + Style.RESET_ALL)
            if content and isinstance(content, str) and content.strip():
                for line in content.splitlines():
                    if line.strip():
                        print(Fore.GREEN + line.strip() + Style.RESET_ALL)
            print("\n" + "-"*40 + "\n")
            continue

        # Diğer stage’ler default
        print(Fore.YELLOW + f"[{domain}]" + Style.RESET_ALL)
        if isinstance(content, str) and content.strip():
            print(content)
        print("\n" + "-"*40 + "\n")

# ---------------------------
# Command Base
# ---------------------------
class Command(ABC):
    def __init__(self, domain): self.domain, self.base = domain, sanitize_name(domain)
    @abstractmethod
    def get_stage_name(self): pass
    @abstractmethod
    def execute(self): pass

# ---------------------------
# Subfinder
# ---------------------------
class SubfinderCommand(Command):
    def get_stage_name(self): return "Subfinder - Subdomain Enumeration"
    def execute(self):
        ext = tldextract.extract(self.domain)
        out = f"subdomains_{self.base}.txt"
        if ext.subdomain:
            open(out, "w").write(self.domain + "\n")
            Logger.success(f"[+] Subfinder quick: single subdomain -> {out}")
            return out
        cmd = f"subfinder -d {ext.domain}.{ext.suffix} -silent -o {out}"
        Logger.info("Running: " + cmd)
        safe_run(cmd, timeout=180)
        count = sum(1 for _ in open(out)) if os.path.exists(out) else 0
        Logger.success(f"[+] Subfinder produced {count} subdomains")
        return out

# ---------------------------
# HTTPX Precheck
# ---------------------------
class HttpxPrecheck:
    BIN = "/root/go/bin/httpx"
    @staticmethod
    def run_for_file(subfile, out_file, timeout=180):
        cmd = f"{HttpxPrecheck.BIN} -l {subfile} -sc -title -td -j -o {out_file} -silent"
        Logger.info("Running: " + cmd)
        safe_run(cmd, timeout=timeout); return out_file
    @staticmethod
    def run_for_single(domain, out_file, timeout=120):
        cmd = f"{HttpxPrecheck.BIN} -u https://{domain} -sc -title -td -j -o {out_file} -silent"
        Logger.info("Running: " + cmd)
        safe_run(cmd, timeout=timeout); return out_file
    @staticmethod
    def parse_alive(out_file):
        alive = []
        if not os.path.exists(out_file): return alive
        for line in open(out_file):
            try: obj = json.loads(line)
            except: continue
            status = obj.get("status_code") or obj.get("status")
            if str(status) != "200": continue
            val = obj.get("input") or obj.get("url") or obj.get("host")
            if val:
                host = urlparse(val).netloc or val
                host = host.split(":")[0]
                if host not in alive: alive.append(host)
        return alive

# ---------------------------
# Subzy
# ---------------------------
class SubzyPerHost(Command):
    def get_stage_name(self): return "Subzy - Subdomain Takeover Detection"
    def execute(self):
        subfile = f"subdomains_{self.base}.txt"; open(subfile,"w").write(self.domain+"\n")
        out = f"subzy_{self.base}.txt"
        cmd = f"subzy run --targets {subfile} -o {out}"
        safe_run(cmd, timeout=120)
        return out

# ---------------------------
# FFUF
# ---------------------------
class FfufCommand(Command):

    def get_stage_name(self) -> str:
        return "FFUF - Endpoint Discovery"

    def execute(self):
        baseline_json = "/tmp/baseline.json"
        baseline_wordlist = "/usr/share/wordlists/onelistforallmicro.txt"
        main_json = "ffuf_main.json"
        endpoints_txt = "ffuf.txt"

        # Baseline quick run (küçük süreli)
        subprocess.run(
            f"ffuf -u https://{self.domain}/FUZZ -w {baseline_wordlist} -mc all -of json -o {baseline_json} -maxtime-job 5",
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        # Baseline analiz (fw / fs)
        fw_vals, fs_vals = [], []
        try:
            with open(baseline_json) as f:
                data = json.load(f)
                for r in data.get("results", []):
                    if "words" in r: fw_vals.append(r["words"])
                    if "length" in r: fs_vals.append(r["length"])
        except Exception:
            pass

        from collections import Counter
        fw_base = fs_base = None
        try:
            if fw_vals:
                fw_base = Counter(fw_vals).most_common(1)[0][0]
            if fs_vals:
                fs_base = Counter(fs_vals).most_common(1)[0][0]
        except Exception:
            fw_base = fw_base or None
            fs_base = fs_base or None

        params = []
        if fw_base: params.append(f"-fw {fw_base}")
        if fs_base: params.append(f"-fs {fs_base}")
        param_str = " ".join(params)

        Logger.debug(f"[*] Baseline scan finished → fw={fw_base or 'n/a'}, fs={fs_base or 'n/a'}")
        Logger.debug(f"[*] Applied filter params: {param_str or 'none'}")

        # --- MAIN scan (bunu terminale basacağız) ---
        # output JSON (single file)
        cmd_main = (
            f"ffuf -u https://{self.domain}/FUZZ -w {baseline_wordlist} -mc 200,201,202,203,204 {param_str} "
            f"-of json -o {main_json}"
        )
        subprocess.run(cmd_main, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # --- Robust parse of main_json: try standard JSON, else try jsonl/lines ---
        endpoints = []
        try:
            with open(main_json) as f:
                raw = f.read().strip()
                if not raw:
                    data = {}
                else:
                    try:
                        data = json.loads(raw)
                    except Exception:
                        # try JSONL or multiple objects: parse line-by-line
                        data = {"results": []}
                        for line in raw.splitlines():
                            line=line.strip()
                            if not line: continue
                            try:
                                obj = json.loads(line)
                                # ffuf jsonl may have top-level "results" or be a chunk; support both
                                if isinstance(obj, dict) and "results" in obj:
                                    data["results"].extend(obj.get("results", []))
                                elif isinstance(obj, dict) and "url" in obj:
                                    data["results"].append(obj)
                                elif isinstance(obj, list):
                                    data["results"].extend(obj)
                            except Exception:
                                continue

                for r in data.get("results", []):
                    url = r.get("url") or r.get("input", {}).get("url") if isinstance(r.get("input"), dict) else None
                    if not url:
                        # legacy: try 'host' + 'input.FUZZ' etc
                        url = r.get("url") or r.get("resultfile") or None
                    if url:
                        endpoints.append(url)
        except Exception:
            pass

        # Fallback: if no endpoints in JSON, try to extract lines that look like http(s)
        if not endpoints and os.path.exists(main_json):
            try:
                with open(main_json) as f:
                    for line in f:
                        for token in re.findall(r"https?://[^\s\"']+", line):
                            if token not in endpoints: endpoints.append(token)
            except Exception:
                pass

        # Save endpoints to text for later pipeline stages
        try:
            with open(endpoints_txt, "w") as f:
                f.write("\n".join(endpoints))
        except Exception:
            pass

        # Terminal output: print only main endpoints, green
        if endpoints:
            Logger.success(f"[+] Ffuf finished → {len(endpoints)} endpoints")
        else:
            Logger.warning("[!] No endpoints found by ffuf (main scan)")


        # Return tuple (file, inline content) so record_stage_output can save content safely
        # second element is newline-joined endpoints (string)
        return endpoints_txt, "\n".join(endpoints)



# ---------------------------
# Katana, Wayback, JS
# ---------------------------
class KatanaCommand(Command):

    def get_stage_name(self) -> str:
        return "Katana - Content Discovery via Crawling"

    def execute(self):
        # Katana sonuçlarını dosyaya al ama ekrana hiçbir şey basma
        with open("katana.txt", "w") as outfile:
            subprocess.run(
                f"katana -silent -u https://{self.domain} -d 1 -rl 5",
                shell=True,
                stdout=outfile,
                stderr=subprocess.DEVNULL,
                text=True
            )
        # Konsola log basılmıyor ❌
        self.result_file = "katana.txt"
        return "katana.txt", ""


class WaybackCommand(Command):

    def get_stage_name(self) -> str:
        return "Wayback - Historical URL Collection (No Live Check)"

    def execute(self):
        subprocess.run(f"waybackurls {self.domain} > wayback.txt", shell=True)

        urls = []
        if os.path.exists("wayback.txt"):
            with open("wayback.txt") as f:
                urls = f.read().splitlines()

        # ❌ Terminale log yok
        subprocess.run(
            "grep -Ev '\\.(jpg|jpeg|png|gif|css|js|ico|svg|woff|ttf|mp4|avi|mov|mp3|wav)$' wayback.txt > wayback_urls.txt",
            shell=True
        )

        self.result_file = "wayback_urls.txt"
        return "wayback_urls.txt", "\n".join(urls)


class JsHunterCommand(Command):
    def get_stage_name(self): return "JS Hunter - .js URLs & secrets"
    def execute(self): out=f"js_urls_{self.base}.txt"; safe_run(f"gau {self.domain} | grep -Ei '\\.js(\\?|$)' > {out}", timeout=60); return out

# ---------------------------
# Secret Scan
# ---------------------------
SECRET_REGEX = {
    'google_api'     : r'AIza[0-9A-Za-z-_]{35}',
    'firebase'  : r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    'google_captcha' : r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
    'google_oauth'   : r'ya29\.[0-9A-Za-z\-_]+',
    'amazon_aws_access_key_id' : r'A[SK]IA[0-9A-Z]{16}',
    'amazon_mws_auth_toke' : r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'amazon_aws_url' : r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
    'amazon_aws_url2' : r"(" \
           r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com" \
           r"|s3://[a-zA-Z0-9-\.\_]+" \
           r"|s3-[a-zA-Z0-9-\.\_\/]+" \
           r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+" \
           r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)",
    'facebook_access_token' : r'EAACEdEose0cBA[0-9A-Za-z]+',
    'authorization_basic' : r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
    'authorization_bearer' : r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
    'authorization_api' : r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
    'mailgun_api_key' : r'key-[0-9a-zA-Z]{32}',
    'twilio_api_key' : r'SK[0-9a-fA-F]{32}',
    'twilio_account_sid' : r'AC[a-zA-Z0-9_\-]{32}',
    'twilio_app_sid' : r'AP[a-zA-Z0-9_\-]{32}',
    'paypal_braintree_access_token' : r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'square_oauth_secret' : r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
    'square_access_token' : r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
    'stripe_standard_api' : r'sk_live_[0-9a-zA-Z]{24}',
    'stripe_restricted_api' : r'rk_live_[0-9a-zA-Z]{24}',
    'github_access_token' : r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
    'rsa_private_key' : r'-----BEGIN RSA PRIVATE KEY-----',
    'ssh_dsa_private_key' : r'-----BEGIN DSA PRIVATE KEY-----',
    'ssh_dc_private_key' : r'-----BEGIN EC PRIVATE KEY-----',
    'pgp_private_block' : r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'json_web_token' : r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
    'slack_token' : r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
    'SSH_privKey' : r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
    'Heroku API KEY' : r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    'possible_Creds' : r"(?i)(" \
                    r"password\s*[`=:\"]+\s*[^\s]+|" \
                    r"password is\s*[`=:\"]*\s*[^\s]+|" \
                    r"pwd\s*[`=:\"]*\s*[^\s]+|" \
                    r"passwd\s*[`=:\"]+\s*[^\s]+)",
}


class SecretScanCommand(Command):
    def get_stage_name(self): 
        return "Secret Scan - JS sensitive data"
    
    def execute(self):
        out = f"secrets_{self.base}.json"
        js_file = f"js_urls_{self.base}.txt"
        findings = []

        if not os.path.exists(js_file):
            Logger.info("[!] No JS URLs for secret scan")
            return out

        urls = [l.strip() for l in open(js_file) if l.strip()]
        JWT_REGEX = re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}')
        JUICY_FIELDS = ["email", "username", "password", "api_key", "access_token", "session_id", "role", "scope"]

        for url in urls:
            try:
                resp = requests.get(url, timeout=10)
                if not resp.ok: 
                    continue

                content = resp.text
                for name, regex in SECRET_REGEX.items():
                    matches = re.findall(regex, content, re.I)
                    if matches:
                        for m in set(matches):
                            finding = {"url": url, "type": name, "match": m}

                            # 🔑 Eğer JWT token ise → decode et
                            if name == "json_web_token" or JWT_REGEX.match(m):
                                try:
                                    decoded = jwt.decode(m, options={"verify_signature": False})
                                    juicy = {k: v for k, v in decoded.items() if k in JUICY_FIELDS}
                                    finding["decoded"] = decoded
                                    finding["juicy"] = juicy
                                    if juicy:
                                        Logger.success(f"[+] Juicy JWT in {url}: {juicy}")
                                    else:
                                        Logger.warning(f"[+] JWT in {url} (decoded, no juicy fields)")
                                except Exception as e:
                                    Logger.debug(f"JWT decode failed for {url}: {e}")

                            findings.append(finding)
                            Logger.warning(f"[+] Secret in {url} ({name}): {m[:50]}...")

            except Exception as e:
                Logger.debug(f"Secret scan failed for {url}: {e}")

        with open(out, "w") as f:
            json.dump(findings, f, indent=2)

        if not findings: 
            Logger.success("[+] No secrets detected")
        return out

# ---------------------------
# BackupFinder
# ---------------------------
class BackupFinderCommand(Command):
    def get_stage_name(self): return "BackupFinder - Archive leak scan"
    def execute(self):
        out=f"backup_{self.base}.json"
        findings=[]
        wayback_file=f"wayback_{self.base}.txt"
        urls=[l.strip() for l in open(wayback_file) if l.strip()] if os.path.exists(wayback_file) else []
        exts=[".sql",".db",".sqlite",".sql.gz",".sql.zip",".bak",".backup",".bkp",".old",".save",
              ".yml",".yaml",".config",".conf",".ini",".pem",".key",".crt",".pub",".asc",
              ".secret",".env",".log",".swp",".tar",".tar.gz",".zip",".rar",".7z",".gz",".tgz"]
        for url in urls:
            low=url.lower()
            for ext in exts:
                if low.endswith(ext):
                    snapshot=""
                    try:
                        resp=requests.get(f"https://archive.org/wayback/available?url={url}",timeout=8)
                        if resp.ok:
                            data=resp.json()
                            snap_url=data.get("archived_snapshots",{}).get("closest",{}).get("url","")
                            if snap_url:
                                try:
                                    head=requests.head(snap_url,timeout=8,allow_redirects=True)
                                    if head.status_code==200: snapshot=snap_url
                                except: pass
                    except: pass
                    if snapshot:
                        findings.append({"url":url,"extension":ext,"snapshot":snapshot})
                        Logger.warning(f"[+] Leak: {snapshot} ({ext})")
                    break
        with open(out,"w") as fh: json.dump(findings,fh,indent=2)
        if not findings: Logger.success("[+] No backup/leak files detected")
        return out

# ---------------------------
# JWT Scan
# ---------------------------
class JwtScanCommand(Command):
    def get_stage_name(self): return "JWT Scan - Heuristic token search"
    def execute(self):
        out=f"jwt_{self.base}.json"
        wayback_file=f"wayback_{self.base}.txt"
        tokens,results={},{}
        JWT_REGEX=re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}')
        JUICY_FIELDS=["email","username","password","api_key","access_token","session_id","role","scope"]
        urls=[l.strip() for l in open(wayback_file)] if os.path.exists(wayback_file) else []
        for url in urls:
            decoded_url=requests.utils.unquote(url)
            match=JWT_REGEX.search(decoded_url)
            if match:
                token=match.group(0)
                tokens[url]=token
                Logger.warning(f"[+] JWT candidate in URL: {url}")
        for url,token in tokens.items():
            try:
                decoded=jwt.decode(token,options={"verify_signature":False})
                juicy={k:v for k,v in decoded.items() if k in JUICY_FIELDS}
                results[url]={"jwt":token,"decoded":decoded,"juicy":juicy}
                if juicy: Logger.success(f"[+] Juicy fields in {url}: {juicy}")
            except Exception as e:
                Logger.debug(f"Failed to decode JWT from {url}: {e}")
        with open(out,"w") as f: json.dump(results,f,indent=2)
        if not results: Logger.info("[!] No JWT tokens found.")
        return out

# ---------------------------
# Command Handler
# ---------------------------
class CommandHandler:
    def __init__(self, cmd): 
        self.cmd, self.next = cmd, None
    def set_next(self, nxt): 
        self.next = nxt; return nxt
    def handle(self, domain):
        stage = self.cmd.get_stage_name()
        Logger.debug(f"[pipeline] → Starting stage: {stage} for {domain}")
        try:
            fname = self.cmd.execute()
            Logger.debug(f"[pipeline] ✓ Finished stage: {stage} for {domain}")
            record_stage_output(stage, domain, fname)
        except Exception as e:
            Logger.error(f"[!] {stage} failed: {e}")
            record_stage_output(stage, domain, None)
        if self.next:
            self.next.handle(domain)


# ---------------------------
# Worker
# ---------------------------
def run_pipeline(domain):
    cmds=[SubzyPerHost(domain),FfufCommand(domain),KatanaCommand(domain),WaybackCommand(domain),
          JsHunterCommand(domain),SecretScanCommand(domain),BackupFinderCommand(domain),JwtScanCommand(domain)]
    head=CommandHandler(cmds[0]); cur=head
    for c in cmds[1:]: cur=cur.set_next(CommandHandler(c))
    head.handle(domain)

def worker_loop(q,wid,stop):
    while not stop.is_set():
        try: host=q.get(timeout=1)
        except Empty: continue
        run_pipeline(host); q.task_done()

# ---------------------------
# Main
# ---------------------------
if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser(); p.add_argument("--domain",required=True); p.add_argument("--max-workers",type=int,default=10)
    a=p.parse_args()
    cleanup_before_run()
    domain=a.domain.strip(); ext=tldextract.extract(domain)
    if ext.subdomain:
        alive=HttpxPrecheck.parse_alive(HttpxPrecheck.run_for_single(domain,f"alive_{sanitize_name(domain)}.json"))
        if not alive: sys.exit("[!] Not alive")
        alive_hosts=[alive[0]]
    else:
        subfile=SubfinderCommand(domain).execute()
        alive=HttpxPrecheck.parse_alive(HttpxPrecheck.run_for_file(subfile,f"alive_{sanitize_name(domain)}.json"))
        alive_hosts=alive or [domain]
    Logger.success(f"[+] {len(alive_hosts)} alive hosts")
    q=Queue(); [q.put(h) for h in alive_hosts]
    n=min(len(alive_hosts),a.max_workers)
    register_barriers(n)
    stop=threading.Event(); threads=[]
    for i in range(n):
        t=threading.Thread(target=worker_loop,args=(q,i+1,stop),daemon=True); t.start(); threads.append(t)
    for stage in STAGE_ORDER:
        stage_barriers[stage].wait()
        print_stage_results(stage)
    q.join(); stop.set(); [t.join(1) for t in threads]
    Logger.success("[+] All done.")
