import os
import subprocess
import json
import glob
from abc import ABC, abstractmethod
from openai import OpenAI
from collections import Counter
from urllib.parse import urlparse
import time
import atexit, signal, sys
import tldextract
from collections import defaultdict


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

# ---------------------------
# Observer Pattern
# ---------------------------
class Observer(ABC):
    @abstractmethod
    def update(self, event: str, data: str = ""):
        pass

class ConsoleObserver(Observer):
    def update(self, event, data=""):
        print(f"[Console] {event}: {data[:100]}")

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
    def __init__(self, command: Command):
        super().__init__(command.domain)
        self._command = command
        self.last_duration = None

    def execute(self) -> tuple[str, str]:
        import time
        start = time.time()
        file, output = self._command.execute()
        end = time.time()
        self.last_duration = end - start

        mins, secs = divmod(self.last_duration, 60)
        msg = f"[Timing] {self._command.__class__.__name__} took {int(mins)}m {secs:.2f}s"
        print(msg)
        with open("timing.log", "a") as f:
            f.write(msg + "\n")

        return file, output



# ---------------------------
# Tool Commands
# ---------------------------
class SubfinderCommand(Command):
    def execute(self):
        ext = tldextract.extract(self.domain)
        if ext.subdomain:
            # subdomain verilmiş → direkt yaz
            with open("subdomains.txt", "w") as f:
                f.write(self.domain + "\n")
            self.result_file = "subdomains.txt"
            return "subdomains.txt", self.domain
        else:
            # root domain verilmiş → subfinder çalıştır
            return self._run(
                f"subfinder -d {ext.top_domain_under_public_suffix} -silent",
                "subdomains.txt"
            )

class HttpxCommand(Command):
    def execute(self):
        ext = tldextract.extract(self.domain)
        if ext.subdomain:
            # Subdomain → single target
            cmd = [
                "/root/go/bin/httpx", "-u", f"https://{self.domain}",
                "-nc", "-status-code", "-title", "-tech-detect",
                "-json", "-silent"
            ]
            with open("alive.json", "w") as outfile:
                subprocess.run(cmd, stdout=outfile, stderr=subprocess.DEVNULL, text=True)
        else:
            # Root domain → all subdomains
            with open("subdomains.txt", "r") as infile, open("alive.json", "w") as outfile:
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
        if os.path.exists("alive.json"):
            with open("alive.json") as f:
                for line in f:
                    if not line.strip():
                        continue
                    count += 1
                    try:
                        d = json.loads(line)
                        print("\n🌍 Target Info")
                        print(f"- URL       : {d.get('url')}")
                        print(f"- Title     : {d.get('title')}")
                        print(f"- Host/IP   : {d.get('host')} ({', '.join(d.get('a', []))})")
                        print(f"- Server    : {d.get('webserver')}")
                        print(f"- Status    : {d.get('status_code')}")
                        print(f"- Resp Time : {d.get('time')}")
                        print(f"- Size      : {d.get('content_length')} bytes")
                        print(f"- Words     : {d.get('words')}, Lines: {d.get('lines')}")
                        if d.get("tech"):
                            print("🛠 Technologies:")
                            for t in d["tech"]:
                                print(f"   • {t}")
                    except Exception:
                        continue

        print(f"[+] Httpx finished → {count} hosts written to alive.json")
        self.result_file = "alive.json"
        return "alive.json", ""


class SubzyCommand(Command):
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
            print("🚨 Subzy Findings:")
            for f in findings:
                print(f"   • {f}")
        else:
            print("[+] No subdomain takeover issues found")

        self.result_file = "subzy.txt"
        return "subzy.txt", "\n".join(findings)


class FfufCommand(Command):
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
        print("[*] Baseline scan finished.")

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
        print(f"[*] Baseline scan finished → fw={fw_base}, fs={fs_base}")
        print(f"[*] Applied filter params: {param_str or 'none'}")

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

        for ep in endpoints:
            print(f"[+] Endpoint: {ep}")

        self.result_file = "ffuf.txt"
        return "ffuf.txt", "\n".join(endpoints)
    
class KatanaCommand(Command):
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

class WhatwebCommand(Command):
    def execute(self):
        return self._run(f"whatweb --max-threads=5 --open-timeout=20 --read-timeout=30 https://{self.domain}", "whatweb.txt")

class WappalyzerCommand(Command):
    def execute(self):
        return self._run(
            f"/root/go/bin/wappalyzer --target https://{self.domain} --json",
            "wappalyzer.json"
        )



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
    def execute(self):
        fetcher = WaybackFetcher()
        reporter = WaybackReporter()

        # 1) Retrieve Raw URL
        urls = fetcher.fetch(self.domain)
        print(f"[+] Wayback total URLs: {len(urls)}")

        # 2) Get rid of static files
        subprocess.run(
            "grep -Ev '\\.(jpg|jpeg|png|gif|css|js|ico|svg|pdf|woff|ttf)$' wayback.txt > wayback_urls.txt",
            shell=True
        )

        # 3) Retrieve Domains
        subprocess.run(
            "cat wayback_urls.txt | awk -F/ '{print $3}' | sort -u > wayback_domains.txt",
            shell=True
        )

        # 4) Live check for domains
        subprocess.run(
            "cat wayback_domains.txt | /root/go/bin/httpx -silent -mc 200 | sed 's#/$##' > wayback_alive_domains.txt",
            shell=True
        )

        # 5) Filter paths for live urls
        subprocess.run(
            "grep -Ff <(sed 's#https\\?://##' wayback_alive_domains.txt) wayback_urls.txt > wayback_urls_alive.txt",
            shell=True,
            executable="/bin/bash"
        )

        # 6) Check endpoint level
        subprocess.run(
            "cat wayback_urls_alive.txt | /root/go/bin/httpx -silent -mc 200 -status-code -title -json > wayback_alive_urls.json",
            shell=True
        )

        subprocess.run(
            "jq -r '.url' wayback_alive_urls.json > wayback_alive_urls.txt",
            shell=True
        )

        
        if os.path.exists("wayback_alive_urls.json"):
            os.rename("wayback_alive_urls.json", "wayback_valid.json")

       
        if os.path.exists("wayback_valid.json"):
            html = reporter.to_html("wayback_valid.json")
        else:
            html = "<p>[!] No live wayback URLs found.</p>"

        with open("wayback_valid.html", "w") as f:
            f.write(html)

        self.result_file = "wayback_valid.html"
        return "wayback_valid.html", html


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

    print(f"[*] Nuclei input size: {len(urls)} URLs (ffuf only)")
    return "nuclei_urls.txt"


# ---------------------------
# AI Extract (inline, normalized)
# ---------------------------
class AiExtractCommand(Command):
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

        print(f"[+] AI Extract finished → {len(techs)} technologies")
        self.result_file = "tech_ai.json"
        return "tech_ai.json", json.dumps({"technologies": techs})

# ---------------------------
# AI Select Templates (inline)
# ---------------------------
class AiSelectTemplatesCommand(Command):
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

        print(f"[+] AI Select finished → {len(parsed)} templates")
        self.result_file = "selected_templates.json"
        return "selected_templates.json", json.dumps(parsed)

    
# ---------------------------
# AI Select Endpoints (critical focus)
# ---------------------------
class AiSelectEndpointsCommand(Command):
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

        print(f"[+] AI Endpoints finished → {len(endpoints)} suspicious endpoints")
        self.result_file = "ai_endpoints.txt"
        return "ai_endpoints.txt", "\n".join(endpoints)



# ---------------------------
# Nuclei (Critical, AI endpoints)
# ---------------------------
class NucleiCriticalCommand(Command):
    def execute(self):
        urls_file = "ai_endpoints.txt" if os.path.exists("ai_endpoints.txt") else build_nuclei_input()
        cmd = (
            f"nuclei -l {urls_file} "
            f"-t exposures/ -t cves/ -t misconfiguration/ "
            f"-silent -jsonl -o nuclei_critical.json"
        )
        return self._run(cmd, "nuclei_critical.json")


# ---------------------------
# Nuclei
# ---------------------------
class NucleiAiCommand(Command):
    def execute(self):
        try:
            templates = json.load(open("selected_templates.json"))
        except:
            templates = []
        joined = " ".join([f"-t {t}" for t in templates])

        urls_file = build_nuclei_input()
        cmd = f"nuclei -l {urls_file} {joined} -jsonl -o nuclei_ai.json"
        return self._run(cmd, "nuclei_ai.json")


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
        "nuclei_critical": NucleiCriticalCommand,
        "wayback": WaybackCommand,
    }

    @staticmethod
    def create(name, domain):
        cls = CommandFactory.mapping.get(name)
        if not cls:
            raise ValueError(f"Unknown command: {name}")
        return cls(domain)


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
                content = f.read()
        else:
            content = "[missing]"
        self.sections.append((title, filename, content))

    def build_html(self):
        # ---------------------------
        # Findings Parse
        # ---------------------------
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

        # ---------------------------
        # Severity Stats
        # ---------------------------
        severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = (
                f.get("severity") or
                f.get("info", {}).get("severity", "info")
            ).lower()

            if sev in severity_count:
                severity_count[sev] += 1
            else:
                severity_count["info"] += 1


        # ---------------------------
        # Group by Template (Deduplication)
        # ---------------------------
        
        grouped = defaultdict(list)
        for f in findings:
            sev = (
                f.get("severity") or
                f.get("info", {}).get("severity", "info")
            ).lower()
            template = f.get("template", "unknown")
            name = f.get("info", {}).get("name", "Unknown")
            key = (template, name, sev)
            grouped[key].append(f.get("matched-at", ""))

        # ---------------------------
        # Severity Mapper
        # ---------------------------
        severity_map = {
            "critical": "badge-critical",
            "high": "badge-high",
            "medium": "badge-medium",
            "low": "badge-low",
            "info": "badge-info"
        }

        # ---------------------------
        # Technologies (AI extract)
        # ---------------------------
        techs = []
        try:
            for t in self.sections:
                if t[1] and t[1].endswith("tech_ai.json"):
                    techs = json.loads(t[2]).get("technologies", [])
        except Exception:
            pass

        # ---------------------------
        # HTML Report Build
        # ---------------------------
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

        # Executive Summary
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

        # Technologies
        if techs:
            html += """
<section class="mb-4">
<h2>Detected Technologies (AI)</h2>
<ul>
"""
            for t in techs:
                html += f"<li>{t}</li>"
            html += "</ul></section>"

        # Findings Overview (deduplicated)
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

        # Footer
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
        
        commands = [
            TimingDecorator(HttpxCommand(domain)),
            TimingDecorator(SubzyCommand(domain)),
            TimingDecorator(FfufCommand(domain)),
            TimingDecorator(KatanaCommand(domain)),
            TimingDecorator(WhatwebCommand(domain)),
            TimingDecorator(WappalyzerCommand(domain)),
            TimingDecorator(WaybackCommand(domain)),
            TimingDecorator(AiExtractCommand(domain)),
            TimingDecorator(AiSelectTemplatesCommand(domain)),
            TimingDecorator(NucleiAiCommand(domain)),
            TimingDecorator(AiSelectEndpointsCommand(domain)),
            TimingDecorator(NucleiCriticalCommand(domain)),
        ]

        for cmd in commands:
            try:
                print(f"\n=== {cmd.__class__.__name__} ({domain}) ===")
                file, _ = cmd.execute()
                title = cmd.__class__.__name__
                if isinstance(cmd, TimingDecorator) and cmd.last_duration:
                    m, s = divmod(cmd.last_duration, 60)
                    title = f"{title} (took {int(m)}m {s:.2f}s)"
                builder.add_section(title, file)
                for obs in self.observers:
                    obs.update(f"[+] {cmd.__class__.__name__} done", file)
            except Exception as e:
                for obs in self.observers:
                    obs.update(f"[!] {cmd.__class__.__name__} failed", str(e))

    def run(self):
        from pathlib import Path
        builder = ReportBuilder(self.domain)
        targets = self.strategy.get_targets(self.domain)
        for target in targets:
            self.run_single_pipeline(target, builder)
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

# ---------------------------
# Main
# ---------------------------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", required=True)
    args = parser.parse_args()
    ScannerPipeline(args.domain, [ConsoleObserver(), LogFileObserver()]).run()
