# 🔎 AI-Assisted Web Security Scanner

A modular, pattern-driven **web application security scanner pipeline** built in Python.  
This project integrates well-known reconnaissance & vulnerability discovery tools with **AI assistance** for smarter endpoint filtering and template selection.

> This project is not just a security scanner – it is also an **educational showcase of Software Design Patterns in action**.  
> Each scanning step (subdomain discovery, alive probing, endpoint fuzzing, vulnerability scanning, reporting) is modeled using **classic OOP design patterns** such as **Observer, Command, Decorator, Strategy, Factory Method, and Builder**.  
>  
> 🎯 For security researchers: it provides an automated, AI-assisted pipeline for reconnaissance and vulnerability discovery.  
> 📚 For software engineers: it demonstrates how design patterns can be applied to build a clean, extensible, and maintainable architecture in real-world security tooling.


---

## 🚀 Features

- **Design Patterns Used**
  - Observer → Real-time console, log, and Telegram notifications
  - Command → Encapsulated execution of each tool
  - Decorator → Timing wrapper for performance measurement
  - Strategy → Root vs Subdomain handling
  - Factory Method → Dynamic command creation
  - Builder → Full HTML security report generator

- **Integrated Tools**
  - 🔹 [Subfinder](https://github.com/projectdiscovery/subfinder) – Subdomain enumeration
  - 🔹 [Httpx](https://github.com/projectdiscovery/httpx) – Live host probing
  - 🔹 [Subzy](https://github.com/PentestPad/subzy) – Subdomain takeover detection
  - 🔹 [FFUF](https://github.com/ffuf/ffuf) – Endpoint brute-forcing with baseline filtering
  - 🔹 [Katana](https://github.com/projectdiscovery/katana) – Web crawling
  - 🔹 [WhatWeb](https://github.com/urbanadventurer/whatweb) 
  - 🔹 [Wappalyzer](https://github.com/projectdiscovery/wappalyzer) – Technology detection
  - 🔹 [Waybackurls](https://github.com/tomnomnom/waybackurls) – Passive recon via historical URLs
  - 🔹 [Nuclei](https://github.com/projectdiscovery/nuclei) – Vulnerability scanning with AI-assisted template selection

- **AI-Powered Modules**
  - Extract detected technologies (WhatWeb + Wappalyzer + heuristics)
  - Select relevant **Nuclei templates** for the target tech stack
  - Identify **suspicious endpoints** (e.g. `/admin`, `/login`, `/upload`, `.git`, `.env`, etc.)
  - Focus on **high/critical severity scans**

- **Output**
  - Clean HTML report with:
    - Executive summary
    - Technology stack
    - Vulnerability statistics
    - Subdomain takeover results
    - FFUF & Wayback endpoints
    - Nuclei findings (overview + detailed collapsible cards)

---

---

## 📐 Software Design Patterns

This project is also designed as a **showcase of classic OOP design patterns** applied to a real-world security tool.  
It demonstrates how design patterns improve **modularity, extensibility, and maintainability**.

| Pattern           | Where It’s Used                                                                 | Purpose                                                                 |
|-------------------|----------------------------------------------------------------------------------|-------------------------------------------------------------------------|
| **Observer**      | `ConsoleObserver`, `LogFileObserver`, `TelegramObserver`                        | Notify multiple listeners (console, file, Telegram) when a command finishes. |
| **Command**       | `SubfinderCommand`, `HttpxCommand`, `FfufCommand`, `NucleiCommand`, etc.        | Encapsulate each security tool as a reusable, executable object.        |
| **Decorator**     | `TimingDecorator`                                                               | Add execution time measurement without changing the command logic.      |
| **Strategy**      | `RootDomainStrategy`, `SubdomainStrategy`                                       | Switch between workflows depending on whether the input is a root domain or subdomain. |
| **Factory Method**| `CommandFactory`                                                                | Dynamically create the correct command class from a string identifier.  |
| **Builder**       | `ReportBuilder`                                                                 | Assemble findings, technologies, and outputs into a final HTML report. |

> 📚 This makes the tool both **practical for security assessments** and **educational for software engineers** learning design patterns.


## 📂 Project Structure
```bash
├── scanner.py # Main pipeline
├── report-<domain>.html
├── *.json / *.txt # Intermediate scan outputs
└── pipeline.log # Logs
```

## ⚡ Usage

```bash
python3 scanner.py --domain example.com
```

- Input: Root domain (e.g. example.com) or single subdomain (e.g. app.example.com)
- Output: report-example.com.html

## 📊 Example Report

- Executive summary with severity counts  
- Detected technologies (AI-enriched)  
- Live endpoints from FFUF & Wayback  
- Vulnerability details (with collapsible cards per finding)  

## 🔧 Requirements

- Python 3.10+
- Installed tools:
  - subfinder, httpx, subzy, ffuf, katana, whatweb, wappalyzer, waybackurls, nuclei
- API key for [OpenAI](https://platform.openai.com/)

Install Python deps:

```bash
pip install -r requirements.txt
```

## 📜 License

MIT License – free to use & modify.

## 🙌 Credits

Developed by **Onurcan Genç**  
Offensive Security Specialist | Bilkent CTIS  
