# 🔎 Subhunter

**Subhunter** is a lightweight **subdomain reconnaissance tool** for security researchers and penetration testers.  
It combines **passive OSINT**, **DNS brute force**, **DNS resolution**, and **HTTP(S) probing** into a single workflow.

---

## ✨ Features

- 🛰 **Passive reconnaissance** from multiple sources:
  - crt.sh, BufferOver (Project Sonar), ThreatCrowd, Wayback Machine, HackerTarget
  - Optional API sources: **SecurityTrails** & **VirusTotal**
- 🧾 **DNS brute force** with a built-in or custom wordlist
- 🛡 **Wildcard DNS detection** to minimize false positives
- 🌐 **Resolution** of A / AAAA / CNAME records
- 🌍 **HTTP(S) probing** to detect live services and capture:
  - Status codes
  - Page titles (`<title>`)
- 📂 **Structured output**:
  - TXT (raw subdomains)
  - CSV (detailed host info)
  - JSON (machine-friendly export)
- 🗂 Outputs are written **relative to the script folder**, not your shell directory

---

## 📦 Installation


# Create and activate a virtual environment
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows (PowerShell)
.venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt

# Requirements:

Python 3.9+, aiohttp, dnspython, tldextract

# 🚀 Usage

python subhunter.py -d example.com -o out --passive --bruteforce --probe

🔧 Options

        Option	Description

        -d, --domain	Target domain (e.g., example.com) [required]

        -o, --outdir	Output directory (relative to script folder). Default: out

        --passive	Use passive OSINT sources

        --bruteforce	Use DNS brute-force

        --wordlist PATH	  Path to a custom wordlist (built-in if omitted)

        --nameservers NS1,NS2	Comma-separated DNS servers (e.g., 1.1.1.1,8.8.8.8)

        --dns-concurrency INT	DNS concurrency (default: 100)

        --probe	Probe HTTP/HTTPS services

        --http-concurrency INT	HTTP concurrency (default: 50)

        --keep-unresolved	Keep unresolved hosts in outputs

        --virustotal KEY	VirusTotal API key (or via env var VIRUSTOTAL_API_KEY)

        --securitytrails KEY	SecurityTrails API key (or via env var SECURITYTRAILS_API_KEY)

# 🔑 API Keys
Some data sources require API keys:

        Linux/macOS
        export VIRUSTOTAL_API_KEY="your_vt_key"
        export SECURITYTRAILS_API_KEY="your_st_key"

       Windows (PowerShell)
        $env:VIRUSTOTAL_API_KEY="your_vt_key"
        $env:SECURITYTRAILS_API_KEY="your_st_key"
        
Or pass them directly via CLI flags.

    python subhunter.py -d example.com --passive \
    --virustotal YOUR_VT_API_KEY \
    --securitytrails YOUR_ST_API_KEY

# 🧪 Examples
Passive only

    python subhunter.py -d example.com --passive
Brute-force with custom resolvers


    python subhunter.py -d example.com --bruteforce --nameservers 1.1.1.1,8.8.8.8
Full scan (passive + brute + probing)

    python subhunter.py -d example.com -o results --passive --bruteforce --probe


# 📂 Output Files
Output directory:

         <script_folder>/<outdir>

Raw subdomains

    example.com-subdomains-raw-YYYYMMDD-HHMMSS.txt

Detailed CSV report

    example.com-hosts-YYYYMMDD-HHMMSS.csv

Columns:
    
    hostname, ips, cname, http_status, https_status, http_title, https_title, http_url, https_url

Structured JSON

    example.com-hosts-YYYYMMDD-HHMMSS.json

# 💡 Tips
- Built-in wordlist is small & fast; supply your own (--wordlist) for deeper coverage.

- Use --keep-unresolved if you also want hosts that didn’t resolve.

- If DNS queries fail in corporate environments, set resolvers manually (--nameservers).

- Run passive first, then brute force, to balance speed and coverage.

# ⚖️ Legal Disclaimer
This project is licensed under the MIT License – see the LICENSE
 file for details.
You are free to use, modify, and distribute this software in accordance with the license terms.

⚠️ Important Notice

Subhunter is a security research tool. It is intended only for authorized security testing and educational purposes.
You must ensure that you have explicit permission from the target organization before running scans.

    ✅ Ethical use includes penetration tests, bug bounty programs, red team assessments, and lab research on your own assets.

    ❌ Unauthorized scanning, reconnaissance, or exploitation of systems you do not own or control may be illegal and can result in civil and criminal liability.

By using this software, you acknowledge that:

- You are solely responsible for your actions.

- The authors and contributors of Subhunter assume no liability for misuse, damage, or legal consequences arising from its use.

Use responsibly. Act ethically. Always obtain proper authorization.
