"""
CyberScan — Local Backend Server (Run on Parrot OS)
====================================================
Requirements:
    pip install flask requests dnspython python-whois cryptography beautifulsoup4

Run:
    sudo python3 server.py

The frontend (Project.html) connects to http://127.0.0.1:5000
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import subprocess, json, socket, ssl, re, time
from concurrent.futures import ThreadPoolExecutor

# ── optional imports (graceful fallback) ──
try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import whois as pywhois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    import requests as req_lib
    from bs4 import BeautifulSoup
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

app = Flask(__name__)
CORS(app)                          # allow the HTML page to call us

TIMEOUT_SECS = 30                  # per-tool timeout

# ─────────────────────────────────────────────────────────
#  HELPER: run a shell command, capture stdout + stderr
# ─────────────────────────────────────────────────────────
def run_cmd(cmd: str) -> dict:
    """Execute a shell command and return stdout/stderr/returncode."""
    try:
        result = subprocess.run(
            cmd, shell=True,
            capture_output=True, text=True,
            timeout=TIMEOUT_SECS
        )
        return {
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Command timed out after {}s".format(TIMEOUT_SECS), "returncode": -1}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}


# ─────────────────────────────────────────────────────────
#  SECTION 1 — Pure-Python info extraction (no Parrot tool needed)
#  These give real data without requiring external tools.
# ─────────────────────────────────────────────────────────

def extract_ip(domain: str) -> dict:
    """Resolve domain to IP addresses using socket."""
    try:
        ips = list(set(socket.getaddrinfo(domain, None)))
        addresses = list(set(item[4][0] for item in ips))
        return {"status": "ok", "domain": domain, "ips": addresses}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def extract_dns(domain: str) -> dict:
    """Pull A, AAAA, MX, NS, TXT, CNAME records via dnspython."""
    if not HAS_DNSPYTHON:
        return {"status": "error", "message": "dnspython not installed. Run: pip install dnspython"}

    records = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            records[rtype] = []
        except Exception as e:
            records[rtype] = [f"Error: {e}"]
    return {"status": "ok", "domain": domain, "records": records}


def extract_whois(domain: str) -> dict:
    """Fetch WHOIS data via python-whois."""
    if not HAS_WHOIS:
        return {"status": "error", "message": "python-whois not installed. Run: pip install python-whois"}
    try:
        w = pywhois.whois(domain)
        return {
            "status": "ok",
            "domain": domain,
            "registrar":   str(w.registrar)   if w.registrar   else None,
            "created":     str(w.creation_date) if w.creation_date else None,
            "expires":     str(w.expiration_date) if w.expiration_date else None,
            "updated":     str(w.updated_date) if w.updated_date else None,
            "name_servers": w.name_servers if w.name_servers else []
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def extract_ssl(domain: str) -> dict:
    """Grab SSL certificate details via socket + ssl module."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()

        subject   = dict(x[0] for x in cert.get("subject", []))
        issuer    = dict(x[0] for x in cert.get("issuer", []))
        not_before = cert.get("notBefore", "")
        not_after  = cert.get("notAfter", "")
        san        = [v for (t, v) in cert.get("subjectAltName", [])]

        return {
            "status": "ok",
            "domain": domain,
            "subject":      subject,
            "issuer":       issuer,
            "not_before":   not_before,
            "not_after":    not_after,
            "san":          san,
            "serial":       cert.get("serialNumber", "")
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def extract_headers(domain: str) -> dict:
    """Fetch HTTP response headers via requests."""
    if not HAS_REQUESTS:
        return {"status": "error", "message": "requests not installed. Run: pip install requests"}
    try:
        r = req_lib.get(f"https://{domain}/", timeout=10, allow_redirects=True)
        headers = dict(r.headers)
        # Highlight security-relevant headers
        security_headers = [
            "Strict-Transport-Security", "Content-Security-Policy",
            "X-Frame-Options", "X-Content-Type-Options",
            "X-XSS-Protection", "Referrer-Policy",
            "Permissions-Policy", "Cache-Control", "Server", "X-Powered-By"
        ]
        analysis = {}
        for h in security_headers:
            val = headers.get(h)
            if val:
                flag = "disclosed" if h in ("Server", "X-Powered-By") else "present"
                analysis[h] = {"value": val, "flag": flag}
            else:
                flag = "hidden" if h in ("Server", "X-Powered-By") else "missing"
                analysis[h] = {"value": None, "flag": flag}

        return {"status": "ok", "domain": domain, "all_headers": headers, "security_analysis": analysis}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def extract_tech(domain: str) -> dict:
    """Detect technologies from page HTML + response headers."""
    if not HAS_REQUESTS:
        return {"status": "error", "message": "requests not installed"}
    try:
        r = req_lib.get(f"https://{domain}/", timeout=10, allow_redirects=True)
        html = r.text.lower()
        headers = r.headers

        detected = {}

        # ── CMS ──
        cms_map = {
            "WordPress":  ["wp-content", "wordpress"],
            "Joomla":     ["joomla"],
            "Drupal":     ["drupal"],
            "Shopify":    ["shopify"],
            "Wix":        ["wix.com", "wixsite"],
            "Squarespace":["squarespace"],
            "Ghost":      ["ghost.org", "ghost-blog"]
        }
        for name, markers in cms_map.items():
            if any(m in html for m in markers):
                detected.setdefault("CMS", []).append(name)

        # ── Frameworks / Libraries ──
        fw_map = {
            "React / Next.js": ["__next_data__", "react", "next.js"],
            "Angular":         ["ng-app", "angular"],
            "Vue.js":          ["vue.js", "__vue__"],
            "jQuery":          ["jquery"],
            "Bootstrap":       ["bootstrap"],
            "Tailwind CSS":    ["tailwind"],
            "Laravel":         ["laravel"],
            "Django":          ["django", "csrfmiddlewaretoken"]
        }
        for name, markers in fw_map.items():
            if any(m in html for m in markers):
                detected.setdefault("Framework / Library", []).append(name)

        # ── Analytics ──
        if "google-analytics" in html or "gtag" in html:
            detected.setdefault("Analytics", []).append("Google Analytics")
        if "hotjar" in html:
            detected.setdefault("Analytics", []).append("Hotjar")
        if "facebook.net/analytics" in html:
            detected.setdefault("Analytics", []).append("Facebook Analytics")

        # ── CDN / Cloud ──
        if "cloudflare" in html or "cf-ray" in str(headers).lower():
            detected.setdefault("CDN / Cloud", []).append("Cloudflare")
        if "amazonaws" in html or "cloudfront" in html:
            detected.setdefault("CDN / Cloud", []).append("AWS / CloudFront")
        if "cdn.jsdelivr" in html:
            detected.setdefault("CDN / Cloud", []).append("jsDelivr CDN")

        # ── Server (from headers) ──
        srv = headers.get("Server")
        if srv:
            detected.setdefault("Server", []).append(srv)
        xpb = headers.get("X-Powered-By")
        if xpb:
            detected.setdefault("Backend", []).append(xpb)

        return {"status": "ok", "domain": domain, "technologies": detected}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def detect_sqli_params(domain: str) -> dict:
    """Basic SQL injection parameter detection - checks for common vulnerable URL patterns."""
    if not HAS_REQUESTS:
        return {"status": "error", "message": "requests not installed"}
    
    try:
        # Try to crawl the main page and look for forms/links with common SQL-injectable parameters
        r = req_lib.get(f"https://{domain}/", timeout=10, allow_redirects=True)
        html = r.text
        
        # Common SQL-injectable parameter names
        vuln_params = ['id', 'user', 'username', 'pid', 'category', 'cat', 'action', 'sid', 'dir']
        
        detected_params = []
        detected_forms = []
        
        # Parse HTML for forms and links
        soup = BeautifulSoup(html, 'html.parser')
        
        # Check forms
        forms = soup.find_all('form')
        for form in forms:
            method = form.get('method', 'get').lower()
            action = form.get('action', '')
            inputs = form.find_all('input')
            input_names = [inp.get('name') for inp in inputs if inp.get('name')]
            
            # Check if form has vulnerable parameter names
            vuln_inputs = [name for name in input_names if name.lower() in vuln_params]
            if vuln_inputs:
                detected_forms.append({
                    'action': action or 'current page',
                    'method': method.upper(),
                    'parameters': vuln_inputs
                })
        
        # Check links for URL parameters
        links = soup.find_all('a', href=True)
        for link in links:
            href = link['href']
            if '?' in href:
                # Extract parameters
                try:
                    param_part = href.split('?')[1].split('#')[0]
                    params = param_part.split('&')
                    for param in params:
                        if '=' in param:
                            param_name = param.split('=')[0].lower()
                            if param_name in vuln_params and param_name not in detected_params:
                                detected_params.append(param_name)
                except:
                    pass
        
        # Basic SQL error detection in response
        sql_errors = [
            'sql syntax', 'mysql_fetch', 'mysqli', 'sqlstate', 
            'ora-', 'postgresql', 'sqlite_', 'db2 sql error',
            'syntax error', 'unclosed quotation', 'quoted string'
        ]
        
        response_lower = r.text.lower()
        detected_errors = [err for err in sql_errors if err in response_lower]
        
        findings = {
            'vulnerable_parameters': detected_params,
            'forms_with_params': detected_forms,
            'sql_errors_in_response': detected_errors,
            'risk_level': 'high' if (detected_params or detected_forms or detected_errors) else 'low'
        }
        
        return {
            "status": "ok", 
            "domain": domain, 
            "findings": findings,
            "note": "This is basic parameter detection. Use sqlmap for comprehensive SQL injection testing."
        }
        
    except Exception as e:
        return {"status": "error", "message": str(e)}


def detect_xss_params(domain: str) -> dict:
    """Basic XSS vulnerability detection - checks for reflected input and unsafe contexts."""
    if not HAS_REQUESTS:
        return {"status": "error", "message": "requests not installed"}
    
    try:
        r = req_lib.get(f"https://{domain}/", timeout=10, allow_redirects=True)
        html = r.text
        soup = BeautifulSoup(html, 'html.parser')
        
        findings = {
            'input_fields': 0,
            'text_areas': 0,
            'forms_without_validation': [],
            'inline_javascript': 0,
            'event_handlers': 0,
            'missing_csp': False,
            'risk_level': 'low'
        }
        
        # Count input fields and textareas
        inputs = soup.find_all('input', type=['text', 'search', 'email', 'url'])
        textareas = soup.find_all('textarea')
        findings['input_fields'] = len(inputs)
        findings['text_areas'] = len(textareas)
        
        # Check forms for validation attributes
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', 'current page')
            has_validation = any(
                inp.get('pattern') or inp.get('maxlength') or inp.get('required')
                for inp in form.find_all('input')
            )
            if not has_validation:
                findings['forms_without_validation'].append(action)
        
        # Check for inline JavaScript
        scripts = soup.find_all('script')
        inline_scripts = [s for s in scripts if not s.get('src')]
        findings['inline_javascript'] = len(inline_scripts)
        
        # Check for dangerous event handlers
        dangerous_events = ['onclick', 'onerror', 'onload', 'onmouseover']
        event_count = 0
        for tag in soup.find_all(True):
            for event in dangerous_events:
                if tag.get(event):
                    event_count += 1
        findings['event_handlers'] = event_count
        
        # Check CSP header
        csp = r.headers.get('Content-Security-Policy')
        findings['missing_csp'] = not bool(csp)
        
        # Calculate risk
        risk_score = 0
        if findings['input_fields'] > 5: risk_score += 1
        if findings['forms_without_validation']: risk_score += 2
        if findings['missing_csp']: risk_score += 2
        if findings['event_handlers'] > 3: risk_score += 1
        
        findings['risk_level'] = 'high' if risk_score >= 4 else 'medium' if risk_score >= 2 else 'low'
        
        return {
            "status": "ok",
            "domain": domain,
            "findings": findings,
            "note": "This is basic XSS risk assessment. Use xsser in Parrot section for comprehensive testing."
        }
        
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ─────────────────────────────────────────────────────────
#  SECTION 2 — Parrot OS tool wrappers
#  These shell out to the real installed tools.
# ─────────────────────────────────────────────────────────

def run_nikto(domain: str, flags: str = "") -> dict:
    cmd = f"nikto -h {domain} {flags}"
    result = run_cmd(cmd)
    return {"status": "ok", "tool": "nikto", "command": cmd, "output": result["stdout"], "errors": result["stderr"]}


def run_dnsdict6(domain: str, flags: str = "") -> dict:
    cmd = f"atk6-dnsdict6 {domain} {flags}"
    result = run_cmd(cmd)
    return {"status": "ok", "tool": "dnsdict6", "command": cmd, "output": result["stdout"], "errors": result["stderr"]}


def run_dnsenum(domain: str, flags: str = "") -> dict:
    cmd = f"dnsenum {domain} {flags}"
    result = run_cmd(cmd)
    return {"status": "ok", "tool": "dnsenum", "command": cmd, "output": result["stdout"], "errors": result["stderr"]}


def run_dnsnmap(domain: str, flags: str = "") -> dict:
    cmd = f"dnsnmap {domain} {flags}"
    result = run_cmd(cmd)
    return {"status": "ok", "tool": "dnsnmap", "command": cmd, "output": result["stdout"], "errors": result["stderr"]}


def run_lbd(domain: str, flags: str = "") -> dict:
    cmd = f"lbd {domain} {flags}"
    result = run_cmd(cmd)
    return {"status": "ok", "tool": "lbd", "command": cmd, "output": result["stdout"], "errors": result["stderr"]}


def run_wafw00f(domain: str, flags: str = "") -> dict:
    cmd = f"wafw00f https://{domain} {flags}"
    result = run_cmd(cmd)
    return {"status": "ok", "tool": "wafw00f", "command": cmd, "output": result["stdout"], "errors": result["stderr"]}


def run_sqlmap(domain: str, flags: str = "") -> dict:
    """Run sqlmap for SQL injection testing."""
    cmd = f"sqlmap -u https://{domain} --batch --crawl=1 {flags}"
    result = run_cmd(cmd)
    return {"status": "ok", "tool": "sqlmap", "command": cmd, "output": result["stdout"], "errors": result["stderr"]}


def run_sublist3r(domain: str, flags: str = "") -> dict:
    """Run sublist3r for subdomain enumeration."""
    cmd = f"sublist3r -d {domain} {flags}"
    result = run_cmd(cmd)
    return {"status": "ok", "tool": "sublist3r", "command": cmd, "output": result["stdout"], "errors": result["stderr"]}


def run_dirb(domain: str, flags: str = "") -> dict:
    """Run dirb for directory brute forcing."""
    cmd = f"dirb https://{domain} {flags}"
    result = run_cmd(cmd)
    return {"status": "ok", "tool": "dirb", "command": cmd, "output": result["stdout"], "errors": result["stderr"]}


def run_nmap(domain: str, flags: str = "") -> dict:
    """Run nmap for port scanning."""
    cmd = f"nmap {domain} {flags}"
    result = run_cmd(cmd)
    return {"status": "ok", "tool": "nmap", "command": cmd, "output": result["stdout"], "errors": result["stderr"]}


def run_xsser(domain: str, flags: str = "") -> dict:
    """Run xsser for XSS vulnerability scanning."""
    cmd = f"xsser --url https://{domain} --auto {flags}"
    result = run_cmd(cmd)
    return {"status": "ok", "tool": "xsser", "command": cmd, "output": result["stdout"], "errors": result["stderr"]}


# ─────────────────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────────────────

@app.route("/api/status", methods=["GET"])
def status():
    """Health check — the frontend pings this to know if the backend is alive."""
    return jsonify({"alive": True, "message": "CyberScan backend is running on Parrot OS"})


# ── Info extraction routes (pure Python, no Parrot tool needed) ──

@app.route("/api/ip", methods=["GET"])
def api_ip():
    domain = request.args.get("domain", "").strip()
    if not domain:
        return jsonify({"status": "error", "message": "Missing domain parameter"}), 400
    return jsonify(extract_ip(domain))


@app.route("/api/dns", methods=["GET"])
def api_dns():
    domain = request.args.get("domain", "").strip()
    if not domain:
        return jsonify({"status": "error", "message": "Missing domain parameter"}), 400
    return jsonify(extract_dns(domain))


@app.route("/api/whois", methods=["GET"])
def api_whois():
    domain = request.args.get("domain", "").strip()
    if not domain:
        return jsonify({"status": "error", "message": "Missing domain parameter"}), 400
    return jsonify(extract_whois(domain))


@app.route("/api/ssl", methods=["GET"])
def api_ssl():
    domain = request.args.get("domain", "").strip()
    if not domain:
        return jsonify({"status": "error", "message": "Missing domain parameter"}), 400
    return jsonify(extract_ssl(domain))


@app.route("/api/headers", methods=["GET"])
def api_headers():
    domain = request.args.get("domain", "").strip()
    if not domain:
        return jsonify({"status": "error", "message": "Missing domain parameter"}), 400
    return jsonify(extract_headers(domain))


@app.route("/api/tech", methods=["GET"])
def api_tech():
    domain = request.args.get("domain", "").strip()
    if not domain:
        return jsonify({"status": "error", "message": "Missing domain parameter"}), 400
    return jsonify(extract_tech(domain))


@app.route("/api/sqli", methods=["GET"])
def api_sqli():
    """Basic SQL injection parameter detection endpoint."""
    domain = request.args.get("domain", "").strip()
    if not domain:
        return jsonify({"status": "error", "message": "Missing domain parameter"}), 400
    return jsonify(detect_sqli_params(domain))


@app.route("/api/xss", methods=["GET"])
def api_xss():
    """Basic XSS vulnerability detection endpoint."""
    domain = request.args.get("domain", "").strip()
    if not domain:
        return jsonify({"status": "error", "message": "Missing domain parameter"}), 400
    return jsonify(detect_xss_params(domain))


# ── Parrot tool routes (shell out to real tools) ──

@app.route("/api/parrot/<tool>", methods=["GET"])
def api_parrot(tool):
    """
    Generic endpoint for all Parrot tools.
    ?domain=example.com&flags=-v -a
    """
    domain = request.args.get("domain", "").strip()
    flags  = request.args.get("flags", "").strip()
    if not domain:
        return jsonify({"status": "error", "message": "Missing domain parameter"}), 400

    tool_map = {
        "nikto":     run_nikto,
        "dnsdict6":  run_dnsdict6,
        "dnsenum":   run_dnsenum,
        "dnsnmap":   run_dnsnmap,
        "lbd":       run_lbd,
        "wafw00f":   run_wafw00f,
        "sqlmap":    run_sqlmap,
        "sublist3r": run_sublist3r,
        "dirb":      run_dirb,
        "nmap":      run_nmap,
        "xsser":     run_xsser
    }

    fn = tool_map.get(tool)
    if not fn:
        return jsonify({"status": "error", "message": f"Unknown tool: {tool}"}), 400

    return jsonify(fn(domain, flags))


# ─────────────────────────────────────────────────────────
#  START
# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 58)
    print("  CyberScan Backend — Starting on http://127.0.0.1:5000")
    print("  Keep this window open while using Project.html")
    print("=" * 58)
    app.run(host="127.0.0.1", port=5000, debug=False)
