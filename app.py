
from flask import Flask, render_template, request, jsonify
import platform
import socket
import psutil
import requests
import dns.resolver
import re
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

HTTP_TIMEOUT = 8
USER_AGENT = "SentinelOSINT/1.0 (public-information research)"


def http_session():
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    return session


def normalize_domain(value):
    value = value.strip()
    if "://" in value:
        value = urlparse(value).hostname or ""
    value = value.rstrip(".").lower()

    if not value or len(value) > 253:
        raise ValueError("Enter a valid domain name.")

    if any(not re.fullmatch(r"[a-zA-Z0-9-]{1,63}", label)
           for label in value.split(".")):
        raise ValueError("Invalid domain format.")

    if "." not in value:
        raise ValueError("Enter a fully qualified domain, e.g. example.com.")

    return value


def dns_records(domain, record_type):
    try:
        answers = dns.resolver.resolve(
            domain, record_type, lifetime=5
        )
        return [str(answer) for answer in answers]
    except Exception:
        return []


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/device")
def device_info():
    try:
        hostname = socket.gethostname()
        try:
            local_ip = socket.gethostbyname(hostname)
        except OSError:
            local_ip = "Unavailable"

        boot_time = datetime.fromtimestamp(
            psutil.boot_time(), tz=timezone.utc
        ).isoformat()

        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")

        return jsonify({
            "hostname": hostname,
            "local_ip": local_ip,
            "os": platform.platform(),
            "python": platform.python_version(),
            "cpu_percent": psutil.cpu_percent(interval=0.4),
            "cpu_count": psutil.cpu_count(),
            "memory_percent": memory.percent,
            "memory_total_gb": round(memory.total / (1024 ** 3), 2),
            "memory_used_gb": round(memory.used / (1024 ** 3), 2),
            "disk_percent": disk.percent,
            "disk_total_gb": round(disk.total / (1024 ** 3), 2),
            "boot_time_utc": boot_time,
            "timestamp_utc": datetime.now(timezone.utc).isoformat()
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.post("/api/domain")
def domain_intel():
    data = request.get_json(silent=True) or {}

    try:
        domain = normalize_domain(data.get("domain", ""))
        addresses = dns_records(domain, "A")
        ipv6 = dns_records(domain, "AAAA")
        mx = dns_records(domain, "MX")
        ns = dns_records(domain, "NS")
        txt = dns_records(domain, "TXT")
        cname = dns_records(domain, "CNAME")

        try:
            response = http_session().get(
                "https://" + domain,
                timeout=HTTP_TIMEOUT,
                allow_redirects=True
            )
            website = {
                "reachable": True,
                "status_code": response.status_code,
                "final_url": response.url,
                "server": response.headers.get("Server"),
                "content_type": response.headers.get("Content-Type")
            }
        except requests.RequestException as exc:
            website = {"reachable": False, "error": str(exc)}

        return jsonify({
            "domain": domain,
            "checked_at_utc": datetime.now(timezone.utc).isoformat(),
            "dns": {
                "A": addresses,
                "AAAA": ipv6,
                "MX": mx,
                "NS": ns,
                "TXT": txt,
                "CNAME": cname
            },
            "website": website
        })
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/dns")
def dns_lookup():
    data = request.get_json(silent=True) or {}

    try:
        domain = normalize_domain(data.get("domain", ""))
        records = {
            kind: dns_records(domain, kind)
            for kind in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")
        }
        return jsonify({
            "domain": domain,
            "records": records,
            "checked_at_utc": datetime.now(timezone.utc).isoformat()
        })
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/ip")
def ip_lookup():
    data = request.get_json(silent=True) or {}
    raw_ip = data.get("ip", "").strip()

    try:
        address = ipaddress.ip_address(raw_ip)
    except ValueError:
        return jsonify({"error": "Enter a valid IPv4 or IPv6 address."}), 400

    if not address.is_global:
        return jsonify({
            "ip": str(address),
            "note": "This is not a globally routable public IP address."
        })

    try:
        response = http_session().get(
            f"http://ip-api.com/json/{address}",
            params={
                "fields": "status,message,query,continent,country,"
                          "regionName,city,zip,lat,lon,timezone,isp,org,as"
            },
            timeout=HTTP_TIMEOUT
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") != "success":
            return jsonify({
                "error": result.get("message", "IP lookup failed.")
            }), 502

        return jsonify(result)
    except requests.RequestException:
        return jsonify({
            "error": "The external IP lookup service could not be reached."
        }), 502


@app.post("/api/security")
def website_security():
    data = request.get_json(silent=True) or {}

    try:
        domain = normalize_domain(data.get("domain", ""))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    session = http_session()
    checks = []

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            response = session.get(
                url,
                timeout=HTTP_TIMEOUT,
                allow_redirects=True
            )
            headers = response.headers

            checks.append({
                "url": url,
                "reachable": True,
                "status_code": response.status_code,
                "final_url": response.url,
                "https": response.url.lower().startswith("https://"),
                "headers": {
                    "Strict-Transport-Security":
                        headers.get("Strict-Transport-Security"),
                    "Content-Security-Policy":
                        headers.get("Content-Security-Policy"),
                    "X-Content-Type-Options":
                        headers.get("X-Content-Type-Options"),
                    "X-Frame-Options":
                        headers.get("X-Frame-Options"),
                    "Referrer-Policy":
                        headers.get("Referrer-Policy"),
                    "Permissions-Policy":
                        headers.get("Permissions-Policy")
                }
            })
        except requests.RequestException as exc:
            checks.append({
                "url": url,
                "reachable": False,
                "error": str(exc)
            })

    return jsonify({
        "domain": domain,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "note": "Header checks are informational, not a penetration test."
    })


@app.post("/api/username")
def username_check():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()

    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,50}", username):
        return jsonify({
            "error": "Use 1–50 letters, numbers, dots, underscores or hyphens."
        }), 400

    # Keep the list small and use public profile pages only.
    sites = {
        "GitHub": f"https://github.com/{username}",
        "GitLab": f"https://gitlab.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}/",
        "Hacker News": f"https://news.ycombinator.com/user?id={username}"
    }

    results = []
    session = http_session()

    for site, url in sites.items():
        try:
            response = session.get(
                url,
                timeout=HTTP_TIMEOUT,
                allow_redirects=True
            )

            results.append({
                "site": site,
                "url": url,
                "status_code": response.status_code,
                "reachable": response.status_code < 400,
                "result": (
                    "Profile URL responded; verify manually"
                    if response.status_code < 400
                    else "No successful profile response"
                )
            })
        except requests.RequestException:
            results.append({
                "site": site,
                "url": url,
                "reachable": False,
                "result": "Request failed or was blocked"
            })

    return jsonify({
        "username": username,
        "results": results,
        "note": "HTTP responses do not confirm account ownership or existence."
    })


@app.post("/api/email")
def email_check():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip()

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return jsonify({"error": "Enter a syntactically valid email address."}), 400

    domain = email.rsplit("@", 1)[1].lower()

    return jsonify({
        "email": email,
        "syntax_valid": True,
        "domain": domain,
        "mx_records": dns_records(domain, "MX"),
        "has_mx_records": bool(dns_records(domain, "MX")),
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "note": (
            "This does not verify mailbox existence, ownership, "
            "or whether the address has been breached."
        )
    })


@app.get("/api/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    # Local-only by default; do not expose this development server publicly.
    app.run(host="127.0.0.1", port=5000, debug=False)
