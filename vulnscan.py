#!/usr/bin/env python3
"""
VulnScan — Web Vulnerability Scanner
Проверяет: SQLi, XSS, IDOR, открытые редиректы, слабые заголовки, раскрытие информации
"""

import asyncio
import aiohttp
import sys
import re
import json
import time
from urllib.parse import urlparse, urlencode, urljoin, parse_qs, urlunparse
from dataclasses import dataclass, field
from typing import Optional
import argparse

# ─── ANSI Colors ────────────────────────────────────────────────────────────────
R = "\033[91m"   # red
G = "\033[92m"   # green
Y = "\033[93m"   # yellow
B = "\033[94m"   # blue/cyan
M = "\033[95m"   # magenta
C = "\033[96m"   # cyan
W = "\033[97m"   # white
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

BANNER = f"""
{C}╔══════════════════════════════════════════════════════╗
║  {BOLD}{W}VulnScan{RESET}{C}  —  Web Vulnerability Scanner  v1.0         ║
║  {DIM}SQLi · XSS · IDOR · OpenRedirect · Headers · InfoLeak{RESET}{C}  ║
╚══════════════════════════════════════════════════════╝{RESET}
"""


# ─── Data models ────────────────────────────────────────────────────────────────
@dataclass
class Finding:
    severity: str      # CRITICAL / HIGH / MEDIUM / LOW / INFO
    vuln_type: str
    url: str
    detail: str
    payload: Optional[str] = None
    evidence: Optional[str] = None


@dataclass
class ScanResult:
    target: str
    start_time: float = field(default_factory=time.time)
    findings: list = field(default_factory=list)
    requests_made: int = 0
    elapsed: float = 0.0


# ─── Payload banks ──────────────────────────────────────────────────────────────
SQLI_PAYLOADS = [
    ("'", ["sql syntax", "mysql", "sqlite", "postgresql", "ora-", "syntax error",
           "unclosed quotation", "quoted string not properly terminated"]),
    ("1 OR 1=1--", ["you have an error", "warning: mysql", "unclosed quotation"]),
    ("' OR '1'='1", ["you have an error", "warning: mysql"]),
    ("1; SELECT 1--", ["you have an error", "syntax error"]),
    ("' UNION SELECT NULL--", ["you have an error", "null", "union"]),
    ("1 AND SLEEP(2)--", None),   # time-based: handled separately
    ("\\", ["you have an error", "unexpected character"]),
]

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    '"><body onload=alert(1)>',
]

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https:evil.com",
]

INFO_PATHS = [
    "/.git/HEAD",
    "/.env",
    "/config.php",
    "/wp-config.php",
    "/phpinfo.php",
    "/.htaccess",
    "/web.config",
    "/server-status",
    "/robots.txt",
    "/sitemap.xml",
    "/.DS_Store",
    "/admin",
    "/admin/",
    "/login",
    "/api/",
    "/api/v1/",
    "/swagger.json",
    "/openapi.json",
    "/backup.zip",
    "/backup.sql",
    "/dump.sql",
    "/debug",
    "/actuator",
    "/actuator/env",
    "/console",
]

SECURE_HEADERS = {
    "Strict-Transport-Security": ("HSTS missing — MITM risk", "HIGH"),
    "Content-Security-Policy": ("CSP missing — XSS harder to mitigate", "MEDIUM"),
    "X-Frame-Options": ("Clickjacking possible", "MEDIUM"),
    "X-Content-Type-Options": ("MIME sniffing risk", "LOW"),
    "Referrer-Policy": ("Referrer leakage possible", "LOW"),
    "Permissions-Policy": ("No Permissions-Policy header", "LOW"),
}

IDOR_PARAMS = ["id", "user_id", "uid", "account", "account_id",
               "file", "path", "doc", "document", "item", "record"]


# ─── Severity colorizer ──────────────────────────────────────────────────────────
def sev_color(s: str) -> str:
    return {
        "CRITICAL": f"{R}{BOLD}CRITICAL{RESET}",
        "HIGH":     f"{R}HIGH{RESET}",
        "MEDIUM":   f"{Y}MEDIUM{RESET}",
        "LOW":      f"{B}LOW{RESET}",
        "INFO":     f"{DIM}INFO{RESET}",
    }.get(s, s)


def log(msg: str, prefix: str = ""):
    print(f"{DIM}[{RESET}{prefix}{DIM}]{RESET} {msg}")


# ─── Scanner class ───────────────────────────────────────────────────────────────
class VulnScanner:
    def __init__(self, target: str, timeout: int = 8, concurrency: int = 10,
                 aggressive: bool = False):
        self.target = target.rstrip("/")
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.sem = asyncio.Semaphore(concurrency)
        self.aggressive = aggressive
        self.result = ScanResult(target=target)
        self.base_params: dict[str, list[str]] = {}
        self.session: Optional[aiohttp.ClientSession] = None
        self._headers = {
            "User-Agent": "Mozilla/5.0 (VulnScan/1.0; Security Research)",
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.9",
        }

    def _add(self, finding: Finding):
        self.result.findings.append(finding)
        icon = {"CRITICAL": "💀", "HIGH": "🔴", "MEDIUM": "🟡",
                "LOW": "🔵", "INFO": "⚪"}.get(finding.severity, "•")
        print(f"  {icon} [{sev_color(finding.severity)}] {C}{finding.vuln_type}{RESET}  "
              f"{DIM}{finding.url}{RESET}")
        if finding.detail:
            print(f"     {DIM}↳ {finding.detail}{RESET}")
        if finding.payload:
            print(f"     {Y}Payload:{RESET} {finding.payload}")
        if finding.evidence:
            print(f"     {M}Evidence:{RESET} {finding.evidence[:120]}")

    async def _get(self, url: str, **kwargs):
        """Safe async GET with semaphore + counter."""
        async with self.sem:
            try:
                self.result.requests_made += 1
                async with self.session.get(url, timeout=self.timeout,
                                            allow_redirects=False, **kwargs) as r:
                    text = await r.text(errors="replace")
                    return r.status, dict(r.headers), text
            except Exception:
                return None, {}, ""

    # ── 1. Базовая разведка ──────────────────────────────────────────────────────
    async def recon(self):
        print(f"\n{W}{BOLD}[1/7] Разведка{RESET}")
        status, headers, body = await self._get(self.target)
        if status is None:
            print(f"  {R}Цель недоступна!{RESET}")
            return

        server = headers.get("Server", "—")
        powered = headers.get("X-Powered-By", "—")
        print(f"  {G}✓{RESET} Статус: {status}  Server: {server}  X-Powered-By: {powered}")

        if server != "—":
            self._add(Finding("INFO", "Server Banner", self.target,
                               f"Раскрыт тип сервера: {server}"))
        if powered != "—":
            self._add(Finding("LOW", "Technology Disclosure", self.target,
                               f"X-Powered-By: {powered}"))

        # Извлекаем параметры из форм
        for match in re.finditer(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=([^&"\'\s]*)', body):
            k, v = match.group(1), match.group(2)
            self.base_params.setdefault(k, [])
            if v not in self.base_params[k]:
                self.base_params[k].append(v)

        print(f"  {G}✓{RESET} Найдено параметров: {len(self.base_params)} → "
              f"{', '.join(list(self.base_params)[:8])}")

    # ── 2. Заголовки безопасности ────────────────────────────────────────────────
    async def check_headers(self):
        print(f"\n{W}{BOLD}[2/7] Заголовки безопасности{RESET}")
        _, headers, _ = await self._get(self.target)
        hdrs_lower = {k.lower(): v for k, v in headers.items()}

        for header, (msg, sev) in SECURE_HEADERS.items():
            if header.lower() not in hdrs_lower:
                self._add(Finding(sev, "Missing Security Header", self.target,
                                   f"{header}: {msg}"))
            else:
                print(f"  {G}✓{RESET} {header}: OK")

        # Cookie без Secure / HttpOnly
        cookie = hdrs_lower.get("set-cookie", "")
        if cookie:
            if "secure" not in cookie.lower():
                self._add(Finding("MEDIUM", "Insecure Cookie", self.target,
                                   "Set-Cookie без флага Secure", evidence=cookie[:80]))
            if "httponly" not in cookie.lower():
                self._add(Finding("MEDIUM", "Cookie HttpOnly Missing", self.target,
                                   "Set-Cookie без флага HttpOnly", evidence=cookie[:80]))

    # ── 3. Информационное раскрытие ──────────────────────────────────────────────
    async def check_info_disclosure(self):
        print(f"\n{W}{BOLD}[3/7] Раскрытие информации{RESET}")
        tasks = [self._probe_path(p) for p in INFO_PATHS]
        await asyncio.gather(*tasks)

    async def _probe_path(self, path: str):
        url = self.target + path
        status, _, body = await self._get(url)
        if status in (200, 301, 302, 403):
            sev = "HIGH" if any(x in path for x in [".env", ".git", "config", "backup",
                                                      ".sql", "phpinfo", "actuator"]) \
                  else "MEDIUM" if status == 200 else "LOW"
            hint = ""
            if ".git" in path and "ref:" in body:
                hint = "Git репозиторий открыт!"
                sev = "CRITICAL"
            elif ".env" in path and ("=" in body or "KEY" in body):
                hint = "Файл .env доступен!"
                sev = "CRITICAL"
            elif "phpinfo" in path and "PHP Version" in body:
                hint = "phpinfo() открыт!"
                sev = "HIGH"
            self._add(Finding(sev, "Information Disclosure", url,
                               f"HTTP {status} на чувствительном пути" +
                               (f" — {hint}" if hint else ""), evidence=body[:100]))

    # ── 4. SQL-инъекции ──────────────────────────────────────────────────────────
    async def check_sqli(self):
        print(f"\n{W}{BOLD}[4/7] SQL-инъекции{RESET}")
        if not self.base_params:
            print(f"  {DIM}Параметры не найдены, пробуем common params...{RESET}")
            test_params = {"id": ["1"], "q": ["test"], "search": ["test"]}
        else:
            test_params = self.base_params

        tasks = []
        for param, values in test_params.items():
            base_val = values[0] if values else "1"
            for payload, error_sigs in SQLI_PAYLOADS[:-1]:  # пропускаем sleep
                url = self._inject_param(self.target, param, base_val + payload)
                tasks.append(self._test_sqli(url, param, payload, error_sigs))

        if self.aggressive:
            # Time-based blind
            for param, values in test_params.items():
                base_val = values[0] if values else "1"
                tasks.append(self._test_sqli_time(param, base_val))

        await asyncio.gather(*tasks)

    def _inject_param(self, base: str, param: str, value: str) -> str:
        if "?" not in base:
            return f"{base}?{param}={value}"
        parsed = urlparse(base)
        params = parse_qs(parsed.query)
        params[param] = [value]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return urlunparse(parsed._replace(query=new_query))

    async def _test_sqli(self, url: str, param: str, payload: str, error_sigs):
        status, _, body = await self._get(url)
        if not body:
            return
        body_lower = body.lower()
        for sig in error_sigs:
            if sig in body_lower:
                self._add(Finding("HIGH", "SQL Injection (Error-Based)", url,
                                   f"Параметр '{param}' отражает SQL-ошибку",
                                   payload=payload, evidence=sig))
                return

    async def _test_sqli_time(self, param: str, base_val: str):
        payload = "1 AND SLEEP(3)--"
        url = self._inject_param(self.target, param, base_val + payload)
        t0 = time.monotonic()
        await self._get(url)
        elapsed = time.monotonic() - t0
        if elapsed >= 3:
            self._add(Finding("HIGH", "SQL Injection (Time-Based Blind)", url,
                               f"Параметр '{param}': задержка ответа {elapsed:.1f}s",
                               payload=payload))

    # ── 5. XSS ───────────────────────────────────────────────────────────────────
    async def check_xss(self):
        print(f"\n{W}{BOLD}[5/7] Cross-Site Scripting (XSS){RESET}")
        if not self.base_params:
            test_params = {"q": ["test"], "search": ["test"], "query": ["test"]}
        else:
            test_params = self.base_params

        tasks = []
        for param, values in test_params.items():
            for payload in XSS_PAYLOADS[:4]:
                url = self._inject_param(self.target, param, payload)
                tasks.append(self._test_xss(url, param, payload))

        await asyncio.gather(*tasks)

    async def _test_xss(self, url: str, param: str, payload: str):
        status, headers, body = await self._get(url)
        if not body:
            return
        if payload in body or payload.lower() in body.lower():
            csp = headers.get("Content-Security-Policy", "")
            sev = "MEDIUM" if csp else "HIGH"
            self._add(Finding(sev, "Reflected XSS", url,
                               f"Параметр '{param}' отражает payload без экранирования",
                               payload=payload))

    # ── 6. Open Redirect ─────────────────────────────────────────────────────────
    async def check_open_redirect(self):
        print(f"\n{W}{BOLD}[6/7] Open Redirect{RESET}")
        redirect_params = ["redirect", "url", "next", "return", "returnUrl",
                           "returnTo", "continue", "goto", "destination", "redir",
                           "r", "target", "link", "forward"]
        tasks = []
        for param in redirect_params:
            for payload in REDIRECT_PAYLOADS:
                url = self._inject_param(self.target, param, payload)
                tasks.append(self._test_redirect(url, param, payload))
        await asyncio.gather(*tasks)

    async def _test_redirect(self, url: str, param: str, payload: str):
        status, headers, _ = await self._get(url)
        if status in (301, 302, 303, 307, 308):
            loc = headers.get("Location", "")
            if "evil.com" in loc or loc.startswith("//"):
                self._add(Finding("HIGH", "Open Redirect", url,
                                   f"Параметр '{param}' редиректит на внешний домен",
                                   payload=payload, evidence=f"Location: {loc}"))

    # ── 7. IDOR (базовый) ────────────────────────────────────────────────────────
    async def check_idor(self):
        print(f"\n{W}{BOLD}[7/7] IDOR (Insecure Direct Object Reference){RESET}")
        all_params = set(self.base_params.keys()) | set(IDOR_PARAMS)
        idor_params = [p for p in all_params if p in IDOR_PARAMS]

        if not idor_params:
            print(f"  {DIM}IDOR-параметры не обнаружены в URL{RESET}")
            return

        tasks = []
        for param in idor_params:
            for id_val in ["0", "2", "99999", "../etc/passwd", "%00"]:
                url = self._inject_param(self.target, param, id_val)
                tasks.append(self._test_idor(url, param, id_val))
        await asyncio.gather(*tasks)

    async def _test_idor(self, url: str, param: str, val: str):
        status, _, body = await self._get(url)
        if status == 200 and body:
            if any(sig in body.lower() for sig in ["root:", "/bin/", "password",
                                                    "email", "username"]):
                self._add(Finding("CRITICAL", "IDOR / Path Traversal", url,
                                   f"Параметр '{param}'={val!r} возвращает чужие данные!",
                                   payload=val, evidence=body[:150]))
            elif status == 200 and val == "0":
                self._add(Finding("LOW", "Possible IDOR", url,
                                   f"Параметр '{param}'=0 возвращает данные (проверьте вручную)"))

    # ── Main run ─────────────────────────────────────────────────────────────────
    async def run(self):
        connector = aiohttp.TCPConnector(ssl=False, limit=20)
        async with aiohttp.ClientSession(
            connector=connector, headers=self._headers
        ) as session:
            self.session = session
            await self.recon()
            await self.check_headers()
            await self.check_info_disclosure()
            await self.check_sqli()
            await self.check_xss()
            await self.check_open_redirect()
            await self.check_idor()

        self.result.elapsed = time.monotonic() - self.result.start_time

    # ── Report ───────────────────────────────────────────────────────────────────
    def print_report(self):
        r = self.result
        findings = r.findings
        by_sev = {}
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            cnt = sum(1 for f in findings if f.severity == sev)
            if cnt:
                by_sev[sev] = cnt

        print(f"\n{C}{'═'*54}{RESET}")
        print(f"{BOLD}{W}  ИТОГОВЫЙ ОТЧЁТ{RESET}  {DIM}{r.target}{RESET}")
        print(f"{C}{'═'*54}{RESET}")
        print(f"  Время сканирования : {r.elapsed:.1f}s")
        print(f"  Запросов отправлено: {r.requests_made}")
        print(f"  Уязвимостей найдено: {BOLD}{len(findings)}{RESET}")
        print()

        for sev, cnt in by_sev.items():
            print(f"  {sev_color(sev):>30}  ×{cnt}")

        print(f"\n{C}{'─'*54}{RESET}")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            for f in findings:
                if f.severity == sev:
                    print(f"  [{sev_color(sev)}] {C}{f.vuln_type}{RESET}")
                    print(f"    URL    : {f.url}")
                    print(f"    Детали : {f.detail}")
                    if f.payload:
                        print(f"    Payload: {Y}{f.payload}{RESET}")
                    print()

    def save_json(self, path: str):
        data = {
            "target": self.result.target,
            "elapsed": round(self.result.elapsed, 2),
            "requests": self.result.requests_made,
            "findings": [
                {
                    "severity": f.severity,
                    "type": f.vuln_type,
                    "url": f.url,
                    "detail": f.detail,
                    "payload": f.payload,
                    "evidence": f.evidence,
                }
                for f in self.result.findings
            ],
        }
        with open(path, "w", encoding="utf-8") as fp:
            json.dump(data, fp, ensure_ascii=False, indent=2)
        print(f"  {G}✓{RESET} JSON-отчёт сохранён: {path}")


# ─── Entry point ─────────────────────────────────────────────────────────────────
def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="VulnScan — Web Vulnerability Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("target", help="Целевой URL (например: http://testphp.vulnweb.com)")
    parser.add_argument("-t", "--timeout", type=int, default=8, metavar="SEC",
                        help="Таймаут запроса (по умолчанию 8)")
    parser.add_argument("-c", "--concurrency", type=int, default=10, metavar="N",
                        help="Параллельных запросов (по умолчанию 10)")
    parser.add_argument("--aggressive", action="store_true",
                        help="Включить time-based SQLi (медленнее)")
    parser.add_argument("--json", metavar="FILE",
                        help="Сохранить отчёт в JSON")
    args = parser.parse_args()

    if not args.target.startswith(("http://", "https://")):
        args.target = "http://" + args.target

    scanner = VulnScanner(
        args.target,
        timeout=args.timeout,
        concurrency=args.concurrency,
        aggressive=args.aggressive,
    )

    print(f"{DIM}Цель:{RESET} {W}{args.target}{RESET}")
    print(f"{DIM}Модули:{RESET} Recon · Headers · InfoDisclose · SQLi · XSS · Redirect · IDOR")
    if args.aggressive:
        print(f"{Y}⚡ Aggressive mode включён (time-based SQLi){RESET}")
    print()

    asyncio.run(scanner.run())
    scanner.print_report()

    if args.json:
        scanner.save_json(args.json)


if __name__ == "__main__":
    main()
