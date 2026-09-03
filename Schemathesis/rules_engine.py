#!/usr/bin/env python3
"""
rules_engine.py
Quan ly rules dung chung cho tool cua Nguoi 1 (Schemathesis).

- OWASP API Security Top 10: KHONG co API chinh thuc de "tu cap nhat" -
  OWASP chi ra ban moi vai nam 1 lan. Nen luu tinh trong rules.json,
  sua tay khi co ban moi (hien dang la ban 2023). Muc dich cua file nay
  la giup cac category do de bao tri va gan vao tung finding, KHONG phai
  "cao" du lieu OWASP tu dong.

- CVE: co API chinh thuc (NVD - services.nvd.nist.gov), CAP NHAT DUOC
  theo ngay. Module nay goi NVD CVE API 2.0, loc theo tu khoa lien quan
  toi API security (SQLi, JWT, GraphQL, SSRF, framework REST pho bien),
  luu ket qua vao rules.json["cve_signals"] kem CVSS score de tinh
  severity, co cache + TTL de khong spam API (NVD rate-limit ~5
  req/30s khong co API key, 50 req/30s co key).

Cach dung:
    python3 rules_engine.py --update                 # cap nhat CVE 30 ngay gan nhat
    python3 rules_engine.py --update --days 90 --api-key <NVD_KEY>
    (roi run_schemathesis.py --rules rules.json se tu doc file nay)
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Tu khoa lien quan toi de tai (API REST, cac cong nghe dung trong
# crAPI/DVGA/VAmPI: Flask, Express, GraphQL, JWT...) - chinh lai neu
# target stack cua nhom khac.
DEFAULT_KEYWORDS = [
    "REST API injection",
    "JWT authentication bypass",
    "GraphQL injection",
    "SQL injection API",
    "SSRF",
    "mass assignment",
    "broken object level authorization",
]

RATE_LIMIT_SLEEP_S = 6  # khong co API key -> ~5 req/30s, de an toan choi 6s/req


def _severity_from_cvss(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def fetch_cves_for_keyword(keyword: str, days_back: int, api_key: Optional[str]) -> list[dict]:
    """Goi NVD CVE API 2.0, tra ve list CVE ngan gon (id, desc, cvss, severity)."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days_back)
    params = {
        "keywordSearch": keyword,
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 50,
    }
    headers = {"apiKey": api_key} if api_key else {}

    try:
        resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=20)
        resp.raise_for_status()
    except requests.RequestException as exc:
        print(f"[CANH BAO] Khong goi duoc NVD API cho keyword '{keyword}': {exc}",
              file=sys.stderr)
        return []

    data = resp.json()
    out = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        descs = cve.get("descriptions", [])
        desc_en = next((d["value"] for d in descs if d.get("lang") == "en"), "")

        metrics = cve.get("metrics", {})
        score = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                score = metrics[key][0]["cvssData"].get("baseScore")
                break

        out.append({
            "cve_id": cve_id,
            "keyword": keyword,
            "description": desc_en[:300],
            "cvss_score": score,
            "severity": _severity_from_cvss(score),
            "published": cve.get("published"),
        })
    return out


def update_from_nvd(rules: dict, keywords: list[str], days_back: int,
                     api_key: Optional[str] = None) -> dict:
    all_cves = []
    for kw in keywords:
        print(f"[INFO] Truy van NVD: '{kw}' ({days_back} ngay gan nhat)...")
        all_cves.extend(fetch_cves_for_keyword(kw, days_back, api_key))
        if not api_key:
            time.sleep(RATE_LIMIT_SLEEP_S)

    # dedup theo cve_id, giu ban co cvss cao nhat neu trung
    by_id: dict[str, dict] = {}
    for c in all_cves:
        cid = c["cve_id"]
        if cid is None:
            continue
        if cid not in by_id or (c["cvss_score"] or 0) > (by_id[cid]["cvss_score"] or 0):
            by_id[cid] = c

    rules["cve_signals"] = sorted(by_id.values(),
                                   key=lambda c: c["cvss_score"] or 0, reverse=True)
    rules["meta"]["cve_last_updated"] = datetime.now(timezone.utc).isoformat()
    print(f"[XONG] Cap nhat {len(rules['cve_signals'])} CVE lien quan.")
    return rules


def load_rules(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        print(f"[LOI] Khong tim thay {path}. Chay --update lan dau de tao, "
              f"hoac dung file rules.json mau di kem.", file=sys.stderr)
        sys.exit(1)
    return json.loads(p.read_text(encoding="utf-8"))


def save_rules(rules: dict, path: str) -> None:
    Path(path).write_text(json.dumps(rules, indent=2, ensure_ascii=False), encoding="utf-8")


def get_all_signals(rules: dict) -> list[str]:
    """Tra ve toan bo signal (static + CVE description keyword rut gon) dung
    de so khop trong response body khi Nguoi 1 danh gia ket qua fuzzing."""
    signals = list(rules.get("static_error_signals", []))
    for cat in rules.get("owasp_categories", {}).values():
        signals.extend(cat.get("signals", []))
    # CVE description thuong dai, chi lay cac tu khoa ky thuat ngan gon
    # da duoc cau hinh san trong static_error_signals; CVE dung chinh de
    # NANG SEVERITY khi trung endpoint/tech, khong dung de match text.
    return sorted(set(s.lower() for s in signals))


STOPWORDS = {"api", "the", "and", "for", "with", "via", "attackers", "allows"}

# attack_type (dung trong payload cua B) khong cung tu vung voi mo ta CVE
# tieng Anh tu nhien -> can bang dong nghia de match co y nghia.
ATTACK_TYPE_SYNONYMS = {
    "sqli": ["sql", "sql injection", "injection"],
    "xss": ["cross-site scripting", "script injection", "xss"],
    "ssrf": ["server-side request forgery", "ssrf"],
    "bola": ["object level authorization", "idor", "authorization bypass"],
    "bfla": ["function level authorization", "authorization bypass", "privilege"],
    "massassignment": ["mass assignment", "property level authorization"],
    "jwt": ["jwt", "json web token", "authentication bypass"],
    "xxe": ["xml external entity", "xxe"],
    "deserialization": ["deserialization", "insecure deserialization"],
}


def match_cves_by_keyword(rules: dict, attack_type: str, owasp_category: Optional[str] = None
                           ) -> list[dict]:
    """Tim CVE trong cache lien quan toi loai tan cong dang test, dung bang
    dong nghia thay vi so khop chu-doi-chu (attack_type/owasp code thuong
    khong cung tu vung voi mo ta CVE tu nhien)."""
    key = attack_type.lower().replace(" ", "").replace("_", "")
    phrases = list(ATTACK_TYPE_SYNONYMS.get(key, [attack_type.lower()]))

    if owasp_category and rules.get("owasp_categories", {}).get(owasp_category):
        name = rules["owasp_categories"][owasp_category]["name"].lower()
        phrases.extend(w for w in name.replace("(", "").replace(")", "").split()
                        if len(w) >= 4 and w not in STOPWORDS)

    matched = []
    for cve in rules.get("cve_signals", []):
        desc_l = cve["description"].lower()
        if any(p in desc_l for p in phrases):
            matched.append(cve)
    return matched[:3]


def main():
    ap = argparse.ArgumentParser(description="Cap nhat rules (CVE tu NVD) cho tool cua Nguoi 1")
    ap.add_argument("--rules", default="rules.json")
    ap.add_argument("--update", action="store_true", help="Goi NVD API cap nhat CVE")
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--api-key", default=None, help="NVD API key (khuyen khich - tang rate limit)")
    ap.add_argument("--keywords", nargs="*", default=None, help="Ghi de tu khoa mac dinh")
    args = ap.parse_args()

    rules_path = Path(args.rules)
    if not rules_path.exists():
        print(f"[LOI] {args.rules} chua ton tai. Tao file rules.json mau truoc "
              f"(xem file rules.json dinh kem).", file=sys.stderr)
        sys.exit(1)

    rules = load_rules(args.rules)

    if args.update:
        keywords = args.keywords or DEFAULT_KEYWORDS
        rules = update_from_nvd(rules, keywords, args.days, args.api_key)
        save_rules(rules, args.rules)
    else:
        print(f"[INFO] Rules hien tai: {len(get_all_signals(rules))} signal, "
              f"{len(rules.get('cve_signals', []))} CVE cache "
              f"(cap nhat luc: {rules['meta'].get('cve_last_updated')}).")


if __name__ == "__main__":
    main()
