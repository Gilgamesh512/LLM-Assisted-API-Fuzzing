#!/usr/bin/env python3
"""
run_schemathesis.py
Vai trò: Nguoi 1 - tich hop Schemathesis vao pipeline LLM-fuzzing API REST.

Luong xu ly:
  1) Nhan OpenAPI spec (tu Thanh vien A)          -> --spec
  2) Nhan payload JSON do LLM sinh (tu Thanh vien B) -> --payloads
  3) Gan payload vao dung tham so cua dung endpoint, ban request that
     bang Schemathesis (Case.call), khong dung random cua Hypothesis
     vi minh can test CHINH XAC payload ma B sinh ra.
  4) Ghi log ra results/vulnerabilities.csv va results/experiment_runs.csv
     (dung dinh dang voi baseline cua Thanh vien A de D doi chieu).
  5) Dedup theo fingerprint (endpoint, method, param, loai loi) de
     khong test lap lai cho da confirm; ho tro state.json de nho lich su
     giua cac lan chay.

Yeu cau: schemathesis>=4.0, pydantic>=2.0
    pip install schemathesis pydantic --break-system-packages
"""

from __future__ import annotations

import argparse
import asyncio
import contextvars
import csv
import hashlib
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import httpx
import schemathesis
import yaml
from pydantic import BaseModel, Field, ValidationError

import rules_engine

# --------------------------------------------------------------------------
# 1. Schema du lieu (payload tu B phai khop dung format nay)
# --------------------------------------------------------------------------

class Payload(BaseModel):
    endpoint: str                     # vd: "/api/v1/users/{id}"
    method: str                       # GET/POST/PUT/DELETE/PATCH
    target_param: str                 # ten tham so bi nham (query/path/body field)
    param_location: str = "query"     # "query" | "path" | "body" | "header"
    attack_type: str                  # SQLi, XSS, BOLA, MassAssignment, ...
    payload_value: Any                # gia tri thuc su se nhoi vao param
    owasp_category: Optional[str] = None
    context: Optional[str] = None
    expected_signal: list[str] = Field(default_factory=list)  # tu khoa nghi ngo trong response
    target_app: Optional[str] = None  # "vampi" | "crapi" | ... - B NEN dien khi
                                       # chay multi-target, tranh truong hop 1
                                       # endpoint trung ten giua 2 app khac nhau


class Finding(BaseModel):
    run_id: str
    timestamp: str
    target_app: str
    endpoint: str
    method: str
    tool: str = "schemathesis"
    attack_type: str
    owasp_category: Optional[str]
    payload: Any
    status_code: Optional[int]
    response_time_ms: Optional[float]
    evidence: str
    severity: str
    confirmed: bool
    fingerprint: str
    matched_cve: str = ""


# --------------------------------------------------------------------------
# 2. Cac tu khoa/nguong dung de danh gia response co "nghi ngo" khong
#    (co the mo rong theo OWASP API Top 10 khi can)
# --------------------------------------------------------------------------

# Fallback neu khong co --rules (giu tuong thich nguoc); binh thuong
# nen luon chay voi rules.json duoc rules_engine.py cap nhat.
DEFAULT_ERROR_SIGNALS = [
    "sql syntax", "syntaxerror", "traceback", "stack trace",
    "internal server error", "unhandled exception", "odbc",
    "psql", "sqlite", "ora-", "you have an error in your sql",
]

SEVERITY_BY_STATUS = {
    500: "high",
    503: "medium",
}

# ContextVar de moi task async biet run_id hien tai ma khong can truyen tay
# qua tung ham (cac task chay song song dung chung 1 run).
STATE_RUN_ID: "contextvars.ContextVar[str]" = contextvars.ContextVar("run_id", default="")


def fingerprint_of(target_app: str, endpoint: str, method: str, param: str, attack_type: str) -> str:
    """Fingerprint tren (target_app, endpoint, method, param, attack_type).
    PHAI co target_app: khi chay multi-target, VAmPI va crAPI co the cung
    co endpoint /users/{id} - thieu target_app se lam 2 app khac nhau bi
    coi la CUNG 1 fingerprint, dedup/state se sai lech giua 2 target."""
    raw = f"{target_app.lower()}|{method.upper()}|{endpoint}|{param}|{attack_type.lower()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# --------------------------------------------------------------------------
# 3. State giua cac lan chay (tranh danh lai cho da confirm)
# --------------------------------------------------------------------------

class RunState:
    def __init__(self, path: Path):
        self.path = path
        self.data: dict[str, dict] = {}
        if path.exists():
            self.data = json.loads(path.read_text(encoding="utf-8"))

    def status(self, fp: str) -> Optional[str]:
        return self.data.get(fp, {}).get("status")

    def attempts(self, fp: str) -> int:
        return self.data.get(fp, {}).get("attempts", 0)

    def record(self, fp: str, status: str) -> None:
        entry = self.data.setdefault(fp, {"attempts": 0, "status": "new"})
        entry["attempts"] += 1
        entry["status"] = status
        entry["last_seen"] = datetime.now(timezone.utc).isoformat()

    def save(self) -> None:
        self.path.write_text(json.dumps(self.data, indent=2, ensure_ascii=False), encoding="utf-8")


MAX_ATTEMPTS_PER_FINGERPRINT = 3  # dung Nhiem vu 3.3: dung sau 3 lan thu that bai


# --------------------------------------------------------------------------
# 4. Load OpenAPI tu A + payload tu B, voi xu ly loi thuong gap
# --------------------------------------------------------------------------

def _read_spec_dict(spec_path: str) -> dict:
    """Doc spec ra dict, ho tro ca JSON va YAML - OpenAPI thuong duoc viet
    bang YAML tren thuc te, khong chi JSON."""
    text = Path(spec_path).read_text(encoding="utf-8")
    suffix = Path(spec_path).suffix.lower()
    if suffix in (".yaml", ".yml"):
        return yaml.safe_load(text)
    if suffix == ".json":
        return json.loads(text)
    # khong biet duoi file - thu JSON truoc, fallback YAML (YAML la sieu
    # tap cua JSON nen parser YAML doc duoc ca JSON, dung lam fallback an toan)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return yaml.safe_load(text)


def extract_base_url(spec_path: str) -> Optional[str]:
    """Schemathesis.openapi.from_path KHONG tu doc field 'servers'/'host'+
    'basePath' de suy ra base_url (khac voi from_url). Day la loi tich hop
    hay gap nhat khi lay spec dang file tu A - phai tu trich xuat."""
    try:
        raw = _read_spec_dict(spec_path)
    except Exception as exc:
        print(f"[CANH BAO] Khong doc duoc spec de trich base_url: {exc}", file=sys.stderr)
        return None
    if not isinstance(raw, dict):
        return None
    servers = raw.get("servers")
    if servers and isinstance(servers, list) and servers[0].get("url"):
        return servers[0]["url"]
    if raw.get("host"):  # Swagger 2.0 style
        scheme = (raw.get("schemes") or ["http"])[0]
        base_path = raw.get("basePath", "")
        return f"{scheme}://{raw['host']}{base_path}"
    return None


def load_schema(spec_path: str, cli_base_url: Optional[str]):
    try:
        schema = schemathesis.openapi.from_path(spec_path)
    except Exception as exc:  # spec loi cu phap / version khong ho tro
        print(f"[LOI] Khong doc duoc OpenAPI spec tu A: {spec_path}\n  -> {exc}",
              file=sys.stderr)
        print("  Kiem tra: (1) spec co dung OpenAPI 3.0/3.1 khong (Swagger 2.0 "
              "phai convert truoc), (2) $ref co bi loop khong, (3) co field "
              "'servers'/'host'+'basePath' de xac dinh base_url khong.",
              file=sys.stderr)
        sys.exit(1)

    base_url = cli_base_url or extract_base_url(spec_path)
    if not base_url:
        print(f"[LOI] Khong tim duoc base_url. Spec cua A khong co 'servers' "
              f"(hoac 'host'+'basePath') hop le - can chay lai voi --base-url.",
              file=sys.stderr)
        sys.exit(1)
    # Trong Schemathesis 4.x, BaseSchema.clone() khong nhan base_url truc
    # tiep - base_url duoc truyen o buoc goi request (Case.call(base_url=...)).
    return schema, base_url


def load_targets(targets_arg: str, base_urls_arg: Optional[str]) -> dict[str, tuple]:
    """Nap NHIEU spec cung luc cho che do multi-target.
    --targets 'vampi=vampi_spec.yaml,crapi=crapi_spec.json'
    --base-urls 'vampi=http://localhost:5000,crapi=http://localhost:8888' (tuy chon)
    Tra ve dict {ten_app: (schema, base_url)}."""
    base_url_overrides: dict[str, str] = {}
    if base_urls_arg:
        for pair in base_urls_arg.split(","):
            name, sep, url = pair.partition("=")
            if not sep:
                print(f"[LOI] --base-urls sai dinh dang o '{pair}'. Dung 'ten=url'.", file=sys.stderr)
                sys.exit(1)
            base_url_overrides[name.strip().lower()] = url.strip()

    targets: dict[str, tuple] = {}
    for pair in targets_arg.split(","):
        name, sep, spec_path = pair.partition("=")
        if not sep:
            print(f"[LOI] --targets sai dinh dang o '{pair}'. Dung 'ten=duong_dan', "
                  f"vd 'vampi=vampi_spec.yaml'.", file=sys.stderr)
            sys.exit(1)
        name = name.strip().lower()
        spec_path = spec_path.strip()
        if name in targets:
            print(f"[LOI] Ten target '{name}' bi lap trong --targets.", file=sys.stderr)
            sys.exit(1)
        schema, base_url = load_schema(spec_path, base_url_overrides.get(name))
        targets[name] = (schema, base_url)
        print(f"[INFO] Da nap target '{name}': {spec_path} -> base_url={base_url}")

    if not targets:
        print("[LOI] --targets khong co target nao hop le.", file=sys.stderr)
        sys.exit(1)
    return targets


def load_payloads(payload_path: str) -> list[Payload]:
    raw = json.loads(Path(payload_path).read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        raw = raw.get("payloads", [raw])

    valid: list[Payload] = []
    for i, item in enumerate(raw):
        try:
            valid.append(Payload(**item))
        except ValidationError as exc:
            # Day la loi tich hop pho bien nhat voi B: LLM sinh sai field/kieu.
            # KHONG crash ca batch - bo qua item loi, ghi canh bao, chay tiep.
            print(f"[CANH BAO] Payload #{i} tu B khong dung schema, bo qua:\n{exc}",
                  file=sys.stderr)
    if not valid:
        print("[LOI] Khong co payload hop le nao tu B.", file=sys.stderr)
        sys.exit(1)
    return valid


# --------------------------------------------------------------------------
# 5. Ghep payload vao dung operation cua schema, ban request that
# --------------------------------------------------------------------------

def find_operation(schema, endpoint: str, method: str):
    """Tim operation khop endpoint+method trong 1 schema.
    Xu ly ca truong hop B ghi path khong khop 100% (vd thieu {id})."""
    for result in schema.get_all_operations():
        if result.ok():
            op = result.ok()
            if op.method.upper() == method.upper() and op.path == endpoint:
                return op
    # thu khop long leo hon: bo qua path params trong so sanh
    norm = lambda p: p.split("{")[0].rstrip("/")
    for result in schema.get_all_operations():
        if result.ok():
            op = result.ok()
            if op.method.upper() == method.upper() and norm(op.path) == norm(endpoint):
                return op
    return None


def find_operation_multi(targets: dict[str, tuple], payload: "Payload"):
    """Loi cua 'Multi-Spec Engine': tim payload thuoc app nao trong so
    nhieu target da nap. Neu payload.target_app duoc B dien san thi chi
    tim trong dung app do (nhanh + khong bao gio nham). Neu B KHONG dien
    (truong hop pho bien khi B chua sua prompt LLM) thi tu do tim trong
    TAT CA target, va CANH BAO neu trung o >1 app (vi 2 app khac nhau co
    the tinh co cung dinh nghia /users/{id} nhung ngu nghia hoan toan
    khac nhau - khong nen tu y doan bua)."""
    if payload.target_app:
        name = payload.target_app.strip().lower()
        if name not in targets:
            print(f"[CANH BAO] payload ghi target_app='{payload.target_app}' nhung "
                  f"target nay khong nam trong --targets ({sorted(targets)}) - bo qua.",
                  file=sys.stderr)
            return None
        schema, base_url = targets[name]
        op = find_operation(schema, payload.endpoint, payload.method)
        if op is None:
            return None
        return name, schema, base_url, op

    candidates = []
    for name, (schema, base_url) in targets.items():
        op = find_operation(schema, payload.endpoint, payload.method)
        if op is not None:
            candidates.append((name, schema, base_url, op))

    if not candidates:
        return None
    # sap xep truoc de ket qua on dinh (khong phu thuoc thu tu dict cua
    # Python) VA de thong bao canh bao khop dung voi target thuc su duoc chon
    candidates.sort(key=lambda c: c[0])
    if len(candidates) > 1:
        names = [c[0] for c in candidates]
        print(f"[CANH BAO] Endpoint '{payload.method} {payload.endpoint}' trung "
              f"trong NHIEU target: {names}. B nen dien field 'target_app' trong "
              f"payload de tranh nham lan. Tam thoi dung target dau tien: '{names[0]}'.",
              file=sys.stderr)
    return candidates[0]


def build_case(schema, op, payload: Payload):
    kwargs: dict[str, Any] = {"operation": op, "method": op.method, "path": op.path}
    if payload.param_location == "query":
        kwargs["query"] = {payload.target_param: payload.payload_value}
    elif payload.param_location == "path":
        kwargs["path_parameters"] = {payload.target_param: payload.payload_value}
    elif payload.param_location == "header":
        kwargs["headers"] = {payload.target_param: str(payload.payload_value)}
    elif payload.param_location == "body":
        kwargs["body"] = {payload.target_param: payload.payload_value}
    else:
        raise ValueError(f"param_location khong ho tro: {payload.param_location}")
    return schema.make_case(**kwargs)


class PreparedCase:
    """1 payload da duoc resolve xong: biet thuoc target nao, base_url nao,
    va Case cua Schemathesis da build san. Tach buoc nay ra khoi vong lap
    async de: (1) loi resolve/build (endpoint khong ton tai, param sai...)
    bi bat va bao cao HET 1 lan truoc khi ban request nao, thay vi loi
    ret ra giua chung fuzzing; (2) nhom fingerprint chinh xac tu dau."""
    __slots__ = ("fingerprint", "target_app", "base_url", "case", "payload")

    def __init__(self, fingerprint, target_app, base_url, case, payload):
        self.fingerprint = fingerprint
        self.target_app = target_app
        self.base_url = base_url
        self.case = case
        self.payload = payload


def prepare_cases(payloads: list[Payload], targets: dict[str, tuple]) -> list[PreparedCase]:
    prepared: list[PreparedCase] = []
    for payload in payloads:
        match = find_operation_multi(targets, payload)
        if match is None:
            print(f"[CANH BAO] Endpoint '{payload.method} {payload.endpoint}' "
                  f"khong co trong bat ky target nao ({sorted(targets)}) - bo qua.",
                  file=sys.stderr)
            continue
        name, schema, base_url, op = match
        try:
            case = build_case(schema, op, payload)
        except Exception as exc:
            print(f"[CANH BAO] Khong tao duoc case cho {payload.endpoint} "
                  f"(target={name}): {exc}", file=sys.stderr)
            continue
        fp = fingerprint_of(name, payload.endpoint, payload.method,
                             payload.target_param, payload.attack_type)
        prepared.append(PreparedCase(fp, name, base_url, case, payload))
    return prepared


def evaluate_response(resp, payload: Payload, rules: Optional[dict] = None
                       ) -> tuple[str, bool, str, list[str]]:
    """Tra ve (severity, confirmed, evidence, matched_cve_ids).
    Neu co rules (tu rules_engine.py) thi dung signal + CVE cache dong;
    khong thi fallback ve DEFAULT_ERROR_SIGNALS tinh."""
    status = resp.status_code
    body_lower = (resp.text or "").lower()

    if rules is not None:
        signals = [s.lower() for s in payload.expected_signal] + rules_engine.get_all_signals(rules)
    else:
        signals = [s.lower() for s in payload.expected_signal] + DEFAULT_ERROR_SIGNALS
    hit_signals = [s for s in signals if s in body_lower]

    # Tim CVE co lien quan de boost severity + gan bang chung CVE cu the
    # (dung owasp_category + attack_type lam tu khoa tra cuu trong cache).
    matched_cves: list[dict] = []
    if rules is not None:
        matched_cves = rules_engine.match_cves_by_keyword(
            rules, payload.attack_type, payload.owasp_category)
    cve_ids = [c["cve_id"] for c in matched_cves]

    if status >= 500:
        severity = SEVERITY_BY_STATUS.get(status, "high")
        if matched_cves:  # trung voi 1 CVE cong khai -> nang severity + neu ro CVE
            top = max(matched_cves, key=lambda c: c["cvss_score"] or 0)
            if top["severity"] in ("critical",):
                severity = "critical"
            return severity, True, f"HTTP {status}; matched: {hit_signals[:3]}; lien quan {top['cve_id']} (CVSS {top['cvss_score']})", cve_ids
        return severity, True, f"HTTP {status}; matched: {hit_signals[:3]}", cve_ids
    if hit_signals:
        return "medium", True, f"HTTP {status}; leaked signal: {hit_signals[:3]}", cve_ids
    if status in (401, 403) and payload.attack_type.upper() in ("BOLA", "BFLA"):
        # that bai o day co the CHINH LA phat hien tot (bi chan dung) -
        # nguoc lai neu tra 200 voi du lieu cua user khac moi la loi that.
        return "info", False, f"HTTP {status}; bi chan (co the la dung)", cve_ids
    return "info", False, f"HTTP {status}; khong phat hien dau hieu bat thuong", cve_ids


# --------------------------------------------------------------------------
# 6. Main
# --------------------------------------------------------------------------

async def fire_case(client: "httpx.AsyncClient", case, base_url: str, headers: dict):
    """Bao mot Case (Schemathesis) thanh request that qua httpx async,
    dung as_transport_kwargs() de lay method/url/params/json dung dinh dang."""
    kwargs = case.as_transport_kwargs(base_url=base_url)
    if headers:
        kwargs["headers"] = {**kwargs.get("headers", {}), **headers}
    if not kwargs.get("cookies"):  # httpx canh bao neu truyen cookies={} rong
        kwargs.pop("cookies", None)
    return await client.request(**kwargs)


async def process_fingerprint_group(
    client: "httpx.AsyncClient", sem: "asyncio.Semaphore",
    fp: str, group: list[PreparedCase], headers: dict,
    rules: Optional[dict], state: RunState, rate_limit_s: float,
) -> list[Finding]:
    """1 group = cung fingerprint (target_app, endpoint, method, param,
    attack_type) - moi phan tu trong group chac chan CUNG 1 target_app
    (vi fingerprint da bao gom target_app). Xu ly TUAN TU trong group
    (dung sau khi confirmed hoac het luot thu) de khong ban thua cho
    cung 1 loai loi - nhung CAC GROUP KHAC NHAU (kha nang khac ca target)
    chay song song voi nhau, day la phan async giup tang toc."""
    results: list[Finding] = []

    if state.status(fp) == "confirmed":
        return results
    if state.attempts(fp) >= MAX_ATTEMPTS_PER_FINGERPRINT:
        return results

    for pc in group:
        if state.status(fp) == "confirmed":
            break
        if state.attempts(fp) >= MAX_ATTEMPTS_PER_FINGERPRINT:
            break

        async with sem:
            t0 = time.perf_counter()
            try:
                resp = await fire_case(client, pc.case, pc.base_url, headers)
                error_text = None
            except Exception as exc:
                resp = None
                error_text = str(exc)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            if rate_limit_s:
                await asyncio.sleep(rate_limit_s)

        if resp is None:
            severity, confirmed, evidence, cve_ids = "unknown", False, f"request loi: {error_text}", []
            status_code = None
        else:
            severity, confirmed, evidence, cve_ids = evaluate_response(resp, pc.payload, rules)
            status_code = resp.status_code

        finding = Finding(
            run_id=STATE_RUN_ID.get(),
            timestamp=datetime.now(timezone.utc).isoformat(),
            target_app=pc.target_app,
            endpoint=pc.payload.endpoint,
            method=pc.payload.method,
            attack_type=pc.payload.attack_type,
            owasp_category=pc.payload.owasp_category,
            payload=pc.payload.payload_value,
            status_code=status_code,
            response_time_ms=round(elapsed_ms, 1),
            evidence=evidence,
            severity=severity,
            confirmed=confirmed,
            fingerprint=fp,
            matched_cve=",".join(cve_ids),
        )
        results.append(finding)
        state.record(fp, "confirmed" if confirmed else "tested")

    return results


async def run_all(prepared: list[PreparedCase], headers: dict,
                   rules: Optional[dict], state: RunState, concurrency: int,
                   rate_limit_ms: int) -> list[Finding]:
    groups: dict[str, list[PreparedCase]] = {}
    for pc in prepared:
        groups.setdefault(pc.fingerprint, []).append(pc)

    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(timeout=20.0) as client:
        tasks = [
            process_fingerprint_group(
                client, sem, fp, group, headers,
                rules, state, rate_limit_ms / 1000,
            )
            for fp, group in groups.items()
        ]
        grouped_results = await asyncio.gather(*tasks)

    all_findings: list[Finding] = []
    for r in grouped_results:
        all_findings.extend(r)
    return all_findings


# --------------------------------------------------------------------------
# 6. Main
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Nguoi 1: tich hop Schemathesis (ho tro multi-target)")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--spec", default=None,
                       help="[Che do 1 target - nhu cu] duong dan OpenAPI spec don (.json/.yaml)")
    mode.add_argument("--targets", default=None,
                       help="[Che do multi-target - MOI] danh sach 'ten=duong_dan' cach nhau "
                            "boi dau phay. Vd: 'vampi=vampi_spec.yaml,crapi=crapi_spec.json'. "
                            "DVGA la GraphQL, dung run_graphql.py rieng, khong dua vao day.")
    ap.add_argument("--payloads", required=True, help="File JSON payload tu B")
    ap.add_argument("--base-url", default=None,
                     help="[Chi dung voi --spec] Ghi de base_url")
    ap.add_argument("--base-urls", default=None,
                     help="[Chi dung voi --targets] Ghi de base_url tung app, vd "
                          "'vampi=http://localhost:5000,crapi=http://localhost:8888'")
    ap.add_argument("--auth-header", default=None,
                     help='[KHONG KHUYEN KHICH - lo trong bash history] '
                          'Vd: "Authorization: Bearer <jwt>". '
                          'Nen dung bien moi truong FUZZ_AUTH_HEADER thay vi co nay.')
    ap.add_argument("--results-dir", default="main_pipeline/results")
    ap.add_argument("--rate-limit-ms", type=int, default=200,
                     help="Delay giua cac request TRONG CUNG 1 fingerprint group "
                          "(an toan cho container lab)")
    ap.add_argument("--concurrency", type=int, default=10,
                     help="So request toi da chay song song (bat dong bo)")
    ap.add_argument("--rules", default="rules.json", help="File rules OWASP+CVE (rules_engine.py)")
    args = ap.parse_args()

    rules = None
    if Path(args.rules).exists():
        rules = rules_engine.load_rules(args.rules)
        n_cve = len(rules.get("cve_signals", []))
        last_upd = rules["meta"].get("cve_last_updated")
        print(f"[INFO] Rules nap tu {args.rules}: {n_cve} CVE cache "
              f"(cap nhat: {last_upd or 'chua tung'}). "
              f"Neu qua cu, chay: python3 rules_engine.py --update --rules {args.rules}")
    else:
        print(f"[CANH BAO] Khong thay {args.rules} - dung signal tinh mac dinh. "
              f"Nen tao rules.json va chay rules_engine.py --update.", file=sys.stderr)

    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    run_id = str(uuid.uuid4())[:8]
    STATE_RUN_ID.set(run_id)

    state = RunState(results_dir / "state.json")

    if args.spec:
        schema, base_url = load_schema(args.spec, args.base_url)
        target_name = Path(args.spec).stem.lower()
        targets = {target_name: (schema, base_url)}
        print(f"[INFO] Che do 1-target (tuong thich nguoc): '{target_name}'")
        targets_desc = args.spec
    else:
        targets = load_targets(args.targets, args.base_urls)
        print(f"[INFO] Che do multi-target: {sorted(targets)}")
        targets_desc = args.targets

    headers = {}
    auth_header = os.environ.get("FUZZ_AUTH_HEADER")
    if auth_header:
        print("[INFO] Doc auth header tu bien moi truong FUZZ_AUTH_HEADER.")
    elif args.auth_header:
        print("[CANH BAO] --auth-header truyen qua CLI se luu trong bash "
              "history/ps output - danh cho token that. Doi sang:\n"
              "  export FUZZ_AUTH_HEADER='Authorization: Bearer <jwt>'\n"
              "  python3 run_schemathesis.py ... (khong can --auth-header)",
              file=sys.stderr)
        auth_header = args.auth_header
    if auth_header:
        k, _, v = auth_header.partition(":")
        headers[k.strip()] = v.strip()

    payloads = load_payloads(args.payloads)
    total_payloads = len(payloads)

    prepared = prepare_cases(payloads, targets)
    total_prepared = len(prepared)
    total_dropped_at_prepare = total_payloads - total_prepared

    findings = asyncio.run(run_all(
        prepared, headers, rules, state,
        args.concurrency, args.rate_limit_ms,
    ))
    total_fired = len(findings)
    total_skipped = total_prepared - total_fired

    vuln_csv = results_dir / "vulnerabilities.csv"
    is_new_file = not vuln_csv.exists()
    with open(vuln_csv, "a", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=list(Finding.model_fields.keys()))
        if is_new_file:
            writer.writeheader()
        for finding in findings:
            row = finding.model_dump()
            row["payload"] = json.dumps(row["payload"], ensure_ascii=False)
            writer.writerow(row)

    # --- NDJSON (1 JSON object/dong) - dinh dang chuan de Filebeat/Fluentd/
    # Logstash tail truc tiep vao ELK/Splunk sau nay, khong can sua code
    # fuzzing engine khi co ha tang SIEM that. Khong tu day len bat ky
    # SIEM cu the nao vi de tai chua co ha tang do (xem ghi chu Huong
    # phat trien). Moi dong da bao gom "source":"schemathesis" de phan
    # biet voi log cua Nuclei (Nguoi 2) khi gop chung 1 pipeline sau nay.
    ndjson_path = results_dir / "vulnerabilities.ndjson"
    with open(ndjson_path, "a", encoding="utf-8") as f:
        for finding in findings:
            record = finding.model_dump()
            record["source"] = "schemathesis"
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    state.save()

    # --- experiment_runs.csv (tong hop 1 dong / lan chay, cho D doi chieu) ---
    runs_csv = results_dir / "experiment_runs.csv"
    is_new_runs = not runs_csv.exists()
    with open(runs_csv, "a", newline="", encoding="utf-8") as f:
        run_writer = csv.DictWriter(f, fieldnames=[
            "run_id", "timestamp", "tool", "targets", "total_payloads",
            "total_dropped_at_prepare", "total_fired", "total_skipped_dedup",
            "total_confirmed", "llm_used"
        ])
        if is_new_runs:
            run_writer.writeheader()
        run_writer.writerow({
            "run_id": run_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": "schemathesis",
            "targets": targets_desc,
            "total_payloads": total_payloads,
            "total_dropped_at_prepare": total_dropped_at_prepare,
            "total_fired": total_fired,
            "total_skipped_dedup": total_skipped,
            "total_confirmed": sum(1 for f in findings if f.confirmed),
            "llm_used": True,
        })

    print(f"[XONG] run_id={run_id} | chuan_bi={total_prepared}/{total_payloads} "
          f"| ban={total_fired} | bo_qua(dedup)={total_skipped} "
          f"| phat_hien={sum(1 for f in findings if f.confirmed)} "
          f"| log: {vuln_csv}")


if __name__ == "__main__":
    main()
