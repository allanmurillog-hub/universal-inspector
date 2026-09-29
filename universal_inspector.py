#!/usr/bin/env python3
"""
Universal Scraper Inspector v2.0
================================

Genera un dossier TXT auto-contenido con TODA la información necesaria
para que una IA construya un scraper perfecto a la primera.

Captura:
- HTML crudo (sin JS) vs HTML renderizado (con JS) para saber si se necesita navegador.
- Requests/responses de red completas (XHR, Fetch, GraphQL, APIs).
- Esquemas JSON inferidos automáticamente de respuestas API.
- Selectores CSS + XPath de todos los elementos relevantes.
- Mapa de campos de datos de items repetidos (productos, reviews, etc.).
- Detección de anti-bot (Cloudflare, Datadome, reCAPTCHA, Akamai, etc.).
- Código de reproducción listo para usar (curl + Python requests).
- Estrategia de paginación recomendada.
- Cookies/storage, formularios, JSON-LD, iframes, WebSockets.
- Screenshot completo de la página.

Instalación:
    pip install playwright
    playwright install chromium

Uso básico:
    python universal_inspector.py "https://example.com"

Con interacciones automáticas:
    python universal_inspector.py "https://example.com" --auto-interact

Salida:
    inspection_output/<dominio_timestamp>/dossier_maestro.txt  (archivo principal)
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import ssl
import sys
import traceback
import urllib.request
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse, parse_qsl, urlencode

from playwright.async_api import (
    async_playwright,
    Browser,
    BrowserContext,
    Page,
    Request,
    Response,
    WebSocket,
)

VERSION = "2.0.0"

# ─── Constantes ───────────────────────────────────────────────────────────────

SENSITIVE_HEADER_NAMES = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "api-key", "x-auth-token", "x-access-token",
    "x-csrf-token", "x-xsrf-token", "csrf-token", "xsrf-token",
}

SECRETISH_KEY_RE = re.compile(
    r"(pass(word)?|secret|token|auth|session|cookie|csrf|xsrf|api[_-]?key|bearer|jwt)",
    re.I,
)

DYNAMIC_TEXT_PATTERNS = [
    re.compile(r"\bload\s*more\b", re.I),
    re.compile(r"\bshow\s*more\b", re.I),
    re.compile(r"\bview\s*more\b", re.I),
    re.compile(r"\bmore\s*results\b", re.I),
    re.compile(r"\bnext\b", re.I),
    re.compile(r"\bprevious\b", re.I),
    re.compile(r"\bsiguiente\b", re.I),
    re.compile(r"\banterior\b", re.I),
    re.compile(r"\bver\s*m[aá]s\b", re.I),
    re.compile(r"\bcargar\s*m[aá]s\b", re.I),
    re.compile(r"\bpage\s*\d+\b", re.I),
    re.compile(r"\bpágina\s*\d+\b", re.I),
]

API_URL_HINT_RE = re.compile(
    r"/(api|graphql|ajax|search|query|results|data|feed|items|products|reviews|list|listing|v\d+)/",
    re.I,
)

ANTIBOT_SIGNATURES = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id", "cf-mitigated"],
        "server_value": "cloudflare",
        "scripts": ["challenges.cloudflare.com", "cdn-cgi/challenge-platform", "/cdn-cgi/", "turnstile"],
        "cookies": ["__cfduid", "cf_clearance", "__cf_bm", "cf_ob_info"],
    },
    "datadome": {
        "headers": ["x-datadome", "x-dd-b", "x-dd-type"],
        "scripts": ["datadome.co", "js.datadome.co"],
        "cookies": ["datadome"],
    },
    "recaptcha": {
        "scripts": ["google.com/recaptcha", "gstatic.com/recaptcha", "grecaptcha"],
    },
    "hcaptcha": {
        "scripts": ["hcaptcha.com", "js.hcaptcha.com"],
    },
    "akamai_bot_manager": {
        "headers": ["x-akamai-transformed", "akamai-grn"],
        "scripts": ["akamaihd.net", "akam/", "_bm/sdk"],
        "cookies": ["_abck", "bm_sz", "ak_bmsc", "bm_sv"],
    },
    "imperva_incapsula": {
        "headers": ["x-cdn", "x-iinfo"],
        "cookies": ["incap_ses_", "visid_incap_", "reese84"],
        "scripts": ["incapsula", "imperva", "reese84"],
    },
    "perimeterx": {
        "scripts": ["px-cdn.net", "px-cloud.net", "pxchk", "captcha.px-cdn"],
        "cookies": ["_px", "_pxhd", "_pxvid", "_pxde"],
    },
    "kasada": {
        "scripts": ["ips.js", "ct.captcha-delivery"],
        "cookies": ["_ct_", "ct_"],
    },
}

MAX_TEXT_PREVIEW = 500
DEFAULT_MAX_BODY_BYTES = 5_000_000
DEFAULT_TIMEOUT_MS = 60_000
RAW_HTTP_TIMEOUT = 15


# ─── Funciones Utilitarias ────────────────────────────────────────────────────

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_filename(value: str, max_len: int = 100) -> str:
    value = re.sub(r"[^a-zA-Z0-9._-]+", "_", value).strip("._")
    return (value or "site")[:max_len]


def short(value: Any, n: int = MAX_TEXT_PREVIEW) -> str:
    if value is None:
        return ""
    s = str(value)
    return s if len(s) <= n else s[:n] + f"... [truncado {len(s)-n} chars]"


def redact_value(value: Any, keep: int = 4) -> Any:
    if value is None:
        return None
    s = str(value)
    if len(s) <= keep * 2:
        return "***REDACTED***"
    return f"{s[:keep]}...{s[-keep:]} [REDACTED]"


def redact_headers(headers: dict[str, str], include_sensitive: bool) -> dict[str, str]:
    if include_sensitive:
        return dict(headers)
    out = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADER_NAMES or SECRETISH_KEY_RE.search(k):
            out[k] = redact_value(v)
        else:
            out[k] = v
    return out


def redact_json_like(obj: Any, include_sensitive: bool) -> Any:
    if include_sensitive:
        return obj
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if SECRETISH_KEY_RE.search(str(k)):
                out[k] = redact_value(v)
            else:
                out[k] = redact_json_like(v, include_sensitive)
        return out
    if isinstance(obj, list):
        return [redact_json_like(x, include_sensitive) for x in obj]
    return obj


def try_parse_json(text: Optional[str]) -> Any:
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def body_kind(content_type: str, url: str, request_body: Optional[str] = None) -> str:
    ct = (content_type or "").lower()
    u = url.lower()
    rb = (request_body or "").lstrip()
    if "graphql" in u or (rb.startswith("{") and ("query" in rb[:300] or "operationName" in rb[:300])):
        return "graphql"
    if "json" in ct:
        return "json"
    if "html" in ct:
        return "html"
    if "javascript" in ct or "ecmascript" in ct:
        return "javascript"
    if "xml" in ct:
        return "xml"
    if "text/" in ct:
        return "text"
    return "binary_or_other"


def graphql_details(post_data: Optional[str]) -> Optional[dict[str, Any]]:
    obj = try_parse_json(post_data)
    if not isinstance(obj, dict):
        return None
    if not any(k in obj for k in ("query", "variables", "operationName", "extensions")):
        return None
    return {
        "operationName": obj.get("operationName"),
        "query": obj.get("query"),
        "variables": obj.get("variables"),
        "extensions": obj.get("extensions"),
    }


# ─── Funciones Nuevas v2.0 ───────────────────────────────────────────────────

def infer_json_schema(obj: Any, max_depth: int = 10, _depth: int = 0) -> dict[str, Any]:
    """Infiere recursivamente un esquema de tipos a partir de un valor JSON."""
    if _depth >= max_depth:
        return {"tipo": "profundidad_maxima"}
    if obj is None:
        return {"tipo": "null"}
    if isinstance(obj, bool):
        return {"tipo": "boolean", "ejemplo": obj}
    if isinstance(obj, int):
        return {"tipo": "integer", "ejemplo": obj}
    if isinstance(obj, float):
        return {"tipo": "float", "ejemplo": obj}
    if isinstance(obj, str):
        schema: dict[str, Any] = {"tipo": "string", "longitud": len(obj)}
        if len(obj) <= 300:
            schema["ejemplo"] = obj
        else:
            schema["ejemplo"] = obj[:200] + "..."
        if re.match(r"https?://", obj):
            schema["parece"] = "url"
        elif re.match(r"\d{4}-\d{2}-\d{2}", obj):
            schema["parece"] = "fecha/datetime"
        elif re.match(r"[^@]+@[^@]+\.[^@]+", obj):
            schema["parece"] = "email"
        return schema
    if isinstance(obj, list):
        schema = {"tipo": "array", "longitud": len(obj)}
        if not obj:
            schema["items"] = "vacio"
        else:
            schema["items_schema"] = infer_json_schema(obj[0], max_depth, _depth + 1)
            if len(obj) > 1 and isinstance(obj[0], dict):
                all_keys: set[str] = set()
                for item in obj[:5]:
                    if isinstance(item, dict):
                        all_keys.update(item.keys())
                schema["todas_las_keys_en_muestra"] = sorted(all_keys)
        return schema
    if isinstance(obj, dict):
        schema = {"tipo": "object", "num_keys": len(obj), "keys": sorted(obj.keys())}
        campos: dict[str, Any] = {}
        for k, v in obj.items():
            campos[k] = infer_json_schema(v, max_depth, _depth + 1)
        schema["campos"] = campos
        return schema
    return {"tipo": str(type(obj).__name__)}


def detect_antibot_signals(
    dom_analysis: dict[str, Any],
    network: list[dict[str, Any]],
    nav_response_headers: dict[str, str],
    cookies: list[dict[str, Any]],
) -> dict[str, Any]:
    """Detecta señales de protección anti-bot/WAF."""
    detections: dict[str, list[str]] = {}

    all_resp_headers: dict[str, str] = {}
    for k, v in nav_response_headers.items():
        all_resp_headers[k.lower()] = str(v).lower()
    for r in network[:50]:
        resp = r.get("response") or {}
        for k, v in (resp.get("headers") or {}).items():
            all_resp_headers[k.lower()] = str(v).lower()

    all_scripts_text: list[str] = []
    for s in dom_analysis.get("scripts", []):
        if s.get("src"):
            all_scripts_text.append(s["src"].lower())
        if s.get("inlinePreview"):
            all_scripts_text.append(s["inlinePreview"].lower())

    cookie_names = [c.get("name", "").lower() for c in cookies]

    for provider, sigs in ANTIBOT_SIGNATURES.items():
        found: list[str] = []

        for h in sigs.get("headers", []):
            if h.lower() in all_resp_headers:
                found.append(f"header[{h}]")

        sv = sigs.get("server_value", "")
        if sv and "server" in all_resp_headers and sv.lower() in all_resp_headers["server"]:
            found.append(f"server={sv}")

        for s_pat in sigs.get("scripts", []):
            for script_text in all_scripts_text:
                if s_pat.lower() in script_text:
                    found.append(f"script contiene '{s_pat}'")
                    break

        for c_pat in sigs.get("cookies", []):
            for cn in cookie_names:
                if c_pat.lower() in cn:
                    found.append(f"cookie '{cn}'")
                    break

        if found:
            detections[provider] = found

    return detections


def generate_curl_command(record: dict[str, Any]) -> str:
    """Genera un comando curl para reproducir un request de red."""
    parts = ["curl -s"]
    method = record.get("method", "GET")
    url = record.get("url", "")

    if method != "GET":
        parts.append(f"-X {method}")

    headers = record.get("headers", {})
    skip_headers = {"host", "content-length", "connection", "accept-encoding"}
    for k, v in headers.items():
        if k.lower() not in skip_headers and "REDACTED" not in str(v):
            safe_v = str(v).replace("'", "'\\''")
            parts.append(f"-H '{k}: {safe_v}'")

    post_data = record.get("post_data")
    if post_data:
        escaped = post_data.replace("'", "'\\''")
        if len(escaped) > 2000:
            escaped = escaped[:2000] + "... [TRUNCADO]"
        parts.append(f"--data-raw '{escaped}'")

    parts.append(f"'{url}'")
    return " \\\n  ".join(parts)


def generate_python_code(record: dict[str, Any], response_schema: Optional[dict] = None) -> str:
    """Genera código Python requests para reproducir un request de red."""
    method = record.get("method", "GET").lower()
    url = record.get("url", "")
    headers = record.get("headers", {})
    post_data = record.get("post_data")
    post_json = record.get("post_data_json")

    lines = ["import requests", "import json", ""]

    skip = {"host", "content-length", "connection", "accept-encoding", "cookie"}
    h = {k: v for k, v in headers.items()
         if k.lower() not in skip and "REDACTED" not in str(v)}

    lines.append("headers = " + json.dumps(h, indent=4, ensure_ascii=False))
    lines.append("")

    if post_json and method != "get":
        lines.append("payload = " + json.dumps(post_json, indent=4, ensure_ascii=False))
        lines.append("")
        lines.append(f"response = requests.{method}(")
        lines.append(f'    "{url}",')
        lines.append("    headers=headers,")
        lines.append("    json=payload,")
        lines.append(")")
    elif post_data and method != "get":
        lines.append(f"data = {post_data!r}")
        lines.append("")
        lines.append(f"response = requests.{method}(")
        lines.append(f'    "{url}",')
        lines.append("    headers=headers,")
        lines.append("    data=data,")
        lines.append(")")
    else:
        lines.append(f"response = requests.{method}(")
        lines.append(f'    "{url}",')
        lines.append("    headers=headers,")
        lines.append(")")

    lines.append("")
    lines.append("print(f'Status: {response.status_code}')")
    lines.append("")
    lines.append("try:")
    lines.append("    data = response.json()")
    lines.append("    print(json.dumps(data, indent=2, ensure_ascii=False))")
    lines.append("except Exception:")
    lines.append("    print(response.text[:2000])")

    return "\n".join(lines)


# ─── Dataclass ────────────────────────────────────────────────────────────────

@dataclass
class InteractionRecord:
    index: int
    trigger_type: str
    selector: str
    tag: str
    text: str
    before_url: str
    after_url: str
    before_dom_metric: dict[str, Any]
    after_dom_metric: dict[str, Any]
    new_network_record_ids: list[int]
    success: bool
    error: Optional[str] = None


# ─── Inspector Principal ─────────────────────────────────────────────────────

class Inspector:
    def __init__(
        self,
        url: str,
        output_dir: Path,
        headless: bool,
        timeout_ms: int,
        auto_interact: bool,
        max_interactions: int,
        max_body_bytes: int,
        include_sensitive: bool,
        scroll_rounds: int,
    ):
        self.url = url
        self.output_dir = output_dir
        self.headless = headless
        self.timeout_ms = timeout_ms
        self.auto_interact = auto_interact
        self.max_interactions = max_interactions
        self.max_body_bytes = max_body_bytes
        self.include_sensitive = include_sensitive
        self.scroll_rounds = scroll_rounds

        self.network: list[dict[str, Any]] = []
        self._request_to_id: dict[int, int] = {}
        self._network_lock = asyncio.Lock()
        self._body_tasks: list[asyncio.Task] = []

        self.console_events: list[dict[str, Any]] = []
        self.page_errors: list[dict[str, Any]] = []
        self.failed_requests: list[dict[str, Any]] = []
        self.websockets: list[dict[str, Any]] = []
        self.interactions: list[InteractionRecord] = []
        self.redirects: list[dict[str, Any]] = []

        self.raw_http_result: dict[str, Any] = {}
        self.antibot_detections: dict[str, Any] = {}
        self.nav_response_headers: dict[str, str] = {}

        self.page: Optional[Page] = None
        self.context: Optional[BrowserContext] = None
        self.browser: Optional[Browser] = None

    # ── Raw HTTP fetch (sin navegador) ────────────────────────────────────────

    async def raw_http_fetch(self) -> dict[str, Any]:
        """Descarga la página con HTTP puro (sin JS) para comparar con el DOM renderizado."""
        result: dict[str, Any] = {
            "success": False, "status": None, "headers": {},
            "html_length": 0, "html_preview": "", "content_type": "", "error": None,
        }
        try:
            def _fetch():
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(self.url, headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/120.0.0.0 Safari/537.36"
                    ),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                })
                with urllib.request.urlopen(req, timeout=RAW_HTTP_TIMEOUT, context=ctx) as resp:
                    raw = resp.read(self.max_body_bytes)
                    html = raw.decode("utf-8", errors="replace")
                    return {
                        "success": True, "status": resp.status,
                        "headers": dict(resp.headers),
                        "html_length": len(html),
                        "html_preview": html[:50000],
                        "content_type": resp.headers.get("Content-Type", ""),
                        "error": None,
                    }
            result = await asyncio.to_thread(_fetch)
        except Exception as e:
            result["error"] = repr(e)
        self.raw_http_result = result
        return result

    # ── Handlers de red ───────────────────────────────────────────────────────

    async def _all_request_headers(self, request: Request) -> dict[str, str]:
        try:
            return await request.all_headers()
        except Exception:
            try:
                return dict(request.headers)
            except Exception:
                return {}

    async def _all_response_headers(self, response: Response) -> dict[str, str]:
        try:
            return await response.all_headers()
        except Exception:
            try:
                return dict(response.headers)
            except Exception:
                return {}

    async def on_request(self, request: Request) -> None:
        try:
            headers = await self._all_request_headers(request)
            post_data = request.post_data
            parsed_post = try_parse_json(post_data)
            if parsed_post is not None:
                parsed_post = redact_json_like(parsed_post, self.include_sensitive)

            record = {
                "id": None,
                "timestamp_utc": utc_now_iso(),
                "phase": "request",
                "url": request.url,
                "method": request.method,
                "resource_type": request.resource_type,
                "is_navigation_request": request.is_navigation_request(),
                "headers": redact_headers(headers, self.include_sensitive),
                "post_data": post_data if self.include_sensitive else self._redact_post_data(post_data),
                "post_data_json": parsed_post,
                "graphql": redact_json_like(graphql_details(post_data), self.include_sensitive),
                "redirected_from": request.redirected_from.url if request.redirected_from else None,
                "redirected_to": None,
                "response": None,
                "failure": None,
            }
            async with self._network_lock:
                record["id"] = len(self.network) + 1
                self.network.append(record)
                self._request_to_id[id(request)] = record["id"]

            if request.redirected_from:
                self.redirects.append({
                    "from": request.redirected_from.url,
                    "to": request.url,
                    "method": request.method,
                    "timestamp_utc": utc_now_iso(),
                })
        except Exception as e:
            self.page_errors.append({
                "type": "inspector_request_handler",
                "error": repr(e),
                "timestamp_utc": utc_now_iso(),
            })

    def _redact_post_data(self, post_data: Optional[str]) -> Optional[str]:
        if post_data is None:
            return None
        obj = try_parse_json(post_data)
        if obj is not None:
            return json.dumps(redact_json_like(obj, False), ensure_ascii=False)
        try:
            pairs = parse_qsl(post_data, keep_blank_values=True)
            if pairs:
                redacted = []
                for k, v in pairs:
                    redacted.append((k, redact_value(v) if SECRETISH_KEY_RE.search(k) else v))
                return urlencode(redacted)
        except Exception:
            pass
        return post_data

    async def on_response(self, response: Response) -> None:
        task = asyncio.create_task(self._capture_response(response))
        self._body_tasks.append(task)

    async def _capture_response(self, response: Response) -> None:
        try:
            request = response.request
            req_id = self._request_to_id.get(id(request))
            headers = await self._all_response_headers(response)
            content_type = headers.get("content-type", headers.get("Content-Type", ""))

            if request.is_navigation_request() and not self.nav_response_headers:
                self.nav_response_headers = dict(headers)

            response_info: dict[str, Any] = {
                "status": response.status,
                "status_text": response.status_text,
                "ok": response.ok,
                "url": response.url,
                "headers": redact_headers(headers, self.include_sensitive),
                "content_type": content_type,
                "body_kind": body_kind(content_type, response.url, request.post_data),
                "body_text": None,
                "body_json": None,
                "body_sha256": None,
                "body_bytes": None,
                "body_truncated": False,
                "body_error": None,
            }

            textual = (
                any(x in content_type.lower() for x in (
                    "json", "text", "html", "xml", "javascript", "graphql",
                    "x-www-form-urlencoded",
                ))
                or request.resource_type in {"xhr", "fetch", "document", "script"}
            )

            is_sse = "text/event-stream" in content_type.lower()
            if textual or is_sse:
                try:
                    timeout = 1.0 if is_sse else 5.0
                    raw = await asyncio.wait_for(response.body(), timeout=timeout)
                    response_info["body_bytes"] = len(raw)
                    response_info["body_sha256"] = hashlib.sha256(raw).hexdigest()
                    if len(raw) > self.max_body_bytes:
                        raw = raw[:self.max_body_bytes]
                        response_info["body_truncated"] = True
                    text = raw.decode("utf-8", errors="replace")

                    if is_sse:
                        response_info["body_text"] = text
                        response_info["body_kind"] = "sse"
                    else:
                        obj = try_parse_json(text)
                        if obj is not None:
                            obj = redact_json_like(obj, self.include_sensitive)
                            response_info["body_json"] = obj
                            response_info["body_text"] = json.dumps(obj, ensure_ascii=False)
                        else:
                            response_info["body_text"] = text
                except asyncio.TimeoutError:
                    if is_sse:
                        response_info["body_error"] = "SSE stream or long-polling connection (timed out waiting for full body)"
                        response_info["body_kind"] = "sse"
                    else:
                        response_info["body_error"] = "Timeout reading body"
                except Exception as e:
                    response_info["body_error"] = repr(e)

            if req_id is None:
                async with self._network_lock:
                    req_id = len(self.network) + 1
                    self.network.append({
                        "id": req_id,
                        "timestamp_utc": utc_now_iso(),
                        "phase": "response_without_request_record",
                        "url": request.url,
                        "method": request.method,
                        "resource_type": request.resource_type,
                        "headers": {},
                        "post_data": request.post_data,
                        "graphql": graphql_details(request.post_data),
                        "response": response_info,
                        "failure": None,
                    })
            else:
                async with self._network_lock:
                    self.network[req_id - 1]["response"] = response_info
        except Exception as e:
            self.page_errors.append({
                "type": "inspector_response_handler",
                "error": repr(e),
                "url": getattr(response, "url", None),
                "timestamp_utc": utc_now_iso(),
            })

    async def on_request_failed(self, request: Request) -> None:
        failure = request.failure
        item = {
            "url": request.url,
            "method": request.method,
            "resource_type": request.resource_type,
            "failure": failure,
            "timestamp_utc": utc_now_iso(),
        }
        self.failed_requests.append(item)
        async with self._network_lock:
            req_id = self._request_to_id.get(id(request))
            if req_id and req_id <= len(self.network):
                self.network[req_id - 1]["failure"] = failure

    async def on_console(self, msg) -> None:
        try:
            self.console_events.append({
                "type": msg.type,
                "text": msg.text,
                "timestamp_utc": utc_now_iso(),
            })
        except Exception:
            pass

    async def on_page_error(self, exc) -> None:
        self.page_errors.append({
            "type": "pageerror",
            "error": str(exc),
            "timestamp_utc": utc_now_iso(),
        })

    async def on_websocket(self, ws: WebSocket) -> None:
        rec = {
            "url": ws.url, "opened_utc": utc_now_iso(),
            "frames_sent": [], "frames_received": [], "closed_utc": None,
        }
        self.websockets.append(rec)

        def sent(payload):
            rec["frames_sent"].append({"timestamp_utc": utc_now_iso(), "payload": short(payload, 5000)})

        def received(payload):
            rec["frames_received"].append({"timestamp_utc": utc_now_iso(), "payload": short(payload, 5000)})

        def closed(_=None):
            rec["closed_utc"] = utc_now_iso()

        ws.on("framesent", sent)
        ws.on("framereceived", received)
        ws.on("close", closed)

    # ── Utilidades de página ──────────────────────────────────────────────────

    async def wait_settle(self, ms: int = 1500) -> None:
        assert self.page is not None
        try:
            await self.page.wait_for_load_state("domcontentloaded", timeout=min(self.timeout_ms, 10_000))
        except Exception:
            pass
        try:
            await self.page.wait_for_load_state("networkidle", timeout=min(self.timeout_ms, 8_000))
        except Exception:
            pass
        await self.page.wait_for_timeout(ms)

    async def page_metric(self) -> dict[str, Any]:
        assert self.page is not None
        try:
            return await self.page.evaluate("""() => ({
                url: location.href,
                title: document.title,
                textLength: (document.body?.innerText || "").length,
                htmlLength: document.documentElement.outerHTML.length,
                elementCount: document.querySelectorAll("*").length,
                linkCount: document.querySelectorAll("a").length,
                buttonCount: document.querySelectorAll("button,[role='button']").length,
                formCount: document.querySelectorAll("form").length,
                scrollHeight: document.documentElement.scrollHeight,
                viewportHeight: innerHeight
            })""")
        except Exception:
            return {}

    # ── Captura del DOM (con XPath y extracción de campos) ────────────────────

    async def capture_dom_artifacts(self) -> dict[str, Any]:
        assert self.page is not None
        dom_html = await self.page.content()
        (self.output_dir / "rendered_dom.html").write_text(dom_html, encoding="utf-8")

        try:
            await self.page.screenshot(
                path=str(self.output_dir / "full_page.png"),
                full_page=True,
            )
        except Exception as e:
            self.page_errors.append({
                "type": "screenshot", "error": repr(e), "timestamp_utc": utc_now_iso(),
            })

        analysis = await self.page.evaluate(r"""
        () => {
          const text = el => (el.innerText || el.textContent || "").trim().replace(/\s+/g," ");
          const attrs = el => Object.fromEntries([...el.attributes].map(a => [a.name, a.value]));
          const cssEscape = s => {
            try { return CSS.escape(s); } catch { return String(s).replace(/[^a-zA-Z0-9_-]/g, "\\$&"); }
          };

          function selector(el) {
            if (!el || el.nodeType !== 1) return "";
            if (el.id) return "#" + cssEscape(el.id);
            const parts = [];
            let cur = el;
            for (let depth=0; cur && cur.nodeType===1 && depth<4; depth++, cur=cur.parentElement) {
              let p = cur.tagName.toLowerCase();
              const cls = [...cur.classList].filter(Boolean).slice(0,2);
              if (cls.length) p += "." + cls.map(cssEscape).join(".");
              if (cur.parentElement) {
                const sibs = [...cur.parentElement.children].filter(x => x.tagName === cur.tagName);
                if (sibs.length > 1) p += `:nth-of-type(${sibs.indexOf(cur)+1})`;
              }
              parts.unshift(p);
            }
            return parts.join(" > ");
          }

          function xpath(el) {
            if (!el || el.nodeType !== 1) return "";
            if (el.id) {
              const safeId = el.id.replace(/"/g, '\"').replace(/'/g, "\\'");
              return `//*[@id="${safeId}"]`;
            }
            const parts = [];
            let cur = el;
            let depth = 0;
            while (cur && cur.nodeType === 1 && depth < 8) {
              depth++;
              let tag = cur.tagName.toLowerCase();
              if (cur.parentElement) {
                const sibs = [...cur.parentElement.children].filter(x => x.tagName === cur.tagName);
                if (sibs.length > 1) tag += `[${sibs.indexOf(cur) + 1}]`;
              }
              parts.unshift(tag);
              cur = cur.parentElement;
            }
            return "/" + parts.join("/");
          }

          function extractFields(el) {
            const fields = {};
            const imgs = [...el.querySelectorAll("img")];
            if (imgs.length) {
              fields.imagenes = imgs.slice(0,5).map(i => ({
                src: i.src, alt: i.alt || null,
                selector_css: selector(i), selector_xpath: xpath(i)
              }));
            }
            const lnks = [...el.querySelectorAll("a[href]")];
            if (lnks.length) {
              fields.enlaces = lnks.slice(0,5).map(a => ({
                href: a.href, texto: text(a).slice(0,200),
                selector_css: selector(a), selector_xpath: xpath(a)
              }));
            }
            const headings = [...el.querySelectorAll("h1,h2,h3,h4,h5,h6,[class*='title'],[class*='name'],[class*='titulo'],[class*='nombre']")];
            if (headings.length) {
              fields.titulos = headings.slice(0,3).map(h => ({
                tag: h.tagName.toLowerCase(), texto: text(h).slice(0,300),
                selector_css: selector(h), selector_xpath: xpath(h)
              }));
            }
            const allEls = [...el.querySelectorAll("*")];
            const priceEls = allEls.filter(x => {
              const t = text(x);
              return t.length > 0 && t.length < 50 && /[\$\u20AC\u00A3\u00A5\u20B9]\s*[\d,.]+|\d+[.,]\d{2}\s*(USD|EUR|MXN|COP|ARS|CLP|PEN|BRL)?/i.test(t);
            });
            if (priceEls.length) {
              fields.precios = priceEls.slice(0,5).map(p => ({
                texto: text(p), selector_css: selector(p), selector_xpath: xpath(p)
              }));
            }
            const ratingEls = allEls.filter(x => {
              const cl = (typeof x.className === "string" ? x.className : (x.className?.baseVal || "")).toLowerCase();
              const ar = x.getAttribute("aria-label") || "";
              return /rating|star|estrella|review|score|puntuacion/i.test(cl + " " + ar);
            });
            if (ratingEls.length) {
              fields.ratings = ratingEls.slice(0,3).map(r => ({
                texto: text(r).slice(0,100), ariaLabel: r.getAttribute("aria-label"),
                selector_css: selector(r), selector_xpath: xpath(r)
              }));
            }
            const descs = allEls.filter(x => {
              const t = text(x);
              const cl = typeof x.className === "string" ? x.className : (x.className?.baseVal || "");
              return (x.tagName === "P" || /desc|description|resumen|summary/i.test(cl))
                && t.length > 30 && t.length < 2000;
            });
            if (descs.length) {
              fields.descripciones = descs.slice(0,2).map(d => ({
                texto: text(d).slice(0,500),
                selector_css: selector(d), selector_xpath: xpath(d)
              }));
            }
            const dateEls = [...el.querySelectorAll("time,[datetime],[class*='date'],[class*='fecha']")];
            if (dateEls.length) {
              fields.fechas = dateEls.slice(0,3).map(d => ({
                texto: text(d), datetime: d.getAttribute("datetime"),
                selector_css: selector(d), selector_xpath: xpath(d)
              }));
            }
            return fields;
          }

          const controls = [...document.querySelectorAll(
            "button, [role='button'], input[type='button'], input[type='submit'], a"
          )].map(el => ({
            tag: el.tagName.toLowerCase(),
            text: text(el).slice(0,300),
            selector_css: selector(el),
            selector_xpath: xpath(el),
            href: el.href || null,
            type: el.getAttribute("type"),
            ariaLabel: el.getAttribute("aria-label"),
            title: el.getAttribute("title"),
            disabled: !!el.disabled || el.getAttribute("aria-disabled")==="true",
            visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length),
            attrs: attrs(el)
          })).filter(x => x.visible);

          const forms = [...document.forms].map(f => ({
            selector_css: selector(f), selector_xpath: xpath(f),
            action: f.action,
            method: (f.method || "get").toUpperCase(),
            enctype: f.enctype,
            fields: [...f.elements].map(el => ({
              tag: el.tagName?.toLowerCase(), type: el.type || null,
              name: el.name || null, id: el.id || null,
              placeholder: el.placeholder || null, required: !!el.required,
              selector_css: selector(el), selector_xpath: xpath(el)
            }))
          }));

          const links = [...document.querySelectorAll("a[href]")].map(a => ({
            text: text(a).slice(0,300), href: a.href,
            rel: a.rel || null, target: a.target || null,
            selector_css: selector(a), selector_xpath: xpath(a)
          }));

          const iframes = [...document.querySelectorAll("iframe")].map(x => ({
            src: x.src, name: x.name, title: x.title,
            selector_css: selector(x), selector_xpath: xpath(x)
          }));

          const scripts = [...document.scripts].map(s => ({
            src: s.src || null, type: s.type || null,
            async: !!s.async, defer: !!s.defer,
            inlinePreview: s.src ? null : (s.textContent || "").slice(0,1000)
          }));

          const jsonLd = [...document.querySelectorAll('script[type="application/ld+json"]')].map(s => {
            try { return JSON.parse(s.textContent); } catch { return s.textContent; }
          });

          const metas = [...document.querySelectorAll("meta")].map(m => ({
            name: m.name || null,
            property: m.getAttribute("property"),
            httpEquiv: m.httpEquiv || null,
            content: m.content || null
          }));

          const tables = [...document.querySelectorAll("table")].map(t => {
            const hdrs = [...t.querySelectorAll("th")].map(th => text(th));
            const rows = [...t.querySelectorAll("tbody tr, tr")].slice(0,5).map(tr =>
              [...tr.querySelectorAll("td,th")].map(td => text(td).slice(0,200))
            );
            return {
              selector_css: selector(t), selector_xpath: xpath(t),
              headers: hdrs, sampleRows: rows,
              totalRows: t.querySelectorAll("tbody tr, tr").length
            };
          });

          const repeated = [];
          const seen = new Set();
          const candidateParents = [...document.querySelectorAll("ul, ol, table, tbody, main, section, [class*='list'], [class*='grid'], [class*='container'], [class*='feed'], [class*='cards'], div")].slice(0, 150);
          for (const parent of candidateParents) {
            const kids = [...parent.children];
            if (kids.length < 3 || kids.length > 500) continue;
            const pSel = selector(parent);
            if (seen.has(pSel)) continue;
            const signatures = kids.map(k => {
              const cls = [...k.classList].sort().slice(0,6).join(".");
              return `${k.tagName.toLowerCase()}|${cls}`;
            });
            const counts = {};
            for (const sig of signatures) counts[sig] = (counts[sig] || 0) + 1;
            for (const [sig,count] of Object.entries(counts)) {
              if (count < 3) continue;
              const matches = kids.filter((_,i) => signatures[i]===sig);
              const avgText = matches.reduce((n,x) => n + text(x).length,0) / matches.length;
              if (avgText < 5) continue;
              seen.add(pSel);
              const firstMatch = matches[0];
              const childTag = firstMatch.tagName.toLowerCase();
              const childClasses = [...firstMatch.classList].slice(0,5);
              let itemCSS = pSel + " > " + childTag;
              if (childClasses.length) itemCSS += "." + childClasses.map(cssEscape).join(".");
              repeated.push({
                parentSelector_css: pSel,
                parentSelector_xpath: xpath(parent),
                parentTag: parent.tagName.toLowerCase(),
                itemSelector_css: itemCSS,
                itemSelector_xpath: xpath(parent) + "/" + childTag,
                childSignature: sig,
                count, averageTextLength: Math.round(avgText),
                sampleSelectors_css: matches.slice(0,3).map(selector),
                sampleSelectors_xpath: matches.slice(0,3).map(xpath),
                sampleOuterHTML: matches.slice(0,2).map(x => x.outerHTML.slice(0,15000)),
                sampleText: matches.slice(0,3).map(x => text(x).slice(0,2000)),
                dataFields: extractFields(matches[0]),
                dataFieldsSample2: matches.length > 1 ? extractFields(matches[1]) : null,
              });
            }
          }
          repeated.sort((a,b) => (b.count*b.averageTextLength) - (a.count*a.averageTextLength));

          return {
            title: document.title, url: location.href,
            lang: document.documentElement.lang || null,
            charset: document.characterSet,
            controls, forms, links, iframes, scripts, jsonLd, metas, tables,
            repeatedGroups: repeated.slice(0,30),
            bodyTextPreview: text(document.body).slice(0,15000)
          };
        }
        """)
        return analysis

    # ── Storage ───────────────────────────────────────────────────────────────

    async def storage_snapshot(self) -> dict[str, Any]:
        assert self.page is not None and self.context is not None
        cookies_raw = await self.context.cookies()
        cookies = [dict(c) for c in cookies_raw]
        if not self.include_sensitive:
            for c in cookies:
                if "value" in c:
                    c["value"] = redact_value(c["value"])
        try:
            local = await self.page.evaluate("() => Object.fromEntries(Object.entries(localStorage))")
        except Exception:
            local = {}
        try:
            session = await self.page.evaluate("() => Object.fromEntries(Object.entries(sessionStorage))")
        except Exception:
            session = {}
        return {
            "cookies": cookies,
            "localStorage": redact_json_like(local, self.include_sensitive),
            "sessionStorage": redact_json_like(session, self.include_sensitive),
        }

    # ── Detección dinámica ────────────────────────────────────────────────────

    async def detect_dynamic_controls(self, dom_analysis: dict[str, Any]) -> list[dict[str, Any]]:
        candidates = []
        for c in dom_analysis.get("controls", []):
            hay = " ".join(filter(None, [
                c.get("text"), c.get("ariaLabel"), c.get("title"),
                c.get("attrs", {}).get("data-testid"),
                c.get("attrs", {}).get("class"),
                c.get("attrs", {}).get("id"),
                c.get("href"),
            ]))
            matched = [p.pattern for p in DYNAMIC_TEXT_PATTERNS if p.search(hay)]
            rel_next = (c.get("attrs", {}).get("rel") or "").lower() == "next"
            aria = (c.get("ariaLabel") or "").lower()
            if matched or rel_next or "next" in aria:
                candidates.append({**c, "matched_patterns": matched, "rel_next": rel_next})
        return candidates

    async def scroll_probe(self) -> list[dict[str, Any]]:
        assert self.page is not None
        rounds = []
        for i in range(self.scroll_rounds):
            before = await self.page_metric()
            net_before = len(self.network)
            try:
                await self.page.evaluate("window.scrollTo(0, document.documentElement.scrollHeight)")
                await self.wait_settle(1000)
            except Exception as e:
                rounds.append({"round": i + 1, "error": repr(e)})
                break
            after = await self.page_metric()
            rounds.append({
                "round": i + 1, "before": before, "after": after,
                "new_network_record_ids": list(range(net_before + 1, len(self.network) + 1)),
                "content_changed": (
                    after.get("htmlLength") != before.get("htmlLength")
                    or after.get("elementCount") != before.get("elementCount")
                    or after.get("scrollHeight") != before.get("scrollHeight")
                ),
            })
            if not rounds[-1]["content_changed"]:
                break
        try:
            await self.page.evaluate("window.scrollTo(0, 0)")
        except Exception:
            pass
        return rounds

    async def auto_interactions(self, candidates: list[dict[str, Any]]) -> None:
        assert self.page is not None
        dangerous = re.compile(
            r"\b(log\s*out|logout|delete|remove|checkout|purchase|buy|pay|submit\s*order|sign\s*out|eliminar|borrar|comprar|pagar)\b",
            re.I,
        )
        used: set[str] = set()
        for candidate in candidates:
            if len(self.interactions) >= self.max_interactions:
                break
            sel = candidate.get("selector_css") or candidate.get("selector") or ""
            label = " ".join(filter(None, [candidate.get("text"), candidate.get("ariaLabel"), candidate.get("title")]))
            if not sel or sel in used or dangerous.search(label):
                continue
            used.add(sel)
            before = await self.page_metric()
            before_url = self.page.url
            net_before = len(self.network)
            success = False
            error = None
            try:
                locator = self.page.locator(sel).first
                if await locator.count() == 0 or not await locator.is_visible():
                    continue
                await locator.scroll_into_view_if_needed()
                await locator.click(timeout=5000)
                await self.wait_settle(1200)
                success = True
            except Exception as e:
                error = repr(e)
            after = await self.page_metric()
            self.interactions.append(InteractionRecord(
                index=len(self.interactions) + 1, trigger_type="auto_click",
                selector=sel, tag=candidate.get("tag") or "",
                text=short(label, 300), before_url=before_url,
                after_url=self.page.url, before_dom_metric=before,
                after_dom_metric=after,
                new_network_record_ids=list(range(net_before + 1, len(self.network) + 1)),
                success=success, error=error,
            ))

    # ── Análisis de paginación ────────────────────────────────────────────────

    def analyze_pagination(
        self,
        dynamic_controls: list[dict[str, Any]],
        scroll_probe: list[dict[str, Any]],
        dom_analysis: dict[str, Any],
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "tipo_detectado": "ninguno", "confianza": "baja",
            "detalles": {}, "recomendacion": "",
        }

        scroll_changed = any(r.get("content_changed") for r in scroll_probe)
        scroll_triggered_api = any(r.get("new_network_record_ids") for r in scroll_probe)

        if scroll_changed:
            result["tipo_detectado"] = "infinite_scroll"
            result["confianza"] = "alta" if scroll_triggered_api else "media"
            result["detalles"]["scroll_rounds_con_cambio"] = sum(1 for r in scroll_probe if r.get("content_changed"))
            result["detalles"]["api_requests_por_scroll"] = [r.get("new_network_record_ids", []) for r in scroll_probe]
            result["recomendacion"] = (
                "La pagina usa infinite scroll. Usar Playwright para scroll progresivo, "
                "o interceptar el API endpoint que se dispara con cada scroll e iterarlo con requests HTTP."
            )
            return result

        load_more = [c for c in dynamic_controls
                     if any("more" in p.lower() or "más" in p.lower() or "mas" in p.lower()
                            for p in c.get("matched_patterns", []))]
        next_controls = [c for c in dynamic_controls
                        if c.get("rel_next") or "next" in (c.get("text") or "").lower()
                        or "siguiente" in (c.get("text") or "").lower()]

        if load_more:
            result["tipo_detectado"] = "load_more_button"
            result["confianza"] = "alta"
            result["detalles"]["botones"] = [
                {"texto": c.get("text"),
                 "selector_css": c.get("selector_css") or c.get("selector"),
                 "selector_xpath": c.get("selector_xpath", "")}
                for c in load_more[:3]
            ]
            result["recomendacion"] = (
                "La pagina usa boton 'cargar mas'. Usar Playwright para click repetido, "
                "o interceptar el API request que dispara y paginarlo."
            )
            return result

        if next_controls:
            result["tipo_detectado"] = "paginacion_por_enlaces"
            result["confianza"] = "alta"
            ctrl = next_controls[0]
            href = ctrl.get("href")
            result["detalles"]["control_next"] = {
                "texto": ctrl.get("text"), "href": href,
                "selector_css": ctrl.get("selector_css") or ctrl.get("selector"),
                "selector_xpath": ctrl.get("selector_xpath", ""),
            }
            if href:
                parsed = urlparse(href)
                params = dict(parse_qsl(parsed.query))
                page_params = {k: v for k, v in params.items()
                              if re.match(r"(page|p|pg|pagina|offset|skip|start|from)", k, re.I)}
                if page_params:
                    result["detalles"]["parametros_paginacion"] = page_params
                    result["recomendacion"] = (
                        f"Paginacion por URL con parametros: {page_params}. "
                        "Iterar incrementando el parametro de pagina con requests HTTP."
                    )
                else:
                    result["recomendacion"] = (
                        f"Paginacion por enlaces. Seguir enlace 'next' ({href}). "
                        "Se puede hacer con requests HTTP o Playwright."
                    )
            return result

        for r in self.network:
            if r.get("resource_type") not in {"xhr", "fetch"}:
                continue
            parsed = urlparse(r.get("url", ""))
            params = dict(parse_qsl(parsed.query))
            page_params = {k: v for k, v in params.items()
                          if re.match(r"(page|p|pg|pagina|offset|skip|start|from|limit|per_page|size|count)", k, re.I)}
            if page_params:
                result["tipo_detectado"] = "paginacion_api"
                result["confianza"] = "media"
                result["detalles"]["api_url"] = r.get("url", "")
                result["detalles"]["parametros"] = page_params
                result["recomendacion"] = (
                    f"Paginacion en API con params {page_params}. "
                    "Iterar incrementando estos parametros con requests HTTP."
                )
                return result

        result["recomendacion"] = (
            "No se detecto paginacion clara. El contenido puede estar en una sola carga "
            "o usar un mecanismo no estandar."
        )
        return result

    # ── Inspección principal ──────────────────────────────────────────────────

    async def inspect(self) -> dict[str, Any]:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        print("[Inspector] Iniciando fetch HTTP crudo en paralelo...")
        raw_http_task = asyncio.create_task(self.raw_http_fetch())

        async with async_playwright() as p:
            self.browser = await p.chromium.launch(headless=self.headless)
            self.context = await self.browser.new_context(
                viewport={"width": 1440, "height": 1000},
                locale="en-US",
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                record_har_path=str(self.output_dir / "network.har"),
                record_har_content="embed",
            )
            self.page = await self.context.new_page()
            self.page.set_default_timeout(self.timeout_ms)

            self.page.on("request", lambda req: asyncio.create_task(self.on_request(req)))
            self.page.on("response", lambda resp: asyncio.create_task(self.on_response(resp)))
            self.page.on("requestfailed", lambda req: asyncio.create_task(self.on_request_failed(req)))
            self.page.on("console", lambda msg: asyncio.create_task(self.on_console(msg)))
            self.page.on("pageerror", lambda exc: asyncio.create_task(self.on_page_error(exc)))
            self.page.on("websocket", lambda ws: asyncio.create_task(self.on_websocket(ws)))

            nav: dict[str, Any] = {
                "requested_url": self.url, "started_utc": utc_now_iso(),
                "response": None, "error": None,
            }

            print("[Inspector] Navegando con Playwright...")
            try:
                resp = await self.page.goto(self.url, wait_until="domcontentloaded", timeout=self.timeout_ms)
                if resp:
                    nav["response"] = {
                        "url": resp.url, "status": resp.status,
                        "status_text": resp.status_text, "ok": resp.ok,
                    }
            except Exception as e:
                nav["error"] = repr(e)

            await self.wait_settle(2000)
            print("[Inspector] Esperando resultado HTTP crudo...")
            await raw_http_task

            print("[Inspector] Capturando estado inicial del DOM...")
            initial_metric = await self.page_metric()
            initial_html = await self.page.content()
            (self.output_dir / "rendered_dom_initial.html").write_text(initial_html, encoding="utf-8")

            initial_dom_analysis = await self.capture_dom_artifacts()
            initial_dynamic_controls = await self.detect_dynamic_controls(initial_dom_analysis)

            print("[Inspector] Probando scroll/infinite-scroll...")
            scroll_probe_results = await self.scroll_probe()

            if self.auto_interact:
                print("[Inspector] Ejecutando interacciones automaticas...")
                dom_for_controls = await self.capture_dom_artifacts()
                dynamic_controls = await self.detect_dynamic_controls(dom_for_controls)
                await self.auto_interactions(dynamic_controls)
            else:
                dynamic_controls = initial_dynamic_controls

            await self.wait_settle(1200)

            pending = [t for t in self._body_tasks if not t.done()]
            if pending:
                print(f"[Inspector] Esperando {len(pending)} responses pendientes...")
                done, not_done = await asyncio.wait(pending, timeout=2.0)
                if not_done:
                    print(f"[Inspector] Cancelando {len(not_done)} responses que superaron el tiempo de espera...")
                    for t in not_done:
                        t.cancel()
                    # Wait for cancellation to complete
                    await asyncio.gather(*not_done, return_exceptions=True)

            print("[Inspector] Capturando estado final del DOM...")
            final_metric = await self.page_metric()
            final_dom_analysis = await self.capture_dom_artifacts()
            storage = await self.storage_snapshot()

            print("[Inspector] Analizando anti-bot y paginacion...")
            self.antibot_detections = detect_antibot_signals(
                final_dom_analysis, self.network,
                self.nav_response_headers, storage.get("cookies", []),
            )
            pagination = self.analyze_pagination(dynamic_controls, scroll_probe_results, final_dom_analysis)

            print("[Inspector] Construyendo dossier...")
            summary = self.build_summary(
                nav=nav, initial_metric=initial_metric, final_metric=final_metric,
                initial_dom=initial_dom_analysis, final_dom=final_dom_analysis,
                dynamic_controls=dynamic_controls, scroll_probe=scroll_probe_results,
                storage=storage, pagination=pagination,
            )
            self.write_outputs(summary)

            await self.context.close()
            await self.browser.close()
            return summary

    # ── Construcción del resumen ──────────────────────────────────────────────

    def build_summary(self, nav, initial_metric, final_metric, initial_dom,
                      final_dom, dynamic_controls, scroll_probe, storage, pagination):
        api_records, graphql_records, xhr_fetch_records = [], [], []
        for r in self.network:
            rt = r.get("resource_type")
            url = r.get("url", "")
            if rt in {"xhr", "fetch"} or API_URL_HINT_RE.search(url):
                api_records.append(r["id"])
            if rt in {"xhr", "fetch"}:
                xhr_fetch_records.append(r["id"])
            if r.get("graphql") or "graphql" in url.lower():
                graphql_records.append(r["id"])

        api_schemas: dict[int, dict] = {}
        relevant = set(xhr_fetch_records + api_records + graphql_records)
        for r in self.network:
            if r["id"] not in relevant:
                continue
            resp = r.get("response") or {}
            if resp.get("body_json") is not None:
                try:
                    api_schemas[r["id"]] = infer_json_schema(resp["body_json"])
                except Exception:
                    pass

        return {
            "inspector": {
                "name": "Universal Scraper Inspector", "version": VERSION,
                "generated_utc": utc_now_iso(),
                "sensitive_values_included": self.include_sensitive,
            },
            "navigation": nav,
            "page": {
                "initial_url": self.url, "final_url": final_dom.get("url"),
                "title": final_dom.get("title"), "lang": final_dom.get("lang"),
                "charset": final_dom.get("charset"),
                "initial_metric": initial_metric, "final_metric": final_metric,
                "redirects": self.redirects,
            },
            "raw_http": self.raw_http_result,
            "antibot": self.antibot_detections,
            "pagination": pagination,
            "dynamic_behavior": {
                "requires_browser_hint": bool(
                    xhr_fetch_records
                    or any(x.get("content_changed") for x in scroll_probe)
                    or self.interactions
                ),
                "dynamic_controls": dynamic_controls,
                "scroll_probe": scroll_probe,
                "interactions": [asdict(x) for x in self.interactions],
            },
            "network_index": {
                "total_records": len(self.network),
                "xhr_fetch_record_ids": xhr_fetch_records,
                "api_candidate_record_ids": api_records,
                "graphql_record_ids": graphql_records,
                "failed_requests_count": len(self.failed_requests),
            },
            "api_schemas": api_schemas,
            "dom": {
                "forms": final_dom.get("forms", []),
                "controls": final_dom.get("controls", []),
                "links": final_dom.get("links", []),
                "iframes": final_dom.get("iframes", []),
                "scripts": final_dom.get("scripts", []),
                "jsonLd": final_dom.get("jsonLd", []),
                "metas": final_dom.get("metas", []),
                "tables": final_dom.get("tables", []),
                "repeatedGroups": final_dom.get("repeatedGroups", []),
                "bodyTextPreview": final_dom.get("bodyTextPreview"),
            },
            "storage": storage,
            "console": self.console_events,
            "page_errors": self.page_errors,
            "failed_requests": self.failed_requests,
            "websockets": self.websockets,
        }

    # ── Escritura de archivos ─────────────────────────────────────────────────

    def write_outputs(self, summary: dict[str, Any]) -> None:
        def dump(name: str, obj: Any):
            (self.output_dir / name).write_text(
                json.dumps(obj, ensure_ascii=False, indent=2, default=str),
                encoding="utf-8",
            )

        dump("summary.json", summary)
        dump("network.json", self.network)
        dump("console.json", self.console_events)
        dump("websockets.json", self.websockets)
        dump("storage.json", summary["storage"])
        dump("dom_analysis.json", summary["dom"])
        dump("interactions.json", summary["dynamic_behavior"])
        dump("api_schemas.json", summary.get("api_schemas", {}))

        if self.raw_http_result.get("html_preview"):
            (self.output_dir / "raw_http.html").write_text(
                self.raw_http_result["html_preview"], encoding="utf-8",
            )

        dossier = self.render_dossier(summary)
        (self.output_dir / "dossier_maestro.txt").write_text(dossier, encoding="utf-8")

    # ══════════════════════════════════════════════════════════════════════════
    # DOSSIER MAESTRO — Archivo principal para la IA
    # ══════════════════════════════════════════════════════════════════════════

    def render_dossier(self, s: dict[str, Any]) -> str:
        L: list[str] = []
        a = L.append
        sep = "=" * 100
        thin = "-" * 100

        p = s["page"]
        ni = s["network_index"]
        ab = s.get("antibot", {})
        pag = s.get("pagination", {})
        raw = s.get("raw_http", {})
        dyn = s["dynamic_behavior"]
        dom = s["dom"]

        # ── Cabecera ──
        a(sep)
        a("DOSSIER MAESTRO PARA GENERACION AUTOMATICA DE SCRAPER")
        a(f"Universal Scraper Inspector v{VERSION}")
        a(sep)
        a("")
        a("INSTRUCCIONES PARA LA IA: Este archivo contiene TODA la informacion necesaria")
        a("para construir un scraper funcional. Lee las secciones en orden.")
        a("Seccion 0 = resumen ejecutivo. Las demas = datos tecnicos detallados.")
        a("")

        # ══════════════ SECCION 0: RESUMEN EJECUTIVO ══════════════
        a(sep)
        a("SECCION 0: RESUMEN EJECUTIVO")
        a(sep)
        a(f"URL objetivo:        {p['initial_url']}")
        a(f"URL final:           {p['final_url']}")
        a(f"Titulo:              {p['title']}")
        a(f"Idioma:              {p.get('lang', 'no detectado')}")
        a(f"Charset:             {p.get('charset', 'no detectado')}")
        a("")

        raw_len = raw.get("html_length", 0)
        rendered_len = (p.get("final_metric") or {}).get("htmlLength", 0)
        needs_js = dyn["requires_browser_hint"]
        diff_ratio = abs(rendered_len - raw_len) / max(raw_len, 1) if raw_len else 0

        a(f"Requiere JavaScript/navegador?  {'SI' if needs_js else 'PROBABLEMENTE NO'}")
        if raw_len:
            a(f"  HTML crudo (sin JS):       {raw_len:,} bytes")
            a(f"  HTML renderizado (con JS): {rendered_len:,} bytes")
            a(f"  Diferencia:                {diff_ratio * 100:.1f}%")
            if diff_ratio > 0.3:
                a("  CONCLUSION: El contenido se genera dinamicamente con JavaScript")
            else:
                a("  CONCLUSION: El contenido principal esta en el HTML estatico del servidor")
        a("")
        a(f"APIs/XHR/Fetch detectadas:   {len(ni['xhr_fetch_record_ids'])} requests")
        a(f"GraphQL detectado:           {len(ni['graphql_record_ids'])} requests")
        a(f"Total requests de red:       {ni['total_records']}")
        a("")

        if ab:
            a("!! PROTECCION ANTI-BOT DETECTADA:")
            for provider, signals in ab.items():
                a(f"  - {provider.upper()}: {', '.join(signals[:5])}")
            a("")
        else:
            a("[OK] No se detecto proteccion anti-bot significativa")
            a("")

        a(f"Paginacion: {pag.get('tipo_detectado', 'no analizada')} (confianza: {pag.get('confianza', 'N/A')})")
        if pag.get("recomendacion"):
            a(f"  Recomendacion: {pag['recomendacion']}")
        a("")

        a("ESTRATEGIA RECOMENDADA:")
        if ni["xhr_fetch_record_ids"] and not ab:
            a("  -> OPCION 1 (PREFERIDA): Usar requests HTTP directos a la API detectada")
            a("     Ventajas: Rapido, eficiente, sin necesidad de navegador")
            a("     Ver: Seccion 3 para detalles de la API y codigo de reproduccion")
        if needs_js or ab:
            a("  -> OPCION 2: Usar Playwright/Selenium para renderizar la pagina")
            reason = "Proteccion anti-bot detectada" if ab else "El contenido requiere JavaScript"
            a(f"     Razon: {reason}")
            a("     Ver: Seccion 4 para selectores CSS y XPath de los datos")
        if not needs_js and not ab:
            a("  -> OPCION 3: Usar requests + BeautifulSoup (HTML estatico)")
            a("     El contenido esta disponible en el HTML sin ejecutar JavaScript")
        a("")

        # ══════════════ SECCION 1: NAVEGACION Y HTTP ══════════════
        a(sep)
        a("SECCION 1: NAVEGACION Y RESPUESTA HTTP")
        a(sep)
        a(f"URL solicitada: {p['initial_url']}")
        a(f"URL final:      {p['final_url']}")
        a(f"Respuesta:      {json.dumps(s['navigation'].get('response'), ensure_ascii=False)}")
        if s["navigation"].get("error"):
            a(f"Error:          {s['navigation']['error']}")
        a("")
        if p.get("redirects"):
            a("Redirecciones:")
            for rd in p["redirects"]:
                a(f"  {rd['from']} -> {rd['to']} (metodo: {rd['method']})")
        a("")
        a("Headers de respuesta del servidor:")
        a(json.dumps(self.nav_response_headers, ensure_ascii=False, indent=2))
        a("")

        # ══════════════ SECCION 2: HTML CRUDO vs RENDERIZADO ══════════════
        a(sep)
        a("SECCION 2: HTML CRUDO (SIN JS) vs HTML RENDERIZADO (CON JS)")
        a(sep)
        if raw.get("success"):
            a(f"HTTP Status crudo: {raw.get('status')}")
            a(f"Content-Type:      {raw.get('content_type')}")
            a(f"HTML crudo bytes:  {raw.get('html_length', 0):,}")
            a("")
            a("--- PRIMEROS 30,000 CARACTERES DEL HTML CRUDO (SIN JAVASCRIPT) ---")
            a(raw.get("html_preview", "")[:30000])
            a("--- FIN HTML CRUDO ---")
        else:
            a(f"No se pudo obtener HTML crudo: {raw.get('error')}")
        a("")
        a(f"HTML renderizado bytes: {rendered_len:,}")
        a("(El HTML renderizado completo esta en: rendered_dom.html)")
        a("")

        # ══════════════ SECCION 3: APIs ══════════════
        a(sep)
        a("SECCION 3: APIs DETECTADAS - REQUESTS/RESPONSES COMPLETOS")
        a(sep)
        a(f"Total requests:     {ni['total_records']}")
        a(f"XHR/Fetch IDs:      {ni['xhr_fetch_record_ids']}")
        a(f"API candidatos IDs: {ni['api_candidate_record_ids']}")
        a(f"GraphQL IDs:        {ni['graphql_record_ids']}")
        a("")

        relevant_ids = set(
            ni["xhr_fetch_record_ids"]
            + ni["api_candidate_record_ids"]
            + ni["graphql_record_ids"]
        )
        api_schemas = s.get("api_schemas", {})

        if not relevant_ids:
            a("No se detectaron requests API/XHR/Fetch. Los datos estan en el HTML estatico.")
            a("")
        else:
            for r in self.network:
                if r["id"] not in relevant_ids:
                    continue
                resp = r.get("response") or {}
                a(thin)
                a(f"API REQUEST #{r['id']}")
                a(thin)
                a(f"URL:            {r.get('url')}")
                a(f"METHOD:         {r.get('method')}")
                a(f"RESOURCE TYPE:  {r.get('resource_type')}")
                a(f"NAVEGACION:     {r.get('is_navigation_request')}")
                a("")
                a("REQUEST HEADERS:")
                a(json.dumps(r.get("headers"), ensure_ascii=False, indent=2))
                a("")
                if r.get("post_data"):
                    a("REQUEST BODY:")
                    a(str(r["post_data"]))
                    a("")
                if r.get("post_data_json") is not None:
                    a("REQUEST BODY (JSON):")
                    a(json.dumps(r["post_data_json"], ensure_ascii=False, indent=2))
                    a("")
                if r.get("graphql"):
                    a("GRAPHQL DETAILS:")
                    a(json.dumps(r["graphql"], ensure_ascii=False, indent=2))
                    a("")
                a(f"RESPONSE STATUS: {resp.get('status')} {resp.get('status_text')}")
                a(f"CONTENT-TYPE:    {resp.get('content_type')}")
                a(f"BODY BYTES:      {resp.get('body_bytes')}")
                a(f"TRUNCADO:        {resp.get('body_truncated')}")
                a("")
                a("RESPONSE HEADERS:")
                a(json.dumps(resp.get("headers"), ensure_ascii=False, indent=2))
                a("")

                if resp.get("body_json") is not None:
                    a("RESPONSE JSON COMPLETO:")
                    jt = json.dumps(resp["body_json"], ensure_ascii=False, indent=2)
                    a(jt[:100000])
                    if len(jt) > 100000:
                        a(f"... [TRUNCADO en dossier, total: {len(jt):,} chars. Ver network.json]")
                    a("")
                elif resp.get("body_text"):
                    a("RESPONSE BODY:")
                    a(str(resp["body_text"])[:50000])
                    a("")

                schema = api_schemas.get(r["id"])
                if schema:
                    a("ESQUEMA JSON INFERIDO DE LA RESPUESTA:")
                    a("(Estructura de tipos y campos para parsear la respuesta)")
                    a(json.dumps(schema, ensure_ascii=False, indent=2)[:20000])
                    a("")

                a("== CODIGO PARA REPRODUCIR ESTE REQUEST ==")
                a("")
                a("CURL:")
                a(generate_curl_command(r))
                a("")
                a("PYTHON REQUESTS:")
                a(generate_python_code(r, schema))
                a("")
        a("")

        # ══════════════ SECCION 4: ITEMS REPETIDOS ══════════════
        a(sep)
        a("SECCION 4: ITEMS REPETIDOS EN EL DOM (PRODUCTOS/CARDS/FILAS)")
        a(sep)
        a("Candidatos heuristicos a listas de datos. Incluyen selectores CSS y XPath,")
        a("HTML de ejemplo y campos de datos extraibles detectados automaticamente.")
        a("")

        for i, g in enumerate(dom.get("repeatedGroups", [])[:15], 1):
            a(thin)
            a(f"GRUPO DE ITEMS #{i}")
            a(thin)
            a(f"Cantidad de items:       {g.get('count')}")
            a(f"Texto promedio por item: {g.get('averageTextLength')} chars")
            a(f"Firma del hijo:          {g.get('childSignature')}")
            a("")
            a("CONTENEDOR (parent):")
            a(f"  CSS:   {g.get('parentSelector_css', g.get('parentSelector', ''))}")
            a(f"  XPath: {g.get('parentSelector_xpath', '')}")
            a("")
            a("SELECTOR DE CADA ITEM:")
            a(f"  CSS:   {g.get('itemSelector_css', '')}")
            a(f"  XPath: {g.get('itemSelector_xpath', '')}")
            a("")

            df = g.get("dataFields") or {}
            if df:
                a("CAMPOS DE DATOS DETECTADOS EN ITEM #1:")
                for field_name, field_data in df.items():
                    a(f"  >> {field_name.upper()}:")
                    if isinstance(field_data, list):
                        for fd in field_data[:3]:
                            if isinstance(fd, dict):
                                for fk, fv in fd.items():
                                    a(f"      {fk}: {short(fv, 300)}")
                                a("")
                    elif isinstance(field_data, dict):
                        for fk, fv in field_data.items():
                            a(f"      {fk}: {short(fv, 300)}")
                    a("")

            df2 = g.get("dataFieldsSample2") or {}
            if df2:
                a("CAMPOS DE DATOS EN ITEM #2 (confirma patron):")
                for field_name, field_data in df2.items():
                    a(f"  >> {field_name.upper()}:")
                    if isinstance(field_data, list):
                        for fd in field_data[:3]:
                            if isinstance(fd, dict):
                                for fk, fv in fd.items():
                                    a(f"      {fk}: {short(fv, 300)}")
                                a("")
                a("")

            sample_css = g.get("sampleSelectors_css", g.get("sampleSelectors", []))
            sample_xpath = g.get("sampleSelectors_xpath", [])
            if sample_css:
                a("SELECTORES DE ITEMS INDIVIDUALES:")
                for j, sel in enumerate(sample_css[:3]):
                    xp = sample_xpath[j] if j < len(sample_xpath) else ""
                    a(f"  Item {j + 1} CSS:   {sel}")
                    if xp:
                        a(f"  Item {j + 1} XPath: {xp}")

            a("")
            a("TEXTO VISIBLE DE ITEMS:")
            for j, sample in enumerate(g.get("sampleText", [])[:3]):
                a(f"  --- Item {j + 1} ---")
                a(f"  {short(sample, 2000)}")
            a("")

            a("HTML COMPLETO DE ITEMS (para construir selectores):")
            for j, html_sample in enumerate(g.get("sampleOuterHTML", [])[:2]):
                a(f"  --- HTML Item {j + 1} ---")
                a(html_sample[:15000])
            a("")
        a("")

        # ══════════════ SECCION 5: TABLAS ══════════════
        tables = dom.get("tables", [])
        if tables:
            a(sep)
            a("SECCION 5: TABLAS DE DATOS HTML")
            a(sep)
            for i, t in enumerate(tables[:10], 1):
                a(f"TABLA #{i}:")
                a(f"  CSS:   {t.get('selector_css', '')}")
                a(f"  XPath: {t.get('selector_xpath', '')}")
                a(f"  Headers: {t.get('headers', [])}")
                a(f"  Total filas: {t.get('totalRows', 0)}")
                if t.get("sampleRows"):
                    a("  Filas de ejemplo:")
                    for row in t["sampleRows"][:3]:
                        a(f"    {row}")
                a("")
            a("")

        # ══════════════ SECCION 6: COMPORTAMIENTO DINAMICO ══════════════
        a(sep)
        a("SECCION 6: COMPORTAMIENTO DINAMICO Y PAGINACION")
        a(sep)
        a(f"Requiere navegador/JS: {dyn['requires_browser_hint']}")
        a("")
        a("ANALISIS DE PAGINACION:")
        a(json.dumps(pag, ensure_ascii=False, indent=2))
        a("")
        a(f"Controles dinamicos candidatos: {len(dyn['dynamic_controls'])}")
        for i, c in enumerate(dyn["dynamic_controls"][:20], 1):
            a(f"  [{i}] tag={c.get('tag')} text={short(c.get('text'), 150)!r} "
              f"css={c.get('selector_css', c.get('selector', ''))} href={c.get('href')}")
        a("")
        a("Prueba de scroll/infinite scroll:")
        for sr in dyn.get("scroll_probe", []):
            a(f"  Round {sr.get('round')}: content_changed={sr.get('content_changed')} "
              f"new_requests={sr.get('new_network_record_ids', [])}")
        a("")
        if dyn.get("interactions"):
            a("Interacciones automaticas realizadas:")
            a(json.dumps(dyn["interactions"], ensure_ascii=False, indent=2))
        a("")

        # ══════════════ SECCION 7: DATOS ESTRUCTURADOS ══════════════
        a(sep)
        a("SECCION 7: DATOS ESTRUCTURADOS (JSON-LD, META, OPEN GRAPH)")
        a(sep)
        if dom.get("jsonLd"):
            a("JSON-LD:")
            a(json.dumps(dom["jsonLd"], ensure_ascii=False, indent=2))
            a("")
        og = [m for m in dom.get("metas", []) if m.get("property") and "og:" in (m.get("property") or "")]
        if og:
            a("OPEN GRAPH TAGS:")
            for m in og:
                a(f"  {m['property']}: {m.get('content', '')}")
            a("")
        important = [m for m in dom.get("metas", [])
                     if m.get("name") and m["name"].lower() in
                     ("description", "keywords", "robots", "viewport", "author")]
        if important:
            a("META TAGS RELEVANTES:")
            for m in important:
                a(f"  {m['name']}: {m.get('content', '')}")
            a("")

        # ══════════════ SECCION 8: FORMULARIOS ══════════════
        if dom.get("forms"):
            a(sep)
            a("SECCION 8: FORMULARIOS")
            a(sep)
            a(json.dumps(dom["forms"], ensure_ascii=False, indent=2))
            a("")

        # ══════════════ SECCION 9: IFRAMES / SCRIPTS ══════════════
        a(sep)
        a("SECCION 9: IFRAMES Y SCRIPTS CLAVE")
        a(sep)
        if dom.get("iframes"):
            a("IFRAMES:")
            a(json.dumps(dom["iframes"], ensure_ascii=False, indent=2))
            a("")
        ext_scripts = [sc for sc in dom.get("scripts", []) if sc.get("src")]
        if ext_scripts:
            a(f"SCRIPTS EXTERNOS ({len(ext_scripts)}):")
            for sc in ext_scripts[:30]:
                a(f"  {sc['src']}")
            a("")

        # ══════════════ SECCION 10: COOKIES / STORAGE ══════════════
        a(sep)
        a("SECCION 10: COOKIES Y STORAGE")
        a(sep)
        storage = s["storage"]
        if storage.get("cookies"):
            a(f"COOKIES ({len(storage['cookies'])}):")
            for c in storage["cookies"]:
                a(f"  {c.get('name')}: domain={c.get('domain')} path={c.get('path')} "
                  f"httpOnly={c.get('httpOnly')} secure={c.get('secure')} "
                  f"sameSite={c.get('sameSite')}")
            a("")
        if storage.get("localStorage"):
            a("LOCAL STORAGE:")
            a(json.dumps(storage["localStorage"], ensure_ascii=False, indent=2))
            a("")
        if storage.get("sessionStorage"):
            a("SESSION STORAGE:")
            a(json.dumps(storage["sessionStorage"], ensure_ascii=False, indent=2))
            a("")

        # ══════════════ SECCION 11: ANTI-BOT ══════════════
        a(sep)
        a("SECCION 11: DETECCION ANTI-BOT / WAF")
        a(sep)
        if ab:
            for provider, signals in ab.items():
                a(f"!! {provider.upper()}:")
                for signal in signals:
                    a(f"    - {signal}")
            a("")
            a("RECOMENDACIONES ANTI-BOT:")
            if "cloudflare" in ab:
                a("  - Cloudflare: Considerar undetected-chromedriver, cloudscraper, o FlareSolverr")
            if "datadome" in ab:
                a("  - DataDome: Requiere resolver challenge JS. Considerar Playwright con stealth")
            if "recaptcha" in ab:
                a("  - reCAPTCHA: Requiere resolucion manual o servicio (2captcha, anticaptcha)")
            if "akamai_bot_manager" in ab:
                a("  - Akamai: Requiere sensor data. Considerar Playwright stealth + cookies validas")
            if "imperva_incapsula" in ab:
                a("  - Imperva/Incapsula: Considerar rotacion de proxies + headers realistas")
            if "hcaptcha" in ab:
                a("  - hCaptcha: Requiere resolucion manual o servicio de captcha solving")
        else:
            a("[OK] No se detectaron protecciones anti-bot significativas.")
        a("")

        # ══════════════ SECCION 12: WEBSOCKETS ══════════════
        if s.get("websockets"):
            a(sep)
            a("SECCION 12: WEBSOCKETS")
            a(sep)
            a(json.dumps(s["websockets"], ensure_ascii=False, indent=2))
            a("")

        # ══════════════ SECCION 13: ERRORES ══════════════
        if s.get("page_errors") or s.get("failed_requests"):
            a(sep)
            a("SECCION 13: ERRORES Y REQUESTS FALLIDOS")
            a(sep)
            if s.get("page_errors"):
                a("ERRORES DE PAGINA:")
                a(json.dumps(s["page_errors"], ensure_ascii=False, indent=2))
            if s.get("failed_requests"):
                a("REQUESTS FALLIDOS:")
                a(json.dumps(s["failed_requests"], ensure_ascii=False, indent=2))
            a("")

        # ══════════════ SECCION 14: TEXTO VISIBLE ══════════════
        a(sep)
        a("SECCION 14: TEXTO VISIBLE COMPLETO DE LA PAGINA (preview)")
        a(sep)
        a(dom.get("bodyTextPreview", "")[:15000])
        a("")

        # ══════════════ SECCION FINAL ══════════════
        a(sep)
        a("SECCION FINAL: ARCHIVOS COMPLEMENTARIOS Y NOTAS")
        a(sep)
        a("Archivos generados en el directorio de salida:")
        a("  - dossier_maestro.txt       <- Este archivo (lectura principal)")
        a("  - summary.json              <- Resumen estructurado completo")
        a("  - network.json              <- Todos los requests/responses de red")
        a("  - rendered_dom.html         <- HTML renderizado (con JS)")
        a("  - rendered_dom_initial.html <- HTML renderizado inicial")
        a("  - raw_http.html            <- HTML crudo del servidor (sin JS)")
        a("  - full_page.png            <- Screenshot de la pagina")
        a("  - network.har             <- Archivo HAR (para importar en DevTools)")
        a("  - api_schemas.json        <- Esquemas inferidos de respuestas API")
        a("  - dom_analysis.json       <- Analisis completo del DOM")
        a("  - storage.json            <- Cookies y storage")
        a("")
        a("NOTAS IMPORTANTES PARA LA IA:")
        a("1. Revisar PRIMERO Seccion 3 (APIs). Si hay API JSON reproducible, es lo mas eficiente.")
        a("2. Si no hay API, usar selectores CSS/XPath de Seccion 4 con BeautifulSoup o Playwright.")
        a("3. Verificar Seccion 11 (Anti-bot) antes de disenar el scraper.")
        a("4. Seccion 6 (Paginacion) indica como iterar para obtener todos los datos.")
        a("5. El codigo curl y Python en Seccion 3 esta listo para copiar y ejecutar.")
        a("")
        a(sep)
        a("FIN DEL DOSSIER")
        a(sep)

        return "\n".join(L)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def build_output_dir(base: Path, url: str) -> Path:
    host = urlparse(url).netloc or "site"
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return base / f"{safe_filename(host)}_{stamp}"


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Inspecciona una web y genera un dossier completo para construir un scraper.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python universal_inspector.py "https://example.com"
  python universal_inspector.py "https://tienda.com/productos" --auto-interact
  python universal_inspector.py "https://api-site.com" --include-sensitive --headed
        """,
    )
    ap.add_argument("url", help="URL objetivo, incluyendo https://")
    ap.add_argument("--output", default="inspection_output",
                    help="Directorio base de salida (default: inspection_output)")
    ap.add_argument("--headed", action="store_true",
                    help="Mostrar Chromium durante la inspeccion.")
    ap.add_argument("--auto-interact", action="store_true",
                    help="Probar Load More/Next detectados automaticamente.")
    ap.add_argument("--max-interactions", type=int, default=5,
                    help="Maximo de clics automaticos (default: 5).")
    ap.add_argument("--scroll-rounds", type=int, default=3,
                    help="Rondas de scroll para infinite scroll (default: 3).")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_MS,
                    help=f"Timeout Playwright en ms (default: {DEFAULT_TIMEOUT_MS}).")
    ap.add_argument("--max-body-bytes", type=int, default=DEFAULT_MAX_BODY_BYTES,
                    help=f"Max bytes por response textual (default: {DEFAULT_MAX_BODY_BYTES}).")
    ap.add_argument("--include-sensitive", action="store_true",
                    help="Incluir valores completos de cookies/tokens. NO compartir el dossier.")
    return ap.parse_args()


async def amain() -> int:
    args = parse_args()

    if not re.match(r"^https?://", args.url, re.I):
        print("ERROR: la URL debe comenzar por http:// o https://", file=sys.stderr)
        return 2

    base = Path(args.output).resolve()
    out = build_output_dir(base, args.url)

    print(f"{'=' * 60}")
    print(f"  Universal Scraper Inspector v{VERSION}")
    print(f"{'=' * 60}")
    print(f"  URL:              {args.url}")
    print(f"  Salida:           {out}")
    print(f"  Auto interaccion: {args.auto_interact}")
    print(f"  Sensibles:        {args.include_sensitive}")
    print(f"{'=' * 60}")
    print()

    inspector = Inspector(
        url=args.url,
        output_dir=out,
        headless=not args.headed,
        timeout_ms=args.timeout,
        auto_interact=args.auto_interact,
        max_interactions=max(0, args.max_interactions),
        max_body_bytes=max(10_000, args.max_body_bytes),
        include_sensitive=args.include_sensitive,
        scroll_rounds=max(0, args.scroll_rounds),
    )

    try:
        summary = await inspector.inspect()
    except Exception as e:
        print(f"\n[ERROR FATAL] {e!r}", file=sys.stderr)
        traceback.print_exc()
        return 1

    print()
    print(f"{'=' * 60}")
    print("  INSPECCION COMPLETADA")
    print(f"{'=' * 60}")
    print(f"  Dossier:    {out / 'dossier_maestro.txt'}")
    print(f"  Network:    {out / 'network.json'}")
    print(f"  DOM:        {out / 'rendered_dom.html'}")
    print(f"  Screenshot: {out / 'full_page.png'}")
    print(f"  HAR:        {out / 'network.har'}")
    print()
    ni = summary["network_index"]
    print(f"  Requests totales:  {ni['total_records']}")
    print(f"  XHR/Fetch:         {len(ni['xhr_fetch_record_ids'])}")
    print(f"  GraphQL:           {len(ni['graphql_record_ids'])}")

    ab = summary.get("antibot", {})
    if ab:
        print(f"  Anti-bot:          {', '.join(ab.keys())}")
    else:
        print("  Anti-bot:          No detectado")

    pag_tipo = summary.get("pagination", {}).get("tipo_detectado", "N/A")
    print(f"  Paginacion:        {pag_tipo}")
    print()
    return 0


if __name__ == "__main__":
    # Playwright necesita ProactorEventLoop en Windows (es el default en Python 3.8+).
    # NO usar WindowsSelectorEventLoopPolicy — no soporta subprocess_exec.
    raise SystemExit(asyncio.run(amain()))
