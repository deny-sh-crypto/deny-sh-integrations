"""Framework-neutral decoy detection and reporting."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import inspect
import json
import os
import queue
import re
import threading
import warnings
from dataclasses import dataclass, fields, is_dataclass
from typing import Any, Callable, Dict, List, Literal, Mapping, Optional, Sequence, Tuple
from urllib import error as urlerror, request
from urllib.parse import urlsplit

from .core import DenyToolError


DecoySurface = Literal["model_output", "tool_args", "tool_result", "other"]
DecoyEncoding = Literal["plain", "base64", "base64url", "hex", "percent", "spaced"]

_DEFAULT_API_BASE_URL = "https://deny.sh/api"
_DEFAULT_REPORT_TIMEOUT = 3.0
_MAX_SCAN_DEPTH = 64
_MAX_SCAN_NODES = 100_000
_MAX_SCAN_TEXT_BYTES = 8 * 1024 * 1024
if __package__ == "deny_sh_langchain":
    _DECOY_SOURCE = "deny-sh-langchain-py/0.2.0"
else:
    _DECOY_SOURCE = "deny-sh-openai-agents-py/0.2.0"


@dataclass(frozen=True)
class DecoyHit:
    fingerprint: str
    surface: str
    encoding: str
    label: Optional[str] = None


class DenyDecoyLeakError(Exception):
    """Raised after leak callbacks and reports complete when blocking is enabled."""

    code = "deny_decoy_leak"

    def __init__(self, hits: Optional[Sequence[DecoyHit]] = None) -> None:
        super().__init__("A configured decoy was detected in agent-visible data.")
        self.hits = list(hits or ())


@dataclass(frozen=True)
class _NormalizedDecoy:
    value: str
    fingerprint: str
    has_whitespace: bool
    base64_variants: Tuple[str, ...]
    base64url_variants: Tuple[str, ...]
    hex_value: str
    label: Optional[str] = None


@dataclass(frozen=True)
class _ScanText:
    raw: str
    lower: str
    percent_decoded: Optional[str]
    form_decoded: Optional[str]
    unspaced: str


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _unique(values: Sequence[str]) -> Tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _normalize_decoy(entry: Any) -> _NormalizedDecoy:
    if isinstance(entry, str):
        value = entry
        label = None
    elif isinstance(entry, Mapping):
        value = entry.get("value")
        label = entry.get("label")
    else:
        value = None
        label = None
    if not isinstance(value, str) or len(value) < 8:
        raise DenyToolError(
            "deny_config_error",
            "Every decoy value must be a string of at least 8 characters.",
        )
    if isinstance(label, str) and value in label:
        raise DenyToolError(
            "deny_config_error",
            "A decoy label must not contain the decoy value.",
        )
    encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
    encoded_url = encoded.replace("+", "-").replace("/", "_")
    return _NormalizedDecoy(
        value=value,
        label=label if isinstance(label, str) else None,
        fingerprint=_fingerprint(value),
        has_whitespace=bool(re.search(r"\s", value)),
        base64_variants=_unique((encoded, encoded.rstrip("="))),
        base64url_variants=_unique((encoded_url, encoded_url.rstrip("="))),
        hex_value=value.encode("utf-8").hex(),
    )


def _append_text(raws: List[str], value: str, collected: int) -> Tuple[int, bool]:
    if not value:
        return collected, False
    try:
        encoded = value.encode("utf-8", "replace")
    except Exception:
        return collected, False
    remaining = _MAX_SCAN_TEXT_BYTES - collected
    if len(encoded) <= remaining:
        raws.append(value)
        return collected + len(encoded), False
    if remaining:
        raws.append(encoded[:remaining].decode("utf-8", "ignore"))
    return _MAX_SCAN_TEXT_BYTES, True


def _collect_raw_texts(value: Any) -> List[str]:
    raws: List[str] = []
    seen: set[int] = set()
    stack: List[Tuple[Any, int]] = [(value, 0)]
    visited = 0
    collected = 0

    def append(text: str) -> bool:
        nonlocal collected
        collected, limit_hit = _append_text(raws, text, collected)
        return limit_hit

    def push(nested: Any, depth: int) -> bool:
        if visited + len(stack) >= _MAX_SCAN_NODES:
            return True
        stack.append((nested, depth + 1))
        return False

    while stack:
        if visited >= _MAX_SCAN_NODES:
            break
        item, depth = stack.pop()
        visited += 1
        if depth > _MAX_SCAN_DEPTH:
            break
        try:
            if item is None:
                continue
            if isinstance(item, str):
                if append(item):
                    break
                continue
            if isinstance(item, (bytes, bytearray, memoryview)):
                try:
                    data = bytes(item)
                    latin1 = data.decode("latin-1")
                    if append(latin1):
                        break
                    utf8 = data.decode("utf-8", "replace")
                    if utf8 != latin1 and append(utf8):
                        break
                except Exception:
                    continue
                continue
            if isinstance(item, (int, float, bool, complex)):
                try:
                    rendered = str(item)
                except Exception:
                    continue
                if append(rendered):
                    break
                continue
            try:
                routine = inspect.isroutine(item)
            except Exception:
                routine = False
            if routine:
                try:
                    rendered = inspect.getsource(item)
                except Exception:
                    try:
                        rendered = str(item)
                    except Exception:
                        continue
                if append(rendered):
                    break
                continue

            item_id = id(item)
            if item_id in seen:
                continue
            seen.add(item_id)

            if isinstance(item, Mapping):
                try:
                    iterator = iter(item.items())
                except Exception:
                    continue
                while True:
                    try:
                        key, nested = next(iterator)
                    except StopIteration:
                        break
                    except Exception:
                        break
                    if push(key, depth) or push(nested, depth):
                        return raws
                continue
            if isinstance(item, (list, tuple, set, frozenset)):
                try:
                    iterator = iter(item)
                except Exception:
                    continue
                while True:
                    try:
                        nested = next(iterator)
                    except StopIteration:
                        break
                    except Exception:
                        break
                    if push(nested, depth):
                        return raws
                continue

            visited_names: set[str] = set()
            try:
                dataclass_instance = is_dataclass(item) and not isinstance(item, type)
            except Exception:
                dataclass_instance = False
            if dataclass_instance:
                try:
                    field_iterator = iter(fields(item))
                except Exception:
                    field_iterator = iter(())
                while True:
                    try:
                        field = next(field_iterator)
                    except StopIteration:
                        break
                    except Exception:
                        break
                    try:
                        name = field.name
                        visited_names.add(name)
                        nested = getattr(item, name)
                    except Exception:
                        continue
                    if push(nested, depth):
                        return raws

            try:
                instance_values = getattr(item, "__dict__", None)
            except Exception:
                instance_values = None
            if isinstance(instance_values, dict):
                try:
                    instance_iterator = iter(instance_values.items())
                except Exception:
                    instance_iterator = iter(())
                while True:
                    try:
                        name, nested = next(instance_iterator)
                    except StopIteration:
                        break
                    except Exception:
                        break
                    if isinstance(name, str):
                        visited_names.add(name)
                    if push(name, depth) or push(nested, depth):
                        return raws

            try:
                class_iterator = iter(type(item).__mro__)
            except Exception:
                class_iterator = iter(())
            while True:
                try:
                    cls = next(class_iterator)
                except StopIteration:
                    break
                except Exception:
                    break
                try:
                    class_vars = vars(cls)
                    slots = class_vars.get("__slots__")
                except Exception:
                    continue
                if slots:
                    try:
                        slot_names = (slots,) if isinstance(slots, str) else tuple(slots)
                    except Exception:
                        slot_names = ()
                    for name in slot_names:
                        try:
                            if name in visited_names:
                                continue
                            visited_names.add(name)
                            nested = getattr(item, name)
                        except Exception:
                            continue
                        if push(nested, depth):
                            return raws
                try:
                    property_iterator = iter(class_vars.items())
                except Exception:
                    property_iterator = iter(())
                while True:
                    try:
                        name, descriptor = next(property_iterator)
                    except StopIteration:
                        break
                    except Exception:
                        break
                    try:
                        if not isinstance(descriptor, property) or name in visited_names:
                            continue
                        visited_names.add(name)
                        with warnings.catch_warnings():
                            warnings.simplefilter("ignore", DeprecationWarning)
                            nested = getattr(item, name)
                    except Exception:
                        continue
                    if push(nested, depth):
                        return raws
            try:
                rendered = str(item)
            except Exception:
                continue
            if not (rendered.startswith("<") and rendered.endswith(">")):
                if append(rendered):
                    break
        except Exception:
            continue
    return raws


_PERCENT_RUN = re.compile(r"(?:%[0-9a-fA-F]{2})+")


def _percent_decode(text: str) -> str:
    if "%" not in text:
        return text

    def decode(match: re.Match[str]) -> str:
        return bytes.fromhex(match.group(0).replace("%", "")).decode("utf-8", "replace")

    return _PERCENT_RUN.sub(decode, text)


def _collect_scan_texts(value: Any) -> List[_ScanText]:
    texts: List[_ScanText] = []
    for raw in _collect_raw_texts(value):
        try:
            decoded = _percent_decode(raw)
            form = decoded.replace("+", " ") if "+" in decoded else decoded
            texts.append(
                _ScanText(
                    raw=raw,
                    lower=raw.lower(),
                    percent_decoded=decoded if decoded != raw else None,
                    form_decoded=form if form != raw else None,
                    unspaced=(
                        re.sub(r"\s", "", raw) if re.search(r"\s", raw) else raw
                    ),
                )
            )
        except Exception:
            continue
    return texts


def _matching_encoding(
    texts: Sequence[_ScanText], decoy: _NormalizedDecoy
) -> Optional[DecoyEncoding]:
    if any(decoy.value in text.raw for text in texts):
        return "plain"
    if any(
        variant in text.raw
        for text in texts
        for variant in decoy.base64_variants
    ):
        return "base64"
    if any(
        variant in text.raw
        for text in texts
        for variant in decoy.base64url_variants
    ):
        return "base64url"
    if any(decoy.hex_value in text.lower for text in texts):
        return "hex"
    if any(
        (
            text.percent_decoded is not None
            and decoy.value in text.percent_decoded
        )
        or (
            decoy.has_whitespace
            and text.form_decoded is not None
            and decoy.value in text.form_decoded
        )
        for text in texts
    ):
        return "percent"
    if not decoy.has_whitespace and any(
        text.unspaced != text.raw and decoy.value in text.unspaced
        for text in texts
    ):
        return "spaced"
    return None


def _run_bounded(call: Callable[[], Any], timeout: float) -> Tuple[bool, Any]:
    result_queue: queue.Queue[Tuple[bool, Any]] = queue.Queue(maxsize=1)

    def run() -> None:
        try:
            result = call()
            if inspect.isawaitable(result):
                result = asyncio.run(result)
            result_queue.put((True, result))
        except BaseException as error:  # noqa: BLE001 - transported to caller
            result_queue.put((False, error))

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        return result_queue.get(timeout=timeout)
    except queue.Empty:
        return False, TimeoutError("timeout")


class _NoRedirectHandler(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _default_transport(
    url: str, headers: Dict[str, str], body: bytes, timeout: float
) -> int:
    req = request.Request(url, data=body, headers=headers, method="POST")
    opener = request.build_opener(_NoRedirectHandler())
    try:
        with opener.open(req, timeout=timeout) as response:  # noqa: S310
            return int(response.status)
    except urlerror.HTTPError as error:
        return int(error.code)


class DecoyWatch:
    def __init__(
        self,
        decoys: Sequence[_NormalizedDecoy],
        *,
        api_key: Optional[str],
        base_url: str,
        report: bool,
        block: bool,
        on_leak: Optional[Callable[[DecoyHit], Any]],
        on_report_error: Optional[Callable[[Dict[str, Any]], Any]],
        report_timeout: float,
        transport: Callable[[str, Dict[str, str], bytes, float], Any],
    ) -> None:
        self._decoys = tuple(decoys)
        self._api_key = api_key
        self._v1_base = re.sub(r"/api$", "", base_url.rstrip("/"))
        self._report = report
        self._block = block
        self._on_leak = on_leak
        self._on_report_error = on_report_error
        self._report_timeout = report_timeout
        self._transport = transport

    def scan(self, value: Any, surface: DecoySurface = "other") -> List[DecoyHit]:
        try:
            texts = _collect_scan_texts(value)
        except Exception:
            texts = []
        hits: List[DecoyHit] = []
        for decoy in self._decoys:
            try:
                encoding = _matching_encoding(texts, decoy)
            except Exception:
                continue
            if encoding is not None:
                hits.append(
                    DecoyHit(
                        fingerprint=decoy.fingerprint,
                        surface=surface,
                        encoding=encoding,
                        label=decoy.label,
                    )
                )
        return hits

    def _notify_report_error(self, info: Dict[str, Any]) -> None:
        if self._on_report_error is None:
            return
        _run_bounded(lambda: self._on_report_error(info), self._report_timeout)

    def _post(self, path: str, body: Dict[str, Any]) -> int:
        if not self._api_key:
            raise DenyToolError(
                "deny_config_error",
                "An API key is required for decoy reporting or arming.",
            )
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        headers = {
            "Authorization": "Bearer " + self._api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        completed, result = _run_bounded(
            lambda: self._transport(
                self._v1_base + path,
                headers,
                payload,
                self._report_timeout,
            ),
            self._report_timeout,
        )
        if not completed:
            raise result
        if isinstance(result, int):
            return result
        status = getattr(result, "status", None)
        if status is None:
            status = getattr(result, "status_code", None)
        return int(status if status is not None else 200)

    def _safe_error_text(self, error: BaseException) -> str:
        text = str(error) or "network_error"
        for decoy in self._decoys:
            text = text.replace(decoy.value, "[deny:redacted]")
        return text

    def _report_hit(self, hit: DecoyHit) -> None:
        if not self._report:
            return
        try:
            status = self._post(
                "/v1/decoy-tripwires/observe",
                {
                    "tripwire_hash": hit.fingerprint,
                    "surface": hit.surface,
                    "source": _DECOY_SOURCE,
                },
            )
            if not 200 <= status < 300:
                self._notify_report_error(
                    {
                        "fingerprint": hit.fingerprint,
                        "surface": hit.surface,
                        "status": status,
                    }
                )
        except TimeoutError:
            self._notify_report_error(
                {
                    "fingerprint": hit.fingerprint,
                    "surface": hit.surface,
                    "error": "timeout",
                }
            )
        except BaseException as error:  # noqa: BLE001 - reporting never escapes
            self._notify_report_error(
                {
                    "fingerprint": hit.fingerprint,
                    "surface": hit.surface,
                    "error": self._safe_error_text(error),
                }
            )

    def check(self, value: Any, surface: DecoySurface = "other") -> List[DecoyHit]:
        hits = self.scan(value, surface)
        for hit in hits:
            if self._on_leak is not None:
                _run_bounded(lambda hit=hit: self._on_leak(hit), self._report_timeout)
            self._report_hit(hit)
        if self._block and hits:
            raise DenyDecoyLeakError(hits)
        return hits

    async def acheck(
        self, value: Any, surface: DecoySurface = "other"
    ) -> List[DecoyHit]:
        return await asyncio.to_thread(self.check, value, surface)

    def arm(self) -> Dict[str, int]:
        for decoy in self._decoys:
            try:
                status = self._post(
                    "/v1/decoy-tripwires",
                    {
                        "tripwire_hash": decoy.fingerprint,
                        "tripwire_kind": "plaintext",
                        **({"label": decoy.label} if decoy.label is not None else {}),
                    },
                )
            except TimeoutError:
                raise DenyToolError(
                    "deny_timeout",
                    "deny.sh did not respond while arming a decoy tripwire.",
                ) from None
            if not 200 <= status < 300:
                raise DenyToolError(
                    "deny_http_error",
                    "deny.sh returned "
                    + str(status)
                    + " while arming a decoy tripwire.",
                )
        return {"armed": len(self._decoys)}

    def fingerprints(self) -> List[str]:
        return [decoy.fingerprint for decoy in self._decoys]


def create_decoy_watch(
    decoys: Sequence[Any],
    *,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    report: Optional[bool] = None,
    block: bool = True,
    on_leak: Optional[Callable[[DecoyHit], Any]] = None,
    on_report_error: Optional[Callable[[Dict[str, Any]], Any]] = None,
    report_timeout: float = _DEFAULT_REPORT_TIMEOUT,
    transport: Optional[Callable[[str, Dict[str, str], bytes, float], Any]] = None,
) -> DecoyWatch:
    if not isinstance(decoys, (list, tuple)):
        raise DenyToolError("deny_config_error", "`decoys` must be an array.")
    if not isinstance(report_timeout, (int, float)) or not report_timeout > 0:
        raise DenyToolError(
            "deny_config_error", "`report_timeout` must be a positive number."
        )
    normalized_by_fingerprint: Dict[str, _NormalizedDecoy] = {}
    for entry in decoys:
        normalized = _normalize_decoy(entry)
        normalized_by_fingerprint.setdefault(normalized.fingerprint, normalized)
    resolved_api_key = api_key if api_key is not None else os.environ.get("DENY_API_KEY")
    resolved_base_url = (
        base_url
        if base_url is not None
        else os.environ.get("DENY_API_URL", _DEFAULT_API_BASE_URL)
    )
    try:
        parsed_base_url = urlsplit(resolved_base_url)
        scheme = parsed_base_url.scheme.lower()
        hostname = parsed_base_url.hostname
    except Exception:
        scheme = ""
        hostname = None
    if scheme != "https" and not (
        scheme == "http" and hostname in {"localhost", "127.0.0.1", "::1"}
    ):
        raise DenyToolError(
            "deny_config_error",
            "`base_url` must use HTTPS, except for localhost loopback URLs.",
        )
    return DecoyWatch(
        tuple(normalized_by_fingerprint.values()),
        api_key=resolved_api_key,
        base_url=resolved_base_url,
        report=bool(resolved_api_key) if report is None else bool(report),
        block=block is not False,
        on_leak=on_leak,
        on_report_error=on_report_error,
        report_timeout=float(report_timeout),
        transport=transport or _default_transport,
    )


__all__ = [
    "DecoyEncoding",
    "DecoyHit",
    "DecoySurface",
    "DecoyWatch",
    "DenyDecoyLeakError",
    "create_decoy_watch",
]
