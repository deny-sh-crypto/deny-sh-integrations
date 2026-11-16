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

from .core import DenyToolError


DecoySurface = Literal["model_output", "tool_args", "tool_result", "other"]
DecoyEncoding = Literal["plain", "base64", "base64url", "hex", "percent", "spaced"]

_DEFAULT_API_BASE_URL = "https://deny.sh/api"
_DEFAULT_REPORT_TIMEOUT = 3.0
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

    def __init__(self) -> None:
        super().__init__("A configured decoy was detected in agent-visible data.")


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


def _append_text(raws: List[str], value: str) -> None:
    if value:
        raws.append(value)


def _collect_raw_texts(value: Any) -> List[str]:
    raws: List[str] = []
    seen: set[int] = set()

    def visit(item: Any) -> None:
        if item is None:
            return
        if isinstance(item, str):
            _append_text(raws, item)
            return
        if isinstance(item, (bytes, bytearray, memoryview)):
            data = bytes(item)
            latin1 = data.decode("latin-1")
            _append_text(raws, latin1)
            utf8 = data.decode("utf-8", "replace")
            if utf8 != latin1:
                _append_text(raws, utf8)
            return
        if isinstance(item, (int, float, bool, complex)):
            _append_text(raws, str(item))
            return
        if inspect.isroutine(item):
            try:
                _append_text(raws, inspect.getsource(item))
            except Exception:
                _append_text(raws, str(item))
            return

        item_id = id(item)
        if item_id in seen:
            return
        seen.add(item_id)

        if isinstance(item, Mapping):
            for key, nested in item.items():
                visit(key)
                visit(nested)
            return
        if isinstance(item, (list, tuple, set, frozenset)):
            for nested in item:
                visit(nested)
            return

        visited_names: set[str] = set()
        if is_dataclass(item) and not isinstance(item, type):
            for field in fields(item):
                visited_names.add(field.name)
                try:
                    visit(getattr(item, field.name))
                except Exception:
                    continue

        instance_values = getattr(item, "__dict__", None)
        if isinstance(instance_values, dict):
            for name, nested in instance_values.items():
                visited_names.add(str(name))
                visit(name)
                visit(nested)

        for cls in type(item).__mro__:
            slots = vars(cls).get("__slots__")
            if slots:
                for name in (slots,) if isinstance(slots, str) else slots:
                    if name in visited_names:
                        continue
                    visited_names.add(name)
                    try:
                        visit(getattr(item, name))
                    except Exception:
                        continue
            for name, descriptor in vars(cls).items():
                if not isinstance(descriptor, property) or name in visited_names:
                    continue
                visited_names.add(name)
                try:
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", DeprecationWarning)
                        visit(getattr(item, name))
                except Exception:
                    continue
        try:
            rendered = str(item)
        except Exception:
            return
        if not (rendered.startswith("<") and rendered.endswith(">")):
            _append_text(raws, rendered)

    visit(value)
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
        decoded = _percent_decode(raw)
        form = decoded.replace("+", " ") if "+" in decoded else decoded
        texts.append(
            _ScanText(
                raw=raw,
                lower=raw.lower(),
                percent_decoded=decoded if decoded != raw else None,
                form_decoded=form if form != raw else None,
                unspaced=re.sub(r"\s", "", raw) if re.search(r"\s", raw) else raw,
            )
        )
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


def _default_transport(
    url: str, headers: Dict[str, str], body: bytes, timeout: float
) -> int:
    req = request.Request(url, data=body, headers=headers, method="POST")
    try:
        with request.urlopen(req, timeout=timeout) as response:  # noqa: S310
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
        texts = _collect_scan_texts(value)
        hits: List[DecoyHit] = []
        for decoy in self._decoys:
            encoding = _matching_encoding(texts, decoy)
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
            raise DenyDecoyLeakError()
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
