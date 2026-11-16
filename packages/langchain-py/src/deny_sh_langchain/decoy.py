"""Scan strings, bytes, scalars, containers, and declared instance data for decoys.

Properties, callables, and custom ``__str__`` methods on objects with instance data
are not inspected. Any unreadable data carrier makes a clean scan incomplete so a
blocking watch fails closed.
"""

from __future__ import annotations

import asyncio
import base64
import datetime
import hashlib
import inspect
import json
import numbers
import os
import queue
import re
import threading
import time
from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
from pathlib import PurePath
from typing import Any, Callable, Dict, List, Literal, Mapping, Optional, Sequence, Tuple
from urllib import error as urlerror, request
from urllib.parse import urlsplit
from uuid import UUID

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


def _append_text(
    raws: List[str], value: str, collected: int
) -> Tuple[int, bool, bool]:
    if not value:
        return collected, False, False
    try:
        encoded = value.encode("utf-8", "replace")
    except Exception:
        return collected, False, True
    remaining = _MAX_SCAN_TEXT_BYTES - collected
    if len(encoded) <= remaining:
        raws.append(value)
        return collected + len(encoded), False, False
    if remaining:
        raws.append(encoded[:remaining].decode("utf-8", "ignore"))
    return _MAX_SCAN_TEXT_BYTES, True, False


def _collect_raw_texts(value: Any) -> Tuple[List[str], bool]:
    raws: List[str] = []
    seen: set[int] = set()
    stack: List[Tuple[Any, int]] = [(value, 0)]
    visited = 0
    collected = 0
    incomplete = False

    def append(text: str) -> bool:
        nonlocal collected, incomplete
        collected, limit_hit, failed = _append_text(raws, text, collected)
        if failed:
            incomplete = True
        return limit_hit

    def push(nested: Any, depth: int) -> bool:
        if visited + len(stack) >= _MAX_SCAN_NODES:
            return True
        stack.append((nested, depth + 1))
        return False

    while stack:
        if visited >= _MAX_SCAN_NODES:
            incomplete = True
            break
        item, depth = stack.pop()
        visited += 1
        if depth > _MAX_SCAN_DEPTH:
            incomplete = True
            continue
        try:
            if item is None:
                continue
            if isinstance(item, str):
                if append(item):
                    incomplete = True
                    break
                continue
            if isinstance(item, (bytes, bytearray, memoryview)):
                try:
                    data = bytes(item)
                    latin1 = data.decode("latin-1")
                    if append(latin1):
                        incomplete = True
                        break
                    utf8 = data.decode("utf-8", "replace")
                    if utf8 != latin1 and append(utf8):
                        incomplete = True
                        break
                except Exception:
                    incomplete = True
                continue
            if isinstance(
                item,
                (
                    numbers.Number,
                    UUID,
                    PurePath,
                    datetime.date,
                    datetime.time,
                    datetime.timedelta,
                    Enum,
                ),
            ):
                try:
                    rendered = str(item)
                except Exception:
                    incomplete = True
                    continue
                if append(rendered):
                    incomplete = True
                    break
                continue
            try:
                routine = inspect.isroutine(item)
            except Exception:
                routine = False
            if routine:
                continue

            item_id = id(item)
            if item_id in seen:
                continue
            seen.add(item_id)

            if isinstance(item, Mapping):
                try:
                    iterator = iter(item.items())
                except Exception:
                    incomplete = True
                    continue
                while True:
                    try:
                        key, nested = next(iterator)
                    except StopIteration:
                        break
                    except Exception:
                        incomplete = True
                        break
                    if push(key, depth) or push(nested, depth):
                        return raws, True
                continue
            if isinstance(item, (list, tuple, set, frozenset)):
                try:
                    iterator = iter(item)
                except Exception:
                    incomplete = True
                    continue
                while True:
                    try:
                        nested = next(iterator)
                    except StopIteration:
                        break
                    except Exception:
                        incomplete = True
                        break
                    if push(nested, depth):
                        return raws, True
                continue

            visited_names: set[str] = set()
            try:
                dataclass_instance = is_dataclass(item) and not isinstance(item, type)
            except Exception:
                dataclass_instance = False
            if dataclass_instance:
                try:
                    dataclass_fields = fields(item)
                except Exception:
                    dataclass_fields = ()
                    incomplete = True
                for field in dataclass_fields:
                    name = field.name
                    visited_names.add(name)
                    try:
                        nested = getattr(item, name)
                    except Exception:
                        incomplete = True
                        continue
                    if push(nested, depth):
                        return raws, True

            try:
                classes = type(item).__mro__
            except Exception:
                classes = ()
                incomplete = True
            try:
                supports_instance_dict = any(
                    "__dict__" in vars(cls) for cls in classes
                )
            except Exception:
                supports_instance_dict = True
                incomplete = True

            has_instance_dict = False
            try:
                instance_values = getattr(item, "__dict__")
                has_instance_dict = True
            except AttributeError:
                instance_values = None
                if supports_instance_dict:
                    has_instance_dict = True
                    incomplete = True
            except Exception:
                instance_values = None
                has_instance_dict = True
                incomplete = True
            if isinstance(instance_values, dict):
                try:
                    instance_iterator = iter(instance_values.items())
                except Exception:
                    instance_iterator = iter(())
                    incomplete = True
                while True:
                    try:
                        name, nested = next(instance_iterator)
                    except StopIteration:
                        break
                    except Exception:
                        incomplete = True
                        break
                    if isinstance(name, str):
                        visited_names.add(name)
                    if push(name, depth) or push(nested, depth):
                        return raws, True
            elif has_instance_dict:
                incomplete = True

            has_slots = False
            for cls in classes:
                try:
                    slots = vars(cls).get("__slots__")
                except Exception:
                    incomplete = True
                    continue
                if slots is None:
                    continue
                has_slots = True
                try:
                    slot_names = (slots,) if isinstance(slots, str) else tuple(slots)
                except Exception:
                    incomplete = True
                    continue
                for name in slot_names:
                    if name in {"__dict__", "__weakref__"} or name in visited_names:
                        continue
                    visited_names.add(name)
                    try:
                        nested = getattr(item, name)
                    except AttributeError:
                        incomplete = True
                        continue
                    except Exception:
                        incomplete = True
                        continue
                    if name in {"__pydantic_extra__", "__pydantic_private__"}:
                        if not isinstance(nested, dict):
                            continue
                    if push(nested, depth):
                        return raws, True

            if not has_instance_dict and not has_slots:
                try:
                    rendered = str(item)
                except Exception:
                    incomplete = True
                    continue
                if append(rendered):
                    incomplete = True
                    break
        except Exception:
            incomplete = True
    return raws, incomplete


_PERCENT_RUN = re.compile(r"(?:%[0-9a-fA-F]{2})+")


def _percent_decode(text: str) -> str:
    if "%" not in text:
        return text

    def decode(match: re.Match[str]) -> str:
        return bytes.fromhex(match.group(0).replace("%", "")).decode("utf-8", "replace")

    return _PERCENT_RUN.sub(decode, text)


def _collect_scan_texts(value: Any) -> Tuple[List[_ScanText], bool]:
    texts: List[_ScanText] = []
    raws, incomplete = _collect_raw_texts(value)
    for raw in raws:
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
            incomplete = True
            continue
    return texts, incomplete


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
        hits, _incomplete = self._scan(value, surface)
        return hits

    def _scan(
        self, value: Any, surface: DecoySurface
    ) -> Tuple[List[DecoyHit], bool]:
        try:
            texts, incomplete = _collect_scan_texts(value)
        except Exception:
            texts = []
            incomplete = True
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
        return hits, incomplete

    def _notify_report_error(self, info: Dict[str, Any]) -> None:
        if self._on_report_error is None:
            return
        _run_bounded(lambda: self._on_report_error(info), self._report_timeout)

    def _post(
        self, path: str, body: Dict[str, Any], *, bounded: bool = True
    ) -> int:
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
        call = lambda: self._transport(
                self._v1_base + path,
                headers,
                payload,
                self._report_timeout,
            )
        if bounded:
            completed, result = _run_bounded(call, self._report_timeout)
            if not completed:
                raise result
        else:
            result = call()
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
                bounded=False,
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
        hits, incomplete = self._scan(value, surface)
        if hits:
            deadline = time.monotonic() + self._report_timeout
            report_states = (
                [
                    {"done": threading.Event(), "finished_at": None}
                    for _hit in hits
                ]
                if self._report
                else []
            )
            report_started = [threading.Event() for _hit in hits] if self._report else []
            completed = threading.Event()
            completion_lock = threading.Lock()
            task_count = len(report_states) + (len(hits) if self._on_leak else 0)
            remaining = task_count

            def mark_completed() -> None:
                nonlocal remaining
                with completion_lock:
                    remaining -= 1
                    if remaining == 0:
                        completed.set()

            def report_task(
                hit: DecoyHit, started: threading.Event, state: Dict[str, Any]
            ) -> None:
                started.set()
                try:
                    self._report_hit(hit)
                finally:
                    state["finished_at"] = time.monotonic()
                    state["done"].set()
                    mark_completed()

            def notify_leak(hit: DecoyHit) -> None:
                try:
                    result = self._on_leak(hit) if self._on_leak else None
                    if inspect.isawaitable(result):
                        asyncio.run(result)
                except BaseException:  # noqa: BLE001 - callbacks never escape
                    pass
                finally:
                    mark_completed()

            def start_workers(
                work: queue.Queue[Callable[[], None]], name: str
            ) -> None:
                def worker() -> None:
                    while True:
                        try:
                            task = work.get_nowait()
                        except queue.Empty:
                            return
                        task()

                for index in range(min(8, work.qsize())):
                    threading.Thread(
                        target=worker,
                        name=f"deny-decoy-{name}-{index}",
                        daemon=True,
                    ).start()

            report_work: queue.Queue[Callable[[], None]] = queue.Queue()
            for hit, started, state in zip(hits, report_started, report_states):
                report_work.put(
                    lambda hit=hit, started=started, state=state: report_task(
                        hit, started, state
                    )
                )
            start_workers(report_work, "report")

            if len(report_started) <= 8:
                for started in report_started:
                    started.wait(max(0.0, deadline - time.monotonic()))

            callback_work: queue.Queue[Callable[[], None]] = queue.Queue()
            if self._on_leak:
                for hit in hits:
                    callback_work.put(lambda hit=hit: notify_leak(hit))
            start_workers(callback_work, "callback")

            if task_count:
                completed.wait(max(0.0, deadline - time.monotonic()))
            for hit, state in zip(hits, report_states):
                finished_at = state["finished_at"]
                if finished_at is not None and finished_at <= deadline:
                    continue
                threading.Thread(
                    target=self._notify_report_error,
                    args=(
                        {
                            "fingerprint": hit.fingerprint,
                            "surface": hit.surface,
                            "error": "timeout",
                        },
                    ),
                    name="deny-decoy-report-timeout",
                    daemon=True,
                ).start()
        if self._block and hits:
            raise DenyDecoyLeakError(hits)
        if incomplete and not hits:
            if self._block:
                raise DenyToolError(
                    "deny_scan_limit",
                    "Value exceeds decoy scan limits and could not be checked.",
                )
            self._notify_report_error({"error": "scan_limit", "surface": surface})
        elif incomplete and not self._block:
            self._notify_report_error({"error": "scan_limit", "surface": surface})
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
    """Create a watch limited to depth 64, 100,000 nodes, and 8 MiB of text.

    Blocking watches fail closed when a limit prevents a complete clean scan.
    """
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
