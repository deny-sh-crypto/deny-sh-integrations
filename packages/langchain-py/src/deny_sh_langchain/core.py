"""Framework-agnostic vault-entry-as-tool resolver for deny.sh (Python).

Mirrors @deny-sh/integrations-core. The security contract:

1. The credential is resolved from the deny.sh managed vault and decrypted
   inside this resolver, server-side, via the `deny-sh` SDK.
2. The user's `use(secret, args)` callback is the only place the plaintext
   credential exists. It makes the privileged call and returns a narrowed DTO.
3. The DTO is leak-swept before it is returned. If the raw secret is found
   anywhere in it, the resolver FAILS CLOSED: it raises and returns nothing.
"""

from __future__ import annotations

from typing import Any, Callable, Optional


class DenyToolError(Exception):
    """Vault fetch failed or use() raised. Secret-scrubbed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class DenyLeakError(Exception):
    """Fail-closed leak sweep: the returned DTO contained the raw secret."""

    code = "deny_secret_leak"


def _contains_secret(value: Any, secret: str, seen: set[int]) -> bool:
    """Recursively scan a value for the raw secret."""
    if not secret:
        return False
    if value is None:
        return False
    if isinstance(value, str):
        return secret in value
    if isinstance(value, (bytes, bytearray)):
        try:
            return secret in value.decode("utf-8", "ignore")
        except Exception:
            return False
    if isinstance(value, (int, float, bool)):
        return secret in str(value)
    obj_id = id(value)
    if obj_id in seen:
        return False
    seen.add(obj_id)
    if isinstance(value, dict):
        for k, v in value.items():
            if _contains_secret(k, secret, seen):
                return True
            if _contains_secret(v, secret, seen):
                return True
        return False
    if isinstance(value, (list, tuple, set, frozenset)):
        for el in value:
            if _contains_secret(el, secret, seen):
                return True
        return False
    # Fallback: any object whose repr/str renders the secret.
    try:
        if secret in str(value):
            return True
    except Exception:
        pass
    return False


def _scrub(text: str, secret: str) -> str:
    if not secret:
        return text
    return text.replace(secret, "[deny:redacted]")


def create_vault_resolver(
    *,
    use: Callable[[str, Any], Any],
    label: Optional[str] = None,
    id: Optional[str] = None,  # noqa: A002 - mirrors the JS API shape
    password: str,
    client_options: Optional[dict] = None,
    leak_sweep: bool = True,
    vault_get: Optional[Callable[..., str]] = None,
    vault_get_by_id: Optional[Callable[..., str]] = None,
) -> Callable[[Any], Any]:
    """Build the resolver. The returned callable takes the validated tool args
    and returns the narrowed DTO. It never returns or raises the raw secret.

    `vault_get` / `vault_get_by_id` default to the real `deny_sh` SDK functions
    and are injectable for testing.
    """
    if label is None and id is None:
        raise DenyToolError("deny_config_error", "Provide either `label` or `id`.")
    if label is not None and id is not None:
        raise DenyToolError("deny_config_error", "Provide only ONE of `label` or `id`.")
    if not password or not isinstance(password, str):
        raise DenyToolError("deny_config_error", "`password` is required.")
    if not callable(use):
        raise DenyToolError("deny_config_error", "`use(secret, args)` is required.")

    if vault_get is None or vault_get_by_id is None:
        # Imported lazily so the package imports even if deny-sh isn't yet on the
        # path at definition time (it is a hard dependency at runtime).
        from deny_sh import vault_get as _vg, vault_get_by_id as _vgbi

        vault_get = vault_get or _vg
        vault_get_by_id = vault_get_by_id or _vgbi

    opts = dict(client_options or {})

    def resolve(args: Any) -> Any:
        try:
            if id is not None:
                secret = vault_get_by_id(id, password, **opts)
            else:
                secret = vault_get(label, password, **opts)
        except Exception as err:  # noqa: BLE001
            code = getattr(err, "code", "vault_error")
            raise DenyToolError(code, _scrub(str(err), password)) from None

        try:
            result = use(secret, args)
        except Exception as err:  # noqa: BLE001
            raise DenyToolError("deny_use_failed", _scrub(str(err), secret)) from None

        if leak_sweep and _contains_secret(result, secret, set()):
            raise DenyLeakError(
                "The value returned by use() contained the raw credential. "
                "Return a narrowed DTO that excludes the secret. "
                "(deny.sh leak sweep, fail-closed)"
            )
        return result

    return resolve


def is_narrowed(value: Any, secret: str) -> bool:
    """True if `value` would pass the leak sweep for `secret`."""
    return not _contains_secret(value, secret, set())
