"""Security-core tests for deny_sh_langchain. No network, no deny-sh SDK needed:
the vault client is injected."""

import json

import pytest

from deny_sh_langchain import (
    DenyLeakError,
    DenyToolError,
    create_vault_resolver,
    is_narrowed,
)

FAKE_SECRET = "sk_test_DENYFAKE_0000_not_a_real_key"


def fake_get(secret=FAKE_SECRET):
    calls = []

    def vg(label, password, **opts):
        calls.append({"label": label, "password": password, "opts": opts})
        return secret

    def vgbi(item_id, password, **opts):
        calls.append({"id": item_id, "password": password, "opts": opts})
        return secret

    return vg, vgbi, calls


def test_resolves_by_label_threads_args():
    vg, vgbi, calls = fake_get()
    seen = {}

    def use(secret, args):
        seen["secret"] = secret
        seen["args"] = args
        return {"ok": True}

    resolve = create_vault_resolver(
        use=use,
        label="stripe-prod",
        password="VAULT_PW",
        client_options={"api_key": "cs_test"},
        vault_get=vg,
        vault_get_by_id=vgbi,
    )
    out = resolve({"id": "in_1"})
    assert out == {"ok": True}
    assert seen["secret"] == FAKE_SECRET
    assert seen["args"] == {"id": "in_1"}
    assert calls[0] == {"label": "stripe-prod", "password": "VAULT_PW", "opts": {"api_key": "cs_test"}}


def test_resolves_by_id_skips_label_scan():
    vg, vgbi, calls = fake_get()
    resolve = create_vault_resolver(
        use=lambda s, a: {"ok": True},
        id="item_abc",
        password="pw",
        vault_get=vg,
        vault_get_by_id=vgbi,
    )
    resolve({})
    assert calls[0].get("id") == "item_abc"
    assert "label" not in calls[0]


def test_leak_sweep_string_fails_closed():
    vg, vgbi, _ = fake_get()
    resolve = create_vault_resolver(
        use=lambda secret, a: f"key={secret}",
        label="k",
        password="pw",
        vault_get=vg,
        vault_get_by_id=vgbi,
    )
    with pytest.raises(DenyLeakError):
        resolve({})


def test_leak_sweep_nested_and_key_fails_closed():
    vg, vgbi, _ = fake_get()
    r1 = create_vault_resolver(
        use=lambda secret, a: {"a": {"b": ["ok", secret]}},
        label="k", password="pw", vault_get=vg, vault_get_by_id=vgbi,
    )
    with pytest.raises(DenyLeakError):
        r1({})
    r2 = create_vault_resolver(
        use=lambda secret, a: {secret: "v"},
        label="k", password="pw", vault_get=vg, vault_get_by_id=vgbi,
    )
    with pytest.raises(DenyLeakError):
        r2({})


def test_narrowed_dto_passes():
    vg, vgbi, _ = fake_get()
    resolve = create_vault_resolver(
        use=lambda s, a: {"id": "in_1", "status": "paid"},
        label="k", password="pw", vault_get=vg, vault_get_by_id=vgbi,
    )
    assert resolve({}) == {"id": "in_1", "status": "paid"}


def test_leak_sweep_opt_out():
    vg, vgbi, _ = fake_get()
    resolve = create_vault_resolver(
        use=lambda secret, a: {"leaked": secret},
        label="k", password="pw", leak_sweep=False,
        vault_get=vg, vault_get_by_id=vgbi,
    )
    assert resolve({}) == {"leaked": FAKE_SECRET}


def test_use_exception_scrubbed():
    vg, vgbi, _ = fake_get()

    def use(secret, a):
        raise RuntimeError(f"upstream rejected {secret} loudly")

    resolve = create_vault_resolver(
        use=use, label="k", password="pw", vault_get=vg, vault_get_by_id=vgbi,
    )
    with pytest.raises(DenyToolError) as ei:
        resolve({})
    assert ei.value.code == "deny_use_failed"
    assert FAKE_SECRET not in str(ei.value)
    assert "[deny:redacted]" in str(ei.value)


def test_vault_failure_scrubbed_of_password():
    def vg(label, password, **opts):
        e = RuntimeError("boom for password hunter2")
        e.code = "vault_not_found"
        raise e

    def vgbi(*a, **k):
        raise RuntimeError("nope")

    resolve = create_vault_resolver(
        use=lambda s, a: {"ok": True},
        label="k", password="hunter2", vault_get=vg, vault_get_by_id=vgbi,
    )
    with pytest.raises(DenyToolError) as ei:
        resolve({})
    assert ei.value.code == "vault_not_found"
    assert "hunter2" not in str(ei.value)


def test_config_validation():
    with pytest.raises(DenyToolError):
        create_vault_resolver(use=lambda s, a: {}, password="pw")
    with pytest.raises(DenyToolError):
        create_vault_resolver(use=lambda s, a: {}, label="a", id="b", password="pw")


def test_is_narrowed_helper():
    assert is_narrowed({"id": "x"}, FAKE_SECRET) is True
    assert is_narrowed({"leaked": FAKE_SECRET}, FAKE_SECRET) is False
    assert is_narrowed(f"x {FAKE_SECRET}", FAKE_SECRET) is False


# --- Adversarial leak-sweep carriers (pre-publish wide audit 2026-06-10) ----
# Each hides the raw secret in a shape the original sweep missed. The resolver
# MUST fail closed (DenyLeakError) for every one.

def _expect_leak(dto_factory):
    vg, vgbi, _ = fake_get()
    resolve = create_vault_resolver(
        use=lambda secret, a: dto_factory(secret),
        label="k", password="pw", vault_get=vg, vault_get_by_id=vgbi,
    )
    with pytest.raises(DenyLeakError):
        resolve({})


def test_leak_sweep_object_attribute_fails_closed():
    class Carrier:
        def __init__(self, secret):
            self.ok = True
            self.token = secret

    _expect_leak(lambda s: Carrier(s))


def test_leak_sweep_slots_attribute_fails_closed():
    class Slotted:
        __slots__ = ("token",)

        def __init__(self, secret):
            self.token = secret

    _expect_leak(lambda s: Slotted(s))


def test_leak_sweep_property_getter_fails_closed():
    class LazyCarrier:
        def __init__(self, secret):
            self._s = secret

        @property
        def token(self):
            return self._s

    _expect_leak(lambda s: LazyCarrier(s))


def test_leak_sweep_bytes_carrier_fails_closed():
    _expect_leak(lambda s: {"ok": True, "blob": s.encode("utf-8")})


def test_leak_sweep_memoryview_carrier_fails_closed():
    _expect_leak(lambda s: {"ok": True, "blob": memoryview(s.encode("utf-8"))})


def test_leak_sweep_array_carrier_fails_closed():
    import array

    _expect_leak(lambda s: {"ok": True, "blob": array.array("B", s.encode("utf-8"))})
