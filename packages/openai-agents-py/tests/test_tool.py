"""Integration tests for the OpenAI Agents SDK FunctionTool wrapper.

These exercise the real `agents.FunctionTool` surface (name, params schema, and
the async `on_invoke_tool(ctx, input_json)` the runtime calls). Skipped cleanly
if the optional `openai-agents` SDK + pydantic are not installed."""

import asyncio
import json

import pytest

pytest.importorskip("agents")
pytest.importorskip("pydantic")

from pydantic import BaseModel  # noqa: E402

from deny_sh_openai_agents import DenyLeakError, deny_vault_tool  # noqa: E402

FAKE_SECRET = "sk_test_DENYFAKE_0000_not_a_real_key"


class InvoiceArgs(BaseModel):
    id: str


def fake_get(secret=FAKE_SECRET):
    calls = []

    def vg(label, password, **opts):
        calls.append({"label": label, "password": password, "opts": opts})
        return secret

    def vgbi(item_id, password, **opts):
        calls.append({"id": item_id, "password": password, "opts": opts})
        return secret

    return vg, vgbi, calls


def _invoke(tool, payload):
    return asyncio.run(tool.on_invoke_tool(None, json.dumps(payload)))


def test_builds_function_tool_with_schema():
    vg, vgbi, _ = fake_get()
    tool = deny_vault_tool(
        name="get_invoice",
        description="Look up a Stripe invoice by id",
        label="stripe-prod",
        password="pw",
        args_schema=InvoiceArgs,
        use=lambda s, a: {"ok": True},
        vault_get=vg,
        vault_get_by_id=vgbi,
    )
    assert tool.name == "get_invoice"
    assert tool.description == "Look up a Stripe invoice by id"
    # params_json_schema is the pydantic-derived JSON schema.
    assert "id" in tool.params_json_schema.get("properties", {})


def test_invoke_resolves_in_boundary_returns_narrowed_dto():
    vg, vgbi, calls = fake_get()
    seen = {}

    def use(secret, args):
        seen["secret"] = secret
        seen["args"] = args
        return {"id": args["id"], "status": "paid"}

    tool = deny_vault_tool(
        name="get_invoice",
        description="d",
        label="stripe-prod",
        password="VAULT_PW",
        args_schema=InvoiceArgs,
        use=use,
        vault_get=vg,
        vault_get_by_id=vgbi,
    )
    out = _invoke(tool, {"id": "in_1"})
    assert json.loads(out) == {"id": "in_1", "status": "paid"}
    assert seen["secret"] == FAKE_SECRET
    assert seen["args"] == {"id": "in_1"}
    assert FAKE_SECRET not in out
    assert calls[0] == {"label": "stripe-prod", "password": "VAULT_PW", "opts": {}}


def test_invoke_fail_closed_on_leak():
    vg, vgbi, _ = fake_get()
    tool = deny_vault_tool(
        name="leaky",
        description="d",
        label="k",
        password="pw",
        args_schema=InvoiceArgs,
        use=lambda secret, a: {"key": secret},
        vault_get=vg,
        vault_get_by_id=vgbi,
    )
    with pytest.raises(DenyLeakError):
        _invoke(tool, {"id": "x"})


def test_invoke_by_id_skips_label_scan():
    vg, vgbi, calls = fake_get()
    tool = deny_vault_tool(
        name="by_id",
        description="d",
        id="item_abc",
        password="pw",
        args_schema=InvoiceArgs,
        use=lambda s, a: {"ok": True},
        vault_get=vg,
        vault_get_by_id=vgbi,
    )
    _invoke(tool, {"id": "x"})
    assert calls[0].get("id") == "item_abc"
    assert "label" not in calls[0]


def test_client_options_forwarded():
    vg, vgbi, calls = fake_get()
    tool = deny_vault_tool(
        name="tenant_tool",
        description="d",
        label="stripe-prod",
        password="tenant_pw",
        client_options={"api_key": "cs_tenant_42"},
        args_schema=InvoiceArgs,
        use=lambda s, a: {"ok": True},
        vault_get=vg,
        vault_get_by_id=vgbi,
    )
    _invoke(tool, {"id": "x"})
    assert calls[0] == {
        "label": "stripe-prod",
        "password": "tenant_pw",
        "opts": {"api_key": "cs_tenant_42"},
    }


def test_string_dto_passthrough():
    vg, vgbi, _ = fake_get()
    tool = deny_vault_tool(
        name="strtool",
        description="d",
        label="k",
        password="pw",
        args_schema=InvoiceArgs,
        use=lambda s, a: "already-narrowed-string",
        vault_get=vg,
        vault_get_by_id=vgbi,
    )
    out = _invoke(tool, {"id": "x"})
    assert out == "already-narrowed-string"
