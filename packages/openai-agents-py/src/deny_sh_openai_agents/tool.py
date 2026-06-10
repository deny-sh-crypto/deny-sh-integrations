"""OpenAI Agents SDK FunctionTool wrapper around the deny.sh vault resolver."""

from __future__ import annotations

import json
from typing import Any, Callable, Optional, Type

from .core import create_vault_resolver


def deny_vault_tool(
    *,
    name: str,
    description: str,
    use: Callable[[str, Any], Any],
    args_schema: Type,
    label: Optional[str] = None,
    id: Optional[str] = None,  # noqa: A002 - mirrors the JS API shape
    password: str,
    client_options: Optional[dict] = None,
    leak_sweep: bool = True,
    vault_get: Optional[Callable[..., str]] = None,
    vault_get_by_id: Optional[Callable[..., str]] = None,
):
    """Build an OpenAI Agents SDK ``FunctionTool`` that resolves a deny.sh vault
    entry inside the tool boundary and returns a narrowed DTO to the model.

    ``args_schema`` is a pydantic ``BaseModel`` describing the tool args. The
    SDK validates the model's tool call against the schema before ``use`` runs.
    The tool returns the narrowed DTO (a JSON string of the dict, or the raw
    string if ``use`` already returns one).

        from pydantic import BaseModel
        from deny_sh_openai_agents import deny_vault_tool

        class InvoiceArgs(BaseModel):
            id: str

        invoice_tool = deny_vault_tool(
            label="stripe-prod",
            password=os.environ["VAULT_PW"],
            name="get_invoice",
            description="Look up a Stripe invoice by id",
            args_schema=InvoiceArgs,
            use=lambda secret, args: {...},   # narrowed DTO
        )

        agent = Agent(name="Billing", tools=[invoice_tool])
    """
    from agents import FunctionTool

    resolve = create_vault_resolver(
        use=use,
        label=label,
        id=id,
        password=password,
        client_options=client_options,
        leak_sweep=leak_sweep,
        vault_get=vault_get,
        vault_get_by_id=vault_get_by_id,
    )

    async def _on_invoke_tool(_ctx: Any, input_str: str) -> str:
        # The SDK hands us the model's tool-call args as a JSON string. Validate
        # through the pydantic schema, then run the privileged resolver. Returns
        # a JSON string (or the raw string the resolver returned).
        raw = json.loads(input_str) if input_str else {}
        validated = args_schema(**raw)
        # model_dump() (pydantic v2) preserves the validated/coerced values.
        args = validated.model_dump() if hasattr(validated, "model_dump") else dict(raw)
        dto = resolve(args)
        if isinstance(dto, str):
            return dto
        return json.dumps(dto)

    return FunctionTool(
        name=name,
        description=description,
        params_json_schema=args_schema.model_json_schema(),
        on_invoke_tool=_on_invoke_tool,
    )
