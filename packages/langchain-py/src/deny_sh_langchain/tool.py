"""LangChain StructuredTool wrapper around the deny.sh vault resolver."""

from __future__ import annotations

import json
from typing import Any, Callable, Optional, Type

from .core import create_vault_resolver


def deny_vault_tool(
    *,
    name: str,
    description: str,
    use: Callable[[str, Any], Any],
    label: Optional[str] = None,
    id: Optional[str] = None,  # noqa: A002 - mirrors the JS API shape
    password: str,
    args_schema: Optional[Type] = None,
    client_options: Optional[dict] = None,
    leak_sweep: bool = True,
    vault_get: Optional[Callable[..., str]] = None,
    vault_get_by_id: Optional[Callable[..., str]] = None,
):
    """Build a LangChain StructuredTool that resolves a deny.sh vault entry
    inside the tool boundary and returns a narrowed DTO to the agent.

    `args_schema` is a pydantic BaseModel describing the tool args (LangChain
    validates against it before `use` runs). The tool returns a JSON string of
    the narrowed DTO (or the raw string, if `use` already returns one).
    """
    from langchain_core.tools import StructuredTool

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

    def _run(**kwargs: Any) -> str:
        dto = resolve(kwargs)
        if isinstance(dto, str):
            return dto
        return json.dumps(dto)

    return StructuredTool.from_function(
        func=_run,
        name=name,
        description=description,
        args_schema=args_schema,
    )
