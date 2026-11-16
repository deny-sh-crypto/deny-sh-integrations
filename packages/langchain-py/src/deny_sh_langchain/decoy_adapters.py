"""LangChain Runnable and tool adapters for the decoy watch."""

from __future__ import annotations

from typing import Any

from .decoy import DecoyWatch


def decoy_watch_output_runnable(watch: DecoyWatch):
    """Return a Runnable step that blocks decoys in final model output."""
    from langchain_core.runnables import RunnableLambda

    def check_output(value: Any) -> Any:
        watch.check(value, "model_output")
        return value

    async def acheck_output(value: Any) -> Any:
        await watch.acheck(value, "model_output")
        return value

    return RunnableLambda(
        check_output,
        afunc=acheck_output,
        name="deny_decoy_watch_output",
    )


def decoy_watch_tool(tool: Any, watch: DecoyWatch):
    """Return a StructuredTool that checks arguments before delegating."""
    from langchain_core.tools import StructuredTool

    def invoke_wrapped(**kwargs: Any) -> Any:
        watch.check(kwargs, "tool_args")
        return tool.invoke(kwargs)

    async def ainvoke_wrapped(**kwargs: Any) -> Any:
        await watch.acheck(kwargs, "tool_args")
        return await tool.ainvoke(kwargs)

    return StructuredTool.from_function(
        func=invoke_wrapped,
        coroutine=ainvoke_wrapped,
        name=tool.name,
        description=tool.description,
        return_direct=tool.return_direct,
        args_schema=tool.args_schema,
        infer_schema=False,
        response_format=tool.response_format,
        tags=tool.tags,
        metadata=tool.metadata,
    )


__all__ = ["decoy_watch_output_runnable", "decoy_watch_tool"]
