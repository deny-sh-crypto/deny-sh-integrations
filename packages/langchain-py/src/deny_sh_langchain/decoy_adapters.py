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
    """Return a copy that checks raw arguments before normal tool validation."""

    class WatchedTool(type(tool)):
        def run(self, tool_input: Any, *args: Any, **kwargs: Any) -> Any:
            watch.check(tool_input, "tool_args")
            return super().run(tool_input, *args, **kwargs)

        async def arun(self, tool_input: Any, *args: Any, **kwargs: Any) -> Any:
            await watch.acheck(tool_input, "tool_args")
            return await super().arun(tool_input, *args, **kwargs)

    wrapped = tool.model_copy()
    wrapped.__class__ = WatchedTool
    return wrapped


__all__ = ["decoy_watch_output_runnable", "decoy_watch_tool"]
