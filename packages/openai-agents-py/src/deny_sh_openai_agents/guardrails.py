"""OpenAI Agents SDK adapters for the framework-neutral decoy watch.

Tool-input guardrails require openai-agents 0.3.3 or newer.
"""

from __future__ import annotations

from typing import Any

from .decoy import DecoyWatch, DenyDecoyLeakError


def decoy_watch_output_guardrail(watch: DecoyWatch):
    """Return an SDK output guardrail that checks final agent output."""
    from agents import GuardrailFunctionOutput, output_guardrail

    @output_guardrail(name="deny_decoy_watch_output")
    async def guardrail(_context: Any, _agent: Any, agent_output: Any):
        try:
            hits = await watch.acheck(agent_output, "model_output")
            return GuardrailFunctionOutput(
                output_info={"hits": hits}, tripwire_triggered=False
            )
        except DenyDecoyLeakError as error:
            return GuardrailFunctionOutput(
                output_info={"hits": error.hits},
                tripwire_triggered=True,
            )

    return guardrail


def decoy_watch_tool_input_guardrail(watch: DecoyWatch):
    """Return an SDK tool-input guardrail that checks raw call arguments."""
    from agents import ToolGuardrailFunctionOutput, tool_input_guardrail

    @tool_input_guardrail(name="deny_decoy_watch_tool_args")
    async def guardrail(data: Any):
        arguments = data.context.tool_arguments
        try:
            hits = await watch.acheck(arguments, "tool_args")
            return ToolGuardrailFunctionOutput.allow({"hits": hits})
        except DenyDecoyLeakError as error:
            return ToolGuardrailFunctionOutput.raise_exception(
                {"hits": error.hits}
            )

    return guardrail


__all__ = [
    "decoy_watch_output_guardrail",
    "decoy_watch_tool_input_guardrail",
]
