import asyncio

import pytest
from agents import (
    Agent,
    OutputGuardrailTripwireTriggered,
    Runner,
    ToolInputGuardrailTripwireTriggered,
    function_tool,
)
from agents.testing import ScriptedModel, assistant_message, function_call

from deny_sh_openai_agents import (
    create_decoy_watch,
    decoy_watch_output_guardrail,
    decoy_watch_tool_input_guardrail,
)


DECOY = "decoy-value-1234"


def test_decoy_in_final_output_stops_real_sdk_run():
    watch = create_decoy_watch([DECOY], report=False)
    model = ScriptedModel([[assistant_message("result: " + DECOY)]])
    agent = Agent(
        name="test",
        model=model,
        output_guardrails=[decoy_watch_output_guardrail(watch)],
    )
    with pytest.raises(OutputGuardrailTripwireTriggered) as error:
        asyncio.run(Runner.run(agent, "go"))
    assert DECOY not in str(error.value)
    model.assert_complete()


def test_clean_final_output_completes_real_sdk_run():
    watch = create_decoy_watch([DECOY], report=False)
    model = ScriptedModel([[assistant_message("clean result")]])
    agent = Agent(
        name="test",
        model=model,
        output_guardrails=[decoy_watch_output_guardrail(watch)],
    )
    result = asyncio.run(Runner.run(agent, "go"))
    assert result.final_output == "clean result"
    model.assert_complete()


def test_decoy_tool_arguments_stop_before_tool_execution():
    watch = create_decoy_watch([DECOY], report=False)
    counter = {"calls": 0}

    @function_tool(
        tool_input_guardrails=[decoy_watch_tool_input_guardrail(watch)]
    )
    def echo(value: str) -> str:
        """Echo a value."""
        counter["calls"] += 1
        return value

    model = ScriptedModel(
        [[function_call("echo", {"value": DECOY}, call_id="call-decoy")]]
    )
    agent = Agent(name="test", model=model, tools=[echo])
    with pytest.raises(ToolInputGuardrailTripwireTriggered) as error:
        asyncio.run(Runner.run(agent, "go"))
    assert counter["calls"] == 0
    assert DECOY not in str(error.value)
    model.assert_complete()


def test_clean_tool_arguments_execute_once():
    watch = create_decoy_watch([DECOY], report=False)
    counter = {"calls": 0}

    @function_tool(
        tool_input_guardrails=[decoy_watch_tool_input_guardrail(watch)]
    )
    def echo(value: str) -> str:
        """Echo a value."""
        counter["calls"] += 1
        return value

    model = ScriptedModel(
        [
            [function_call("echo", {"value": "clean"}, call_id="call-clean")],
            [assistant_message("done")],
        ]
    )
    agent = Agent(name="test", model=model, tools=[echo])
    result = asyncio.run(Runner.run(agent, "go"))
    assert result.final_output == "done"
    assert counter["calls"] == 1
    model.assert_complete()
