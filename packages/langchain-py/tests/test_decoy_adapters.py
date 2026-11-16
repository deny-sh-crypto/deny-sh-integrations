import asyncio
from typing import Annotated

import pytest
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.runnables import RunnableLambda
from langchain_core.tools import InjectedToolArg, ToolException, tool
from pydantic import BaseModel, field_validator

from deny_sh_langchain import (
    DenyDecoyLeakError,
    create_decoy_watch,
    decoy_watch_output_runnable,
    decoy_watch_tool,
)


DECOY = "decoy-value-1234"


def test_decoy_in_final_output_stops_runnable_pipeline():
    watch = create_decoy_watch([DECOY], report=False)
    fake_model = RunnableLambda(lambda _input: AIMessage(content="result: " + DECOY))
    chain = fake_model | decoy_watch_output_runnable(watch)
    with pytest.raises(DenyDecoyLeakError) as error:
        chain.invoke("go")
    assert DECOY not in str(error.value)


def test_clean_final_output_completes_runnable_pipeline():
    watch = create_decoy_watch([DECOY], report=False)
    fake_model = RunnableLambda(lambda _input: AIMessage(content="clean result"))
    chain = fake_model | decoy_watch_output_runnable(watch)
    result = chain.invoke("go")
    assert result.content == "clean result"


def test_async_output_runnable_blocks():
    watch = create_decoy_watch([DECOY], report=False)
    runnable = decoy_watch_output_runnable(watch)
    with pytest.raises(DenyDecoyLeakError):
        asyncio.run(runnable.ainvoke(AIMessage(content=DECOY)))


def test_decoy_tool_arguments_stop_before_tool_execution():
    watch = create_decoy_watch([DECOY], report=False)
    counter = {"calls": 0}

    @tool
    def echo(value: str) -> str:
        """Echo a value."""
        counter["calls"] += 1
        return value

    wrapped = decoy_watch_tool(echo, watch)
    with pytest.raises(DenyDecoyLeakError) as error:
        wrapped.invoke({"value": DECOY})
    assert counter["calls"] == 0
    assert DECOY not in str(error.value)


def test_clean_tool_arguments_execute_once():
    watch = create_decoy_watch([DECOY], report=False)
    counter = {"calls": 0}

    @tool
    def echo(value: str) -> str:
        """Echo a value."""
        counter["calls"] += 1
        return value

    wrapped = decoy_watch_tool(echo, watch)
    assert wrapped.invoke({"value": "clean"}) == "clean"
    assert counter["calls"] == 1


def test_tool_call_decoy_blocks_execution():
    watch = create_decoy_watch([DECOY], report=False)
    counter = {"calls": 0}

    @tool
    def echo(value: str) -> str:
        """Echo a value."""
        counter["calls"] += 1
        return value

    wrapped = decoy_watch_tool(echo, watch)
    tool_call = {
        "name": echo.name,
        "args": {"value": DECOY},
        "id": "call-1",
        "type": "tool_call",
    }
    with pytest.raises(DenyDecoyLeakError):
        wrapped.invoke(tool_call)
    assert counter["calls"] == 0


def test_invalid_decoy_skips_tool_error_callback():
    errors = []

    class Handler(BaseCallbackHandler):
        def on_tool_error(self, error, **_kwargs):
            errors.append(error)

    @tool
    def echo(value: int) -> str:
        """Echo a numeric value."""
        return str(value)

    echo.callbacks = [Handler()]
    wrapped = decoy_watch_tool(echo, create_decoy_watch([DECOY], report=False))
    with pytest.raises(DenyDecoyLeakError) as error:
        wrapped.invoke({"value": DECOY})
    assert DECOY not in str(error.value)
    assert errors == []


def test_tool_schema_validator_runs_once():
    validations = {"count": 0}

    class Args(BaseModel):
        value: str

        @field_validator("value")
        @classmethod
        def count_validation(cls, value):
            validations["count"] += 1
            return value

    @tool(args_schema=Args)
    def echo(value: str) -> str:
        """Echo a value."""
        return value

    wrapped = decoy_watch_tool(echo, create_decoy_watch([DECOY], report=False))
    assert wrapped.invoke({"value": "clean"}) == "clean"
    assert validations["count"] == 1


def test_artifact_tool_keeps_tool_call_output():
    @tool(response_format="content_and_artifact")
    def artifact(value: str):
        """Return content and artifact."""
        return "content:" + value, {"raw": value}

    wrapped = decoy_watch_tool(
        artifact, create_decoy_watch([DECOY], report=False)
    )
    result = wrapped.invoke(
        {
            "name": artifact.name,
            "args": {"value": "clean"},
            "id": "call-2",
            "type": "tool_call",
        }
    )
    assert isinstance(result, ToolMessage)
    assert result.content == "content:clean"
    assert result.artifact == {"raw": "clean"}
    assert result.tool_call_id == "call-2"


def test_tool_error_and_validation_handlers_are_preserved():
    @tool
    def fails(value: str) -> str:
        """Raise a tool error."""
        raise ToolException("handled")

    fails.handle_tool_error = True
    wrapped = decoy_watch_tool(fails, create_decoy_watch([DECOY], report=False))
    assert wrapped.invoke({"value": "clean"}) == "handled"

    @tool
    def validates(value: int) -> str:
        """Validate numeric input."""
        return str(value)

    validates.handle_validation_error = True
    wrapped_validation = decoy_watch_tool(
        validates, create_decoy_watch([DECOY], report=False)
    )
    assert wrapped_validation.invoke({"value": "not-a-number"}) == (
        "Tool input validation error"
    )


def test_injected_argument_schema_and_execution_are_preserved():
    @tool
    def combine(value: str, secret: Annotated[str, InjectedToolArg]) -> str:
        """Combine visible and injected values."""
        return value + ":" + secret

    wrapped = decoy_watch_tool(combine, create_decoy_watch([DECOY], report=False))
    properties = wrapped.tool_call_schema.model_json_schema()["properties"]
    assert "value" in properties
    assert "secret" not in properties
    assert wrapped.invoke({"value": "clean", "secret": "injected"}) == (
        "clean:injected"
    )


def test_wrapped_tool_preserves_original_type_and_async_path():
    counter = {"calls": 0}

    @tool
    def echo(value: str) -> str:
        """Echo a value."""
        counter["calls"] += 1
        return value

    wrapped = decoy_watch_tool(echo, create_decoy_watch([DECOY], report=False))
    assert isinstance(wrapped, type(echo))
    assert asyncio.run(wrapped.ainvoke({"value": "clean"})) == "clean"
    with pytest.raises(DenyDecoyLeakError):
        asyncio.run(wrapped.ainvoke({"value": DECOY}))
    assert counter["calls"] == 1
