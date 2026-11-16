import asyncio

import pytest
from langchain_core.messages import AIMessage
from langchain_core.runnables import RunnableLambda
from langchain_core.tools import tool

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
