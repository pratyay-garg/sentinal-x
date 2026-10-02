import sys

import pytest

from app.core.subprocess_utils import ToolNotFoundError, run_tool


@pytest.mark.asyncio
async def test_partial_output_is_preserved_when_a_tool_overruns_its_timeout():
    # Emits a line, then blocks past the deadline — mirrors a scanner that has
    # already streamed findings when it is killed at the timeout boundary.
    script = "import sys,time; sys.stdout.write('finding-1\\n'); sys.stdout.flush(); time.sleep(30)"
    result = await run_tool([sys.executable, "-c", script], timeout=1)
    assert result.timed_out is True
    assert b"finding-1" in result.stdout


@pytest.mark.asyncio
async def test_stdin_payload_is_delivered_and_output_returned():
    script = "import sys; data=sys.stdin.read(); sys.stdout.write(data.upper())"
    result = await run_tool([sys.executable, "-c", script], timeout=10,
                            input_data=b"abc")
    assert result.timed_out is False
    assert result.stdout == b"ABC"


@pytest.mark.asyncio
async def test_missing_binary_raises_tool_not_found():
    with pytest.raises(ToolNotFoundError):
        await run_tool(["definitely-not-a-real-binary-xyz"], timeout=5)


@pytest.mark.asyncio
async def test_large_single_line_exceeding_stream_limit_is_not_truncated():
    # A JSONL record can exceed StreamReader's 64 KiB line limit; chunked reads
    # must return it whole instead of aborting the pass.
    size = 200_000
    script = f"import sys; sys.stdout.write('x'*{size})"
    result = await run_tool([sys.executable, "-c", script], timeout=10)
    assert len(result.stdout) == size
