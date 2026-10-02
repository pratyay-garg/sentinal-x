"""
Every external tool invocation in this codebase goes through run_tool().
Do not call asyncio.create_subprocess_exec directly from a pipeline stage —
this wrapper is what makes the process-group-kill guarantee in
app/killswitch.py actually work, and it's the one place timeout/argv-safety
discipline is enforced.

IMPLEMENTATION_SPEC_v4.md §5: "asyncio.create_subprocess_exec with an argv
list, never shell=True; start_new_session=True so every tool gets its own
process group; on timeout/cancel, kill the process group, never just the
parent PID."
"""
from __future__ import annotations

import asyncio
import dataclasses
import logging
import os
import signal
import tempfile

logger = logging.getLogger(__name__)


class ToolNotFoundError(RuntimeError):
    """The binary itself is missing — a broken image, not a transient
    failure. Fail the whole job immediately; don't retry."""


class ToolExecutionError(RuntimeError):
    """The tool ran but failed/timed out. Degrade the owning stage only —
    log a warning to scan_runs.coverage and continue the pipeline."""


@dataclasses.dataclass
class ToolResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False


async def _drain(stream: asyncio.StreamReader | None, sink: list[bytes]) -> None:
    """Copy a pipe into `sink` in fixed chunks.

    Chunked reads (not line iteration) are deliberate: a scanner like Nuclei
    can emit a single JSONL record far larger than StreamReader's default line
    limit, and a `-silent` run must never abort on `LimitOverrunError`. The
    incremental buffer is also what lets a timed-out or cancelled tool still
    return every byte it produced before it was killed.
    """
    if stream is None:
        return
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            break
        sink.append(chunk)


async def _wait_for_returncode(proc: asyncio.subprocess.Process, timeout: float) -> None:
    """Wait without cancelling asyncio's fragile Process.wait future."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while proc.returncode is None:
        if loop.time() >= deadline:
            raise asyncio.TimeoutError
        await asyncio.sleep(min(0.05, max(0.001, deadline - loop.time())))


async def run_tool(argv: list[str], *, timeout: float, input_data: bytes | None = None) -> ToolResult:
    """Run one external tool. argv[0] must be an absolute path or resolvable
    via PATH; never build argv by string-formatting user input into a shell
    string. Kills the whole process group on timeout, not just the child.

    Stdout/stderr are drained incrementally so that a tool which overruns its
    timeout still returns the partial output it had already streamed. For a
    long DAST/signature scan this is the difference between "killed at the
    deadline with zero findings" and "killed at the deadline but every result
    produced so far is kept".
    """
    input_stream = None
    try:
        if input_data is not None:
            # A regular anonymous file gives stdin-driven tools immediate,
            # deterministic EOF. asyncio's subprocess PIPE writer can leave a
            # child blocked on EOF depending on child-watcher scheduling,
            # making completed scans appear to time out. TemporaryFile is
            # unlinked by the OS and never exposes a pathname.
            input_stream = tempfile.TemporaryFile()
            input_stream.write(input_data)
            input_stream.seek(0)
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=input_stream if input_stream is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,  # own process group — required for the kill below to work
        )
    except FileNotFoundError as exc:
        raise ToolNotFoundError(f"binary not found: {argv[0]}") from exc
    finally:
        if input_stream is not None:
            input_stream.close()

    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    drain_out = asyncio.ensure_future(_drain(proc.stdout, stdout_chunks))
    drain_err = asyncio.ensure_future(_drain(proc.stderr, stderr_chunks))

    try:
        await _wait_for_returncode(proc, timeout)
        await asyncio.gather(drain_out, drain_err, return_exceptions=True)
        return ToolResult(
            returncode=proc.returncode or 0,
            stdout=b"".join(stdout_chunks),
            stderr=b"".join(stderr_chunks),
        )
    except asyncio.TimeoutError:
        _kill_group(proc)
        # The SIGKILL closes the pipes; let the drains read whatever the kernel
        # still had buffered, then return it as a partial result.
        try:
            await asyncio.wait_for(
                asyncio.gather(_wait_for_returncode(proc, 5), drain_out, drain_err,
                               return_exceptions=True), timeout=5
            )
        except Exception:
            pass
        logger.warning("tool timed out and was killed (partial output kept): %s", argv[0])
        return ToolResult(
            returncode=-1,
            stdout=b"".join(stdout_chunks),
            stderr=b"".join(stderr_chunks) or b"timeout",
            timed_out=True,
        )
    except asyncio.CancelledError:
        # Job was cancelled (killswitch/per-job cancel) mid-call — still must
        # not leak the process tree.
        _kill_group(proc)
        for task in (drain_out, drain_err):
            task.cancel()
        raise


def _kill_group(proc: asyncio.subprocess.Process) -> None:
    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass
