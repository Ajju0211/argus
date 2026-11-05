"""Hardened Process Execution Subsystem for ARGUS.

Executes external security tool commands in an isolated subprocess group
with strict timeouts, non-zero return code capture, and zombie process prevention.
"""

import asyncio
import os
import signal
import sys

# Maximum raw output limit to prevent out-of-memory denial of service (50 MB)
MAX_STDOUT_BYTES = 50 * 1024 * 1024


def kill_process_group(pid: int) -> None:
    """Deterministically terminates an entire process group to prevent zombie processes (S-07)."""
    if sys.platform == "win32":
        import subprocess

        subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], check=False)
        return

    try:
        pgid = os.getpgid(pid)
        os.killpg(pgid, signal.SIGTERM)
    except (ProcessLookupError, OSError):
        return

    try:
        import time

        time.sleep(0.1)
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, OSError):
        pass


async def run_tool_process(
    cmd: list[str],
    timeout_seconds: int = 120,
) -> tuple[int, str, str]:
    """Executes a command array safely within a detached process group.

    Args:
        cmd: List of execution arguments (argv array).
        timeout_seconds: Maximum wall-clock seconds before termination.

    Returns:
        tuple of (returncode, stdout, stderr)

    Raises:
        TimeoutError: If execution exceeds timeout_seconds.
        ValueError: If command list is empty.
    """
    if not cmd or not any(cmd):
        raise ValueError("Cannot execute empty command")

    # On POSIX systems, start in a new process group so child processes can be killed as a group
    is_posix = sys.platform != "win32"
    if is_posix:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
    else:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(),
            timeout=float(timeout_seconds),
        )
        returncode = proc.returncode if proc.returncode is not None else -1

        # Enforce memory safety cap
        if len(stdout_bytes) > MAX_STDOUT_BYTES:
            stdout_bytes = stdout_bytes[:MAX_STDOUT_BYTES] + b"\n...[ARGUS OUTPUT TRUNCATED]"

        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        return returncode, stdout, stderr

    except TimeoutError as e:
        # Kill the entire process group cleanly (S-07)
        if proc.pid:
            kill_process_group(proc.pid)

        try:
            await asyncio.wait_for(proc.wait(), timeout=1.0)
        except (TimeoutError, OSError):
            pass

        raise TimeoutError(
            f"Tool execution for '{cmd[0]}' timed out after {timeout_seconds}s"
        ) from e


def build_docker_sandbox_command(
    image: str,
    tool_cmd: list[str],
    network: str = "none",
    read_only: bool = True,
    drop_caps: bool = True,
    user: str = "1000:1000",
    tmpfs_size: str = "64m",
) -> list[str]:
    """Builds a Docker execution command with least-privilege sandbox controls (X-05).

    Enforces:
    - Non-root user execution (--user 1000:1000)
    - Full capability dropping (--cap-drop=ALL)
    - Read-only container rootfs (--read-only)
    - Dedicated, non-executable tmpfs for /tmp (--tmpfs=/tmp:rw,noexec,nosuid,size=64m)
    - No privilege escalation (--security-opt=no-new-privileges:true)
    """
    cmd = ["docker", "run", "--rm"]
    if drop_caps:
        cmd.append("--cap-drop=ALL")
    if read_only:
        cmd.append("--read-only")
    cmd.append("--security-opt=no-new-privileges:true")
    cmd.append(f"--user={user}")
    cmd.append(f"--tmpfs=/tmp:rw,noexec,nosuid,size={tmpfs_size}")
    cmd.append(f"--network={network}")
    cmd.append(image)
    cmd.extend(tool_cmd)
    return cmd


def verify_docker_sandbox_security(cmd: list[str]) -> tuple[bool, list[str]]:
    """Inspects a Docker run command line to verify all security lockdown constraints (X-05).

    Returns (is_compliant, list_of_violations).
    """
    violations: list[str] = []
    cmd_str = " ".join(cmd)

    if "--cap-drop=ALL" not in cmd and not any("--cap-drop" in arg for arg in cmd):
        violations.append("Missing capability drop constraint (--cap-drop=ALL)")

    if "--read-only" not in cmd:
        violations.append("Missing read-only filesystem constraint (--read-only)")

    if "no-new-privileges:true" not in cmd_str:
        violations.append(
            "Missing privilege escalation guard (--security-opt=no-new-privileges:true)"
        )

    if not any(arg.startswith("--user=") or arg == "--user" for arg in cmd):
        violations.append("Missing explicit non-root user execution (--user)")
    elif any(arg in ["--user=0", "--user=root", "--user=0:0"] for arg in cmd):
        violations.append("Root user execution is forbidden")

    if not any(arg.startswith(("--tmpfs=/tmp", "--tmpfs /tmp")) for arg in cmd):
        violations.append("Missing dedicated temporary filesystem mount (/tmp)")

    return len(violations) == 0, violations


async def run_tool_in_docker_sandbox(
    image: str,
    tool_cmd: list[str],
    timeout_seconds: int = 120,
    network: str = "none",
    read_only: bool = True,
    drop_caps: bool = True,
    user: str = "1000:1000",
) -> tuple[int, str, str]:
    """Executes a tool command inside a hardened, isolated Docker container (X-05)."""
    docker_cmd = build_docker_sandbox_command(
        image=image,
        tool_cmd=tool_cmd,
        network=network,
        read_only=read_only,
        drop_caps=drop_caps,
        user=user,
    )
    is_safe, violations = verify_docker_sandbox_security(docker_cmd)
    if not is_safe:
        raise ValueError(f"Docker sandbox command failed security check: {violations}")

    return await run_tool_process(docker_cmd, timeout_seconds=timeout_seconds)
