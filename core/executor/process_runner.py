"""Hardened Process Execution Subsystem for ARGUS.

Executes external security tool commands in an isolated subprocess group
with strict timeouts, non-zero return code capture, and zombie process prevention.
"""

import asyncio
import os
import signal
import sys
import threading

# Maximum raw output limit to prevent out-of-memory denial of service (50 MB)
MAX_STDOUT_BYTES = 50 * 1024 * 1024

# Sensitive substrings that must NEVER appear in subprocess environment
SENSITIVE_ENV_SUBSTRINGS = (
    "KEY",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "AUTH",
    "DATABASE",
    "ARGUS_",
    "ANTHROPIC_",
    "OPENAI_",
    "AWS_",
    "AZURE_",
    "GCP_",
    "GOOGLE_",
    "PRIVATE",
)

# Standard safe system environment variables
SAFE_ENV_VARS = (
    "PATH",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
)

_ACTIVE_PROCESSES: dict[str, set[int]] = {}
_PROCESS_LOCK = threading.Lock()


def get_sanitized_env(extra_env: dict[str, str] | None = None) -> dict[str, str]:
    """Builds a strictly sanitized environment dictionary for subprocess isolation (SEC-02).

    Prevents sensitive keys, API secrets, tokens, and database credentials from
    leaking into external tool subprocesses.
    """
    clean_env: dict[str, str] = {}

    for var in SAFE_ENV_VARS:
        if var in os.environ:
            clean_env[var] = os.environ[var]

    if "PATH" not in clean_env:
        clean_env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

    clean_env["HOME"] = "/tmp"
    clean_env["TMPDIR"] = "/tmp"

    if extra_env:
        for k, v in extra_env.items():
            k_upper = k.upper()
            if any(sub in k_upper for sub in SENSITIVE_ENV_SUBSTRINGS):
                continue
            clean_env[k] = str(v)

    return clean_env


def register_active_process(assessment_id: str, pid: int) -> None:
    """Registers an active child process PID under an assessment ID (SEC-09)."""
    with _PROCESS_LOCK:
        if assessment_id not in _ACTIVE_PROCESSES:
            _ACTIVE_PROCESSES[assessment_id] = set()
        _ACTIVE_PROCESSES[assessment_id].add(pid)


def unregister_active_process(assessment_id: str, pid: int) -> None:
    """Unregisters a completed or killed child process PID."""
    with _PROCESS_LOCK:
        if assessment_id in _ACTIVE_PROCESSES:
            _ACTIVE_PROCESSES[assessment_id].discard(pid)
            if not _ACTIVE_PROCESSES[assessment_id]:
                del _ACTIVE_PROCESSES[assessment_id]


def terminate_active_processes(assessment_id: str) -> int:
    """Deterministically kills all active process groups running for an assessment (SEC-09).

    Returns the number of processes targeted for termination.
    """
    with _PROCESS_LOCK:
        pids = list(_ACTIVE_PROCESSES.pop(assessment_id, set()))

    for pid in pids:
        kill_process_group(pid)

    return len(pids)


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
    assessment_id: str | None = None,
    extra_env: dict[str, str] | None = None,
    cwd: str = "/tmp",
) -> tuple[int, str, str]:
    """Executes a command array safely within a detached process group.

    Args:
        cmd: List of execution arguments (argv array).
        timeout_seconds: Maximum wall-clock seconds before termination.
        assessment_id: Assessment tracking ID for lifecycle abort tracking.
        extra_env: Extra non-sensitive environment variables.
        cwd: Working directory (defaults to /tmp).

    Returns:
        tuple of (returncode, stdout, stderr)

    Raises:
        TimeoutError: If execution exceeds timeout_seconds.
        ValueError: If command list is empty.
    """
    if not cmd or not any(cmd):
        raise ValueError("Cannot execute empty command")

    sanitized_env = get_sanitized_env(extra_env)
    effective_cwd = cwd if os.path.exists(cwd) else None

    # On POSIX systems, start in a new process group so child processes can be killed as a group
    is_posix = sys.platform != "win32"
    if is_posix:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
            env=sanitized_env,
            cwd=effective_cwd,
        )
    else:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=sanitized_env,
            cwd=effective_cwd,
        )

    if assessment_id and proc.pid:
        register_active_process(assessment_id, proc.pid)

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
    except asyncio.CancelledError:
        # Prevent orphaned processes on async task cancellation (SEC-09)
        if proc.pid:
            kill_process_group(proc.pid)
        try:
            await asyncio.wait_for(proc.wait(), timeout=1.0)
        except (TimeoutError, OSError, asyncio.CancelledError):
            pass
        raise
    finally:
        if assessment_id and proc.pid:
            unregister_active_process(assessment_id, proc.pid)


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
