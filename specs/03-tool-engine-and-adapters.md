# Module 03 — Tool Engine & Security Adapters

**Module ID:** `tool-engine`  
**Status:** Approved Specification  
**Primary Owner:** Dev 1  
**Dependencies:** `core-scope`, `evidence-vault`  
**Downstream Consumers:** `agent-orchestrator`  

---

## 1. Overview & Architectural Role

The **Tool Engine** provides a sandboxed execution environment for real security tools. It bridges high-level agent action proposals with actual security tooling (Nmap, OWASP ZAP, Nuclei) running in Docker containers.

Core guarantees:
1. **No Arbitrary Shells:** Commands are assembled as deterministic arrays of strings (`argv`), never raw shell strings executed via `shell=True`.
2. **Subprocess Isolation:** Tools run inside a dedicated Docker runner container with hard resource limits and timeouts.
3. **Structured Observation Parsing:** Unstructured CLI stdout is normalized into typed `NormalizedObservation` records before entering agent state.

---

## 2. Abstract Base Adapter (`integrations/tools/base.py`)

Every tool integration must inherit from `ToolAdapter`:

```python
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from pydantic import BaseModel

class NormalizedObservation(BaseModel):
    tool: str                          # "nmap" | "zap" | "nuclei"
    target: str                        # "192.168.100.5" or "http://lab:8080"
    observation_type: str              # "host_discovered" | "open_port" | "service_version" | "vuln_candidate"
    data: Dict[str, Any]               # Parsed attributes (port, service, banner, cve, url)
    severity_hint: Optional[str]       # "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    raw_evidence_id: str               # Pointer to the raw SHA-256 artifact

class ToolAdapter(ABC):
    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Registered identifier for the tool."""
        pass

    @abstractmethod
    def validate_args(self, args: Dict[str, Any]) -> bool:
        """Validate input arguments against injection attacks and allowed parameters."""
        pass

    @abstractmethod
    def build_command(self, args: Dict[str, Any]) -> List[str]:
        """Generate safe, typed execution arguments array."""
        pass

    @abstractmethod
    def parse_output(self, raw_output: str, evidence_id: str) -> List[NormalizedObservation]:
        """Parse raw CLI output into normalized observations."""
        pass
```

---

## 3. Registered Tool Adapters

### 3.1 Nmap Adapter (`integrations/tools/nmap_adapter.py`)
- **Purpose:** Host discovery, TCP port scanning, and service version fingerprinting.
- **Enforced Flags:**
  - `-sT`: TCP Connect scan (requires no unprivileged raw packet capabilities).
  - `-sV`: Probe open ports for service version information.
  - `-T4`: Aggressive timing template suitable for isolated lab environments.
  - `--open`: Show only open ports to minimize clutter.
  - `-oX -`: Output directly as XML to stdout for deterministic parsing.
- **Parsing:** Uses `defusedxml.ElementTree` to parse ports, service names, product versions, and hostnames.

### 3.2 OWASP ZAP Adapter (`integrations/tools/zap_adapter.py`)
- **Purpose:** Passive baseline web application vulnerability scanning.
- **Mode:** Runs ZAP Baseline via Docker API or CLI container.
- **Checks:**
  - Missing HTTP security headers (CSP, HSTS, X-Content-Type-Options).
  - Insecure cookies (missing `HttpOnly` or `Secure` flags).
  - Directory indexing and informational disclosures.
- **Parsing:** Parses ZAP JSON report into observations with `severity_hint` mapped to standard levels.

### 3.3 Nuclei Adapter (`integrations/tools/nuclei_adapter.py`)
- **Purpose:** Fast, template-based verification of specific known CVEs.
- **Mode:** Strictly pinned, local templates directory: `/templates/pinned/`.
- **Command:** `nuclei -u <target_url> -t <pinned_template_path> -j -silent`
- **Safety Rule:** Only non-destructive, informational, and safe proof-of-concept templates are allowlisted. DoS and brute-force templates are stripped.
- **Parsing:** Parses line-delimited JSON (`JSONL`) output, capturing matched URL, template ID, severity, and curl reproduction command.

---

## 4. Docker Runner & Process Execution (`core/executor/docker_runner.py`)

Tools execute inside a lightweight, hardened container (`runner.Dockerfile`):

```dockerfile
FROM debian:bookworm-slim

# Install pinned, official security packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei pinned binary (ARM64 & AMD64)
RUN curl -sSL https://github.com/projectdiscovery/nuclei/releases/download/v3.3.0/nuclei_3.3.0_linux_arm64.zip -o nuclei.zip \
    && unzip nuclei.zip -d /usr/local/bin && rm nuclei.zip

# Run as non-root unprivileged user
RUN useradd -m -u 1000 argusrunner
USER argusrunner
WORKDIR /home/argusrunner
```

### Execution Lifecycle
```python
import asyncio

async def run_tool_process(cmd: List[str], timeout_seconds: int) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
        return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise TimeoutError(f"Tool execution timed out after {timeout_seconds}s")
```

---

## 5. Acceptance Criteria & Test Scenarios

1. `test_nmap_command_builder`: Validates that invalid flags like `--script=vuln` are rejected.
2. `test_nmap_xml_parser`: Confirms valid `NormalizedObservation` records are extracted from standard Nmap XML fixtures.
3. `test_nuclei_jsonl_parser`: Verifies that JSONL outputs generate findings with proper template IDs and severity levels.
4. `test_process_timeout_cleanup`: Confirms that a hung process is killed within 1 second of timeout expiration without leaving zombie processes.

