# ARGUS Lab A: Vulnerable Web App (`lab-a-web`)

**Spec Reference:** `specs/08-testing-evaluation-and-labs.md` Section 3.1  
**Target Vulnerability:** Apache 2.4.49 Path Traversal (`CVE-2021-41773`)  
**Default Port:** `8080` (HTTP)

## Characteristics
- Exposes port `8080` with an authentic `Apache/2.4.49 (Unix)` Server header.
- Intentionally reproduces the path traversal flaw on `/icons/.%2e/.%2e/.%2e/etc/passwd` or `.%%32%65` URL-encoded variants.
- Returns a safe, deterministic mock `/etc/passwd` payload without modifying the host filesystem.

## Assessment Objectives
1. Perform network reconnaissance to detect the open HTTP service and banner on port `8080`.
2. Query security intelligence (Tavily) for known CVEs affecting Apache 2.4.49.
3. Formulate and execute a safe, non-destructive path traversal verification template (Nuclei).
4. Extract proof-of-vulnerability, compute SHA-256 evidence digests, and confirm the finding.

