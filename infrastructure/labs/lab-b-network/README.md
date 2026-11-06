# ARGUS Lab B: Multi-Service Linux Host (`lab-b-network`)

**Spec Reference:** `specs/08-testing-evaluation-and-labs.md` Section 3.2  
**Target Environment:** Isolated host running simulated network services  
**Exposed Services:**
- Port `21` (TCP) — FTP Service (`vsftpd 2.3.4` banner)
- Port `22` (TCP) — SSH Service (`OpenSSH 8.4p1` banner)
- Port `8080` (HTTP) — Healthcheck & Service Registry (`/healthz`)

## Assessment Objectives
1. Multi-port network reconnaissance: Discover open ports 21 and 22 within authorized scope.
2. Banner extraction: Grab protocol headers without triggering rate-limits or denial of service.
3. Service categorization: Map port 21 to FTP (`vsftpd 2.3.4`) and port 22 to SSH (`OpenSSH 8.4p1`).
4. Evidence preservation: Store raw scanner observations with SHA-256 digests in Evidence Vault.

