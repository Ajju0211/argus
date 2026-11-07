#!/bin/bash
# ARGUS lab file-download endpoint — INTENTIONALLY VULNERABLE.
#
# The `file` query parameter is joined to the document root without any
# canonicalisation, so `../` escapes the web root and reads arbitrary files.
#
# Reproduction:
#   curl -s "http://localhost:8888/cgi-bin/download.sh?file=../../../../etc/passwd"

echo "Content-Type: application/octet-stream"
echo ""

FILE_RAW="${QUERY_STRING#file=}"
FILE_RAW="${FILE_RAW%%&*}"
FILE="${FILE_RAW//+/ }"

# INTENTIONALLY VULNERABLE: path traversal is not blocked.
cat "/usr/local/apache2/htdocs/${FILE}" 2>&1
