#!/bin/bash
# ARGUS lab greeting endpoint — INTENTIONALLY VULNERABLE to reflected XSS.
#
# The `name` query parameter is rendered into HTML without escaping.
#
# Reproduction:
#   curl -s "http://localhost:8888/cgi-bin/greet.sh?name=<script>alert(1)</script>"

echo "Content-Type: text/html"
echo ""

NAME_RAW="${QUERY_STRING#name=}"
NAME_RAW="${NAME_RAW%%&*}"
NAME_RAW="${NAME_RAW//+/ }"
# Decode %XX so the reflected value is the browser-supplied payload.
NAME=$(printf '%b' "${NAME_RAW//%/\\x}")

echo "<html><body>"
echo "<h1>Hello, ${NAME}</h1>"
echo "<p>Welcome to the ARGUS authorized lab target.</p>"
echo "</body></html>"
