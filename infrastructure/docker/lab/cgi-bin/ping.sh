#!/bin/bash
# ARGUS lab diagnostic endpoint — INTENTIONALLY VULNERABLE.
#
# The `host` query parameter is interpolated into `eval`, which gives real
# OS command injection as the web user.
#
# Reproduction:
#   curl -s "http://localhost:8888/cgi-bin/ping.sh?host=127.0.0.1;id"

echo "Content-Type: text/plain"
echo ""

HOST_RAW="${QUERY_STRING#host=}"
HOST_RAW="${HOST_RAW%%&*}"
HOST="${HOST_RAW//+/ }"

echo "ARGUS lab network diagnostic"
echo "Target: ${HOST}"
echo "------------------------------------------------------------"

# INTENTIONALLY VULNERABLE: never build shell commands from user input.
eval "getent hosts ${HOST}" 2>&1

echo "------------------------------------------------------------"
echo "diagnostic complete"
