#!/bin/bash
# ARGUS lab diagnostic endpoint — INTENTIONALLY leaks process environment.
#
# Reproduction:
#   curl -s "http://localhost:8888/cgi-bin/info.sh"

echo "Content-Type: text/plain"
echo ""

echo "ARGUS lab CGI environment"
echo "------------------------------------------------------------"
env | sort
echo "------------------------------------------------------------"
id
uname -a
