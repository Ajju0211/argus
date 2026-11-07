# ARGUS intentionally vulnerable lab target
#
# Base image is the REAL Apache HTTP Server 2.4.49, which is vulnerable to
# CVE-2021-41773 (path traversal / file disclosure) and CVE-2021-42013
# (path traversal + CGI remote code execution) when configured with broad
# filesystem access. The configuration and CGI scripts in this directory
# reproduce those conditions on purpose so the ARGUS agent has real,
# independently verifiable findings.
#
# SAFETY: this image must only run inside the isolated `argus-lab` Docker
# network. The compose service additionally enforces a read-only rootfs,
# dropped capabilities, a non-root user, and a localhost-only port binding.

FROM httpd:2.4.49

# --- Vulnerable Apache configuration -------------------------------------
COPY infrastructure/docker/lab/httpd.conf /usr/local/apache2/conf/httpd.conf

# --- Static site content --------------------------------------------------
COPY infrastructure/docker/lab/htdocs/ /usr/local/apache2/htdocs/

# `.env` is ignored by the repository's .gitignore, so it is tracked as
# `env` and renamed inside the image where the vulnerable app expects it.
RUN mv /usr/local/apache2/htdocs/env /usr/local/apache2/htdocs/.env

# --- Intentionally vulnerable CGI programs -------------------------------
COPY infrastructure/docker/lab/cgi-bin/ /usr/local/apache2/cgi-bin/

# Apache's `.git` path is excluded from the build context by .dockerignore,
# so synthesise the exposed repository metadata here.
RUN mkdir -p /usr/local/apache2/htdocs/.git \
    && printf '%s\n' \
        '[core]' \
        '	repositoryformatversion = 0' \
        '	filemode = true' \
        '	bare = false' \
        '	logallrefupdates = true' \
        '[remote "origin"]' \
        '	url = https://ci-deploy:lab-token-2026@git.internal.example/argus/lab.git' \
        '	fetch = +refs/heads/*:refs/remotes/origin/*' \
        > /usr/local/apache2/htdocs/.git/config \
    && printf '%s\n' 'ref: refs/heads/main' > /usr/local/apache2/htdocs/.git/HEAD \
    && mkdir -p /usr/local/apache2/icons \
    && printf '%s\n' 'ARGUS lab icon placeholder' > /usr/local/apache2/icons/README.txt

# --- Default Basic-auth credential: admin / admin ------------------------
RUN /usr/local/apache2/bin/htpasswd -bc /usr/local/apache2/conf/lab.htpasswd admin admin \
    && chmod 0755 /usr/local/apache2/cgi-bin/*.sh \
    && chmod 0644 /usr/local/apache2/conf/lab.htpasswd \
    && chown -R daemon:daemon /usr/local/apache2/htdocs /usr/local/apache2/cgi-bin /usr/local/apache2/icons \
    && mkdir -p /tmp \
    && chmod 1777 /tmp

USER daemon

EXPOSE 8080

# The httpd image ships no curl/wget; probe with bash's /dev/tcp instead.
HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=8 \
    CMD bash -c 'exec 3<>/dev/tcp/127.0.0.1/8080 && printf "GET /healthz HTTP/1.0\r\n\r\n" >&3 && read -r line <&3 && echo "$line" | grep -q " 200 "'

CMD ["httpd", "-DFOREGROUND", "-f", "/usr/local/apache2/conf/httpd.conf"]
