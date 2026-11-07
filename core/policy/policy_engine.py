"""Deterministic Scope & Policy Engine for ARGUS.

Enforces zero out-of-scope executions and acts as the release-blocking safety firewall.
Follows security-and-hardening guidelines with a strict fail-closed architecture.
"""

import ipaddress
import socket
import urllib.parse
from datetime import UTC, datetime
from typing import Any

from core.config import get_settings
from packages.contracts.actions import ActionProposal, FootholdEvidence, PolicyDecision
from packages.contracts.scope import PivotRule, ScopeDocument


class PolicyEngine:
    """Evaluates ActionProposals against an active ScopeDocument deterministically."""

    def __init__(self, scope: ScopeDocument):
        self.scope = scope
        self._settings = get_settings()
        self._forbidden_tokens = self._settings.FORBIDDEN_ARG_TOKENS
        self._parsed_subnets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
            ipaddress.ip_network(s, strict=False) for s in scope.targets.allowed_subnets
        ]
        self._denied_hosts_set = set(scope.targets.denied_hosts)
        self._allowed_hosts_set = set(scope.targets.allowed_hosts)

    def evaluate(
        self,
        proposal: ActionProposal,
        footholds: list[FootholdEvidence] | None = None,
        simulation_mode: bool = False,
    ) -> PolicyDecision:
        """Determines whether an action is authorized under the active scope."""
        try:
            return self._evaluate_internal(proposal, footholds=footholds, simulation_mode=simulation_mode)
        except Exception as e:  # noqa: BLE001
            # Mandatory fail-closed behavior on any unexpected exception
            return PolicyDecision(
                approved=False, reason=f"Policy evaluation failure (fail-closed): {e}"
            )

    def is_target_authorized(
        self,
        host: str,
        footholds: list[FootholdEvidence] | None = None,
        simulation_mode: bool = False,
    ) -> bool:
        """Determines whether a host is authorized for discovery or targeting without raising errors."""
        resolved_ip = self._resolve_host(host)
        if not resolved_ip:
            return False
        if resolved_ip in self._denied_hosts_set or host in self._denied_hosts_set:
            return False
        try:
            ip_obj = ipaddress.ip_address(resolved_ip)
            if (
                ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_reserved
                or ip_obj.is_multicast
            ):
                return False
        except ValueError:
            return False

        # Network boundary check
        in_allowed_subnet = any(ip_obj in subnet for subnet in self._parsed_subnets)
        in_allowed_ip = resolved_ip in self._allowed_hosts_set
        if self._parsed_subnets and not (in_allowed_subnet or in_allowed_ip):
            return False
        if not self._parsed_subnets and ip_obj.is_private:
            return False

        # In entry hosts?
        if resolved_ip in self._allowed_hosts_set or host in self._allowed_hosts_set:
            return True
        for allowed in self._allowed_hosts_set:
            if allowed.startswith("*.") and host.endswith(allowed[1:]):
                return True

        # In authorized pivot rules destination?
        if self.scope.authorized_chain.enabled and self.scope.authorized_chain.pivots:
            for pivot in self.scope.authorized_chain.pivots:
                if pivot.to_host in (host, resolved_ip):
                    if not pivot.requires_foothold:
                        return True
                    now_utc = datetime.now(UTC)
                    return any(
                        fh.host == pivot.from_host
                        and not fh.is_expired(now_utc)
                        and (simulation_mode or not fh.simulated)
                        and (not fh.assessment_id or not self.scope.assessment_id or fh.assessment_id == self.scope.assessment_id)
                        for fh in (footholds or [])
                    )

        # Fallback if scope has no allowed_hosts and no pivots (legacy loose subnet scope)
        return bool(
            not self._allowed_hosts_set
            and not self.scope.authorized_chain.pivots
            and in_allowed_subnet
        )

    def _infer_target_port(self, proposal: ActionProposal) -> int | None:
        """Infers target port from proposal target_port, target_host, or arguments (S-01)."""
        if proposal.target_port is not None:
            return proposal.target_port

        # Check if target_host contains :port
        if ":" in proposal.target_host:
            parts = proposal.target_host.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                return int(parts[1])

        # Check arguments for explicit port
        for key in ("port", "target_port"):
            if key in proposal.arguments:
                val = proposal.arguments[key]
                if isinstance(val, int):
                    return val
                if isinstance(val, str) and val.isdigit():
                    return int(val)

        # Check arguments for URLs
        for key in ("url", "target_url", "target", "endpoint", "matched_at"):
            if key in proposal.arguments:
                val = str(proposal.arguments[key]).strip()
                if "://" in val:
                    parsed = urllib.parse.urlparse(val)
                    if parsed.port is not None:
                        return parsed.port
                    if parsed.scheme.lower() == "http":
                        return 80
                    if parsed.scheme.lower() == "https":
                        return 443
                    if parsed.scheme.lower() == "ssh":
                        return 22

        return None

    def _extract_protocols(self, proposal: ActionProposal) -> list[str]:
        """Extracts protocols referenced across host and arguments (S-03)."""
        schemes: list[str] = []
        for val in [proposal.target_host, *proposal.arguments.values()]:
            s_val = str(val).strip()
            if "://" in s_val:
                parsed = urllib.parse.urlparse(s_val)
                if parsed.scheme:
                    schemes.append(parsed.scheme.lower())
            elif s_val.lower().startswith("file:"):
                schemes.append("file")
        if "protocol" in proposal.arguments:
            schemes.append(str(proposal.arguments["protocol"]).lower())
        return schemes

    def _parse_port_spec(self, raw: Any) -> list[int] | None:
        """Parses an explicit port spec (int, list, comma list, or range) safely.

        Returns None when the specification is malformed or outside 1-65535.
        """
        if isinstance(raw, bool):
            return None
        if isinstance(raw, int):
            return [raw] if 1 <= raw <= 65535 else None
        if isinstance(raw, (list, tuple, set)):
            expanded: set[int] = set()
            for item in raw:
                parsed = self._parse_port_spec(item)
                if parsed is None:
                    return None
                expanded.update(parsed)
            return sorted(expanded)

        raw_str = str(raw).strip()
        if not raw_str:
            return []

        ports: set[int] = set()
        for chunk in raw_str.split(","):
            chunk = chunk.strip()
            if not chunk:
                return None
            if "-" in chunk:
                parts = chunk.split("-")
                if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
                    return None
                start, end = int(parts[0]), int(parts[1])
                if start < 1 or end > 65535 or start > end:
                    return None
                ports.update(range(start, end + 1))
            elif chunk.isdigit():
                port = int(chunk)
                if not 1 <= port <= 65535:
                    return None
                ports.add(port)
            else:
                return None
        return sorted(ports)

    def _infer_protocols(self, proposal: ActionProposal, requested_ports: list[int]) -> list[str]:
        """Infers the effective protocols for an action (S-03).

        Scheme-less web actions are treated as HTTP/HTTPS based on their ports so
        that a scope allowing only HTTPS cannot be bypassed with a bare host.
        """
        protocols = set(self._extract_protocols(proposal))
        if protocols:
            return sorted(protocols)

        category = proposal.action_category.lower()
        tool = proposal.tool_name.lower()
        web_categories = {"web_crawl", "passive_vuln_scan", "active_template_check"}
        web_tools = {"nuclei", "zap"}

        if category in web_categories or tool in web_tools:
            if requested_ports:
                for port in requested_ports:
                    protocols.add("https" if port in (443, 8443) else "http")
            else:
                protocols.add("http")
        elif category == "network_recon" or tool == "nmap":
            protocols.add("tcp")

        return sorted(protocols)

    @staticmethod
    def _is_chain_step(proposal: ActionProposal) -> bool:
        """A proposal is part of a chain only when it declares chain metadata."""
        return proposal.parent_action_id is not None or proposal.step_index is not None

    def _evaluate_chain_authorization(self, proposal: ActionProposal) -> PolicyDecision | None:
        """Enforces explicit bounded multi-step authorization (L-04).

        Returns a denial decision when the proposal violates the chain envelope,
        or None when the proposal is not a chain step or is authorized.
        """
        if not self._is_chain_step(proposal):
            return None

        chain = self.scope.authorized_chain
        if not chain.enabled:
            return PolicyDecision(
                approved=False,
                reason=(
                    "Multi-step chain action requires explicit scope authorization "
                    "('authorized_chain.enabled: true')."
                ),
            )

        if proposal.step_index is None:
            return PolicyDecision(
                approved=False,
                reason="A chain action must declare a 1-based step_index.",
            )
        if proposal.step_index < 1 or proposal.step_index > chain.max_steps:
            return PolicyDecision(
                approved=False,
                reason=(
                    f"Chain step_index {proposal.step_index} is outside the authorized "
                    f"range 1-{chain.max_steps}."
                ),
            )
        if proposal.step_index > len(chain.allowed_steps):
            return PolicyDecision(
                approved=False,
                reason=(
                    f"Chain step {proposal.step_index} is not declared in "
                    "scope.authorized_chain.allowed_steps."
                ),
            )

        step = chain.allowed_steps[proposal.step_index - 1]
        if proposal.action_category != step.action_category:
            return PolicyDecision(
                approved=False,
                reason=(
                    f"Chain step {proposal.step_index} permits action category "
                    f"'{step.action_category}', not '{proposal.action_category}'."
                ),
            )
        if step.allowed_hosts and proposal.target_host not in step.allowed_hosts:
            return PolicyDecision(
                approved=False,
                reason=(
                    f"Chain step {proposal.step_index} does not authorize target "
                    f"'{proposal.target_host}'."
                ),
            )
        if step.allowed_ports and proposal.target_port not in step.allowed_ports:
            return PolicyDecision(
                approved=False,
                reason=(
                    f"Chain step {proposal.step_index} does not authorize port "
                    f"'{proposal.target_port}'."
                ),
            )
        return None

    def _validate_embedded_targets(
        self,
        proposal: ActionProposal,
        footholds: list[FootholdEvidence] | None = None,
        simulation_mode: bool = False,
    ) -> PolicyDecision | None:
        """Validates outbound URLs carried inside tool arguments (adversarial scope evasion).

        The planner can put the tool's real destination in ``target``, ``url``, or
        ``target_url`` while declaring an in-scope ``target_host``. Encoded URLs
        such as ``http://allowed.host%2f@attacker.com`` exploit that mismatch.
        Every URL argument must therefore satisfy the same identity, port, and
        protocol rules as the declared target.
        """
        for key in ("url", "target_url", "target", "endpoint", "matched_at"):
            raw = proposal.arguments.get(key)
            if not isinstance(raw, str) or "://" not in raw:
                continue

            parsed = urllib.parse.urlsplit(raw.strip())

            scheme = parsed.scheme.lower()
            if scheme in self.scope.protocols.denied:
                return PolicyDecision(
                    approved=False, reason=f"Embedded target protocol '{scheme}' is denied."
                )
            if self.scope.protocols.allowed and scheme not in self.scope.protocols.allowed:
                return PolicyDecision(
                    approved=False,
                    reason=f"Embedded target protocol '{scheme}' is not in allowed protocols.",
                )

            host = parsed.hostname
            if not host:
                return PolicyDecision(
                    approved=False,
                    reason=f"Argument '{key}' contains a URL without a valid host.",
                )
            if parsed.username or parsed.password:
                return PolicyDecision(
                    approved=False,
                    reason=f"Argument '{key}' contains embedded URL credentials.",
                )

            resolved_ip = self._resolve_host(host)
            if not resolved_ip:
                return PolicyDecision(
                    approved=False,
                    reason=f"Cannot resolve embedded target host '{host}'.",
                )
            if host in self._denied_hosts_set or resolved_ip in self._denied_hosts_set:
                return PolicyDecision(
                    approved=False,
                    reason=f"Embedded target '{host}' ({resolved_ip}) is explicitly denied.",
                )

            try:
                ip_obj = ipaddress.ip_address(resolved_ip)
            except ValueError:
                return PolicyDecision(
                    approved=False,
                    reason=f"Invalid embedded target IP '{resolved_ip}'.",
                )
            if (
                ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_reserved
                or ip_obj.is_multicast
            ):
                return PolicyDecision(
                    approved=False,
                    reason=f"Embedded target IP {resolved_ip} is loopback, link-local, or reserved.",
                )

            in_allowed_subnet = any(ip_obj in subnet for subnet in self._parsed_subnets)
            in_allowed_ip = resolved_ip in self._allowed_hosts_set
            if self._parsed_subnets and not (in_allowed_subnet or in_allowed_ip):
                return PolicyDecision(
                    approved=False,
                    reason=(
                        f"Embedded target '{host}' ({resolved_ip}) is outside authorized "
                        "IP boundaries / DNS rebinding guard."
                    ),
                )
            if not self.is_target_authorized(host, footholds=footholds, simulation_mode=simulation_mode):
                return PolicyDecision(
                    approved=False,
                    reason=(
                        f"Embedded target '{host}' ({resolved_ip}) is outside allowed targets."
                    ),
                )

            port = parsed.port
            if port is None:
                port = 443 if parsed.scheme.lower() == "https" else 80
            if port in self.scope.ports.denied_ports:
                return PolicyDecision(
                    approved=False, reason=f"Embedded target port {port} is explicitly denied."
                )
            if self.scope.ports.allowed_ports and port not in self.scope.ports.allowed_ports:
                return PolicyDecision(
                    approved=False, reason=f"Embedded target port {port} is not in allowed ports."
                )

        return None

    def _evaluate_internal(
        self,
        proposal: ActionProposal,
        footholds: list[FootholdEvidence] | None = None,
        simulation_mode: bool = False,
    ) -> PolicyDecision:
        # 1. Temporal Check
        now = datetime.now(UTC)
        expires_at = self.scope.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)

        if now > expires_at:
            return PolicyDecision(approved=False, reason="Scope authorization has expired.")

        # 2. Target IP & Hostname Gating with DNS Pinning (S-02 & S-10)
        resolved_ip = self._resolve_host(proposal.target_host)
        if not resolved_ip:
            return PolicyDecision(
                approved=False, reason=f"Cannot resolve target host '{proposal.target_host}'."
            )

        # Explicit exclusions check strictly BEFORE allowed lists (S-10)
        if resolved_ip in self._denied_hosts_set or proposal.target_host in self._denied_hosts_set:
            return PolicyDecision(
                approved=False,
                reason=f"Host '{proposal.target_host}' ({resolved_ip}) is explicitly denied.",
            )

        try:
            ip_obj = ipaddress.ip_address(resolved_ip)
        except ValueError:
            return PolicyDecision(
                approved=False, reason=f"Invalid IP address format '{resolved_ip}'."
            )

        # SSRF & reserved address guards (S-02 & S-10)
        if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast:
            return PolicyDecision(
                approved=False,
                reason=f"Target IP {resolved_ip} is a loopback, link-local, or reserved address.",
            )

        # Network boundary check (allowed_subnets defines the permitted network envelope)
        in_allowed_subnet = any(ip_obj in subnet for subnet in self._parsed_subnets)
        in_allowed_ip = resolved_ip in self._allowed_hosts_set

        if self._parsed_subnets:
            # When subnets are defined, resolved IP must be inside allowed subnets or explicitly allowed host IPs (S-02 DNS rebinding guard)
            if not (in_allowed_subnet or in_allowed_ip):
                return PolicyDecision(
                    approved=False,
                    reason=(
                        f"Target '{proposal.target_host}' ({resolved_ip}) is outside allowed targets "
                        "(outside authorized IP boundaries / DNS rebinding guard)."
                    ),
                )
        else:
            if ip_obj.is_private:
                return PolicyDecision(
                    approved=False,
                    reason=f"Target '{proposal.target_host}' resolved to private IP {resolved_ip} without authorized private subnets.",
                )

        # Target authorization (Entry hosts vs Lateral Movement / Pivots)
        in_allowed_host_or_wildcard = False
        for allowed in self._allowed_hosts_set:
            if allowed == resolved_ip or allowed == proposal.target_host:
                in_allowed_host_or_wildcard = True
                break
            if allowed.startswith("*."):
                suffix = allowed[1:]
                if proposal.target_host.endswith(suffix):
                    in_allowed_host_or_wildcard = True
                    break

        target_authorized = False
        active_pivot: PivotRule | None = None

        # Check explicit bounded multi-step chain authorization (L-04)
        if self._is_chain_step(proposal):
            chain_decision = self._evaluate_chain_authorization(proposal)
            if chain_decision is not None:
                return chain_decision
            target_authorized = True
        elif in_allowed_host_or_wildcard or in_allowed_ip:
            target_authorized = True
        elif self.scope.authorized_chain.enabled and self.scope.authorized_chain.pivots:
            for pivot in self.scope.authorized_chain.pivots:
                if pivot.to_host in (proposal.target_host, resolved_ip):
                    if pivot.requires_foothold:
                        now_utc = datetime.now(UTC)
                        valid_fh = None
                        for fh in (footholds or []):
                            if fh.host == pivot.from_host and not fh.is_expired(now_utc):
                                if not simulation_mode and fh.simulated:
                                    continue
                                if fh.assessment_id and self.scope.assessment_id and fh.assessment_id != self.scope.assessment_id:
                                    continue
                                valid_fh = fh
                                break
                        if not valid_fh:
                            return PolicyDecision(
                                approved=False,
                                reason=(
                                    f"Pivot target '{proposal.target_host}' requires verified foothold "
                                    f"on '{pivot.from_host}', but none was found or evidence has expired."
                                ),
                            )
                    if pivot.allowed_categories and proposal.action_category not in pivot.allowed_categories:
                        return PolicyDecision(
                            approved=False,
                            reason=(
                                f"Pivot rule to '{proposal.target_host}' restricts actions to "
                                f"{pivot.allowed_categories}, but proposed category is '{proposal.action_category}'."
                            ),
                        )
                    target_authorized = True
                    active_pivot = pivot
                    break
            if not target_authorized:
                return PolicyDecision(
                    approved=False,
                    reason=(
                        f"Target '{proposal.target_host}' ({resolved_ip}) is not an authorized entry host "
                        "and no matching pivot rule authorizes targeting it."
                    ),
                )
        elif not self._allowed_hosts_set and not self.scope.authorized_chain.pivots and in_allowed_subnet:
            # Legacy fallback: scope defined subnets but no explicit entry hosts or pivot rules
            target_authorized = True
        else:
            return PolicyDecision(
                approved=False,
                reason=f"Target {proposal.target_host} ({resolved_ip}) is outside allowed targets.",
            )

        # 3. Port Allowlist Check (S-01)
        effective_port = self._infer_target_port(proposal)
        requested_ports: list[int] = []

        raw_port_spec = proposal.arguments.get("ports")
        if raw_port_spec not in (None, ""):
            parsed_ports = self._parse_port_spec(raw_port_spec)
            if parsed_ports is None:
                return PolicyDecision(
                    approved=False,
                    reason=(f"Invalid or out-of-range port specification '{raw_port_spec}'."),
                )
            requested_ports.extend(parsed_ports)

        if effective_port is not None and effective_port not in requested_ports:
            requested_ports.append(effective_port)

        if requested_ports:
            for port in sorted(set(requested_ports)):
                if port in self.scope.ports.denied_ports:
                    return PolicyDecision(
                        approved=False, reason=f"Port {port} is explicitly denied."
                    )
                if self.scope.ports.allowed_ports and port not in self.scope.ports.allowed_ports:
                    return PolicyDecision(
                        approved=False, reason=f"Port {port} is not in allowed ports."
                    )
                if active_pivot and active_pivot.allowed_ports and port not in active_pivot.allowed_ports:
                    return PolicyDecision(
                        approved=False,
                        reason=f"Port {port} is not permitted by pivot rule to '{proposal.target_host}' (allowed: {active_pivot.allowed_ports}).",
                    )
        elif self.scope.ports.allowed_ports:
            # Fail closed: a scan without an explicit port set would use the
            # scanner's default range, which may leave the allowlist.
            if proposal.action_category == "network_recon":
                return PolicyDecision(
                    approved=False,
                    reason=(
                        "Network reconnaissance must specify an explicit port set "
                        "when the scope restricts allowed ports."
                    ),
                )
            return PolicyDecision(
                approved=False,
                reason=(
                    "Target port is unspecified and could not be inferred, "
                    "but scope restricts allowed ports."
                ),
            )

        # 4. Embedded URL Argument Check (scope evasion defense)
        embedded_decision = self._validate_embedded_targets(
            proposal, footholds=footholds, simulation_mode=simulation_mode
        )
        if embedded_decision is not None:
            return embedded_decision

        # 5. Protocol Restriction Check (S-03)
        for proto in self._infer_protocols(proposal, requested_ports):
            if proto in self.scope.protocols.denied:
                return PolicyDecision(
                    approved=False, reason=f"Protocol '{proto}' is explicitly denied."
                )
            if self.scope.protocols.allowed and proto not in self.scope.protocols.allowed:
                return PolicyDecision(
                    approved=False, reason=f"Protocol '{proto}' is not in allowed protocols."
                )

        # 5. Action Category Allowlist Check
        if proposal.action_category in self.scope.actions.prohibited_categories:
            return PolicyDecision(
                approved=False,
                reason=f"Action category '{proposal.action_category}' is prohibited.",
            )
        if proposal.action_category not in self.scope.actions.allowed_categories:
            return PolicyDecision(
                approved=False,
                reason=f"Action category '{proposal.action_category}' is not in allowed categories.",
            )

        # 6. Bounded Multi-Step Chain Authorization (L-04)
        chain_decision = self._evaluate_chain_authorization(proposal)
        if chain_decision is not None:
            return chain_decision

        # 7. Argument Injection Scrubbing
        if not self._verify_arguments(proposal.arguments):
            return PolicyDecision(
                approved=False, reason="Arguments contain forbidden flags or shell tokens."
            )

        return PolicyDecision(
            approved=True, reason="Authorized by scope policy.", resolved_ip=resolved_ip
        )

    def validate_redirect(self, initial_url: str, redirect_target_url: str) -> PolicyDecision:
        """Validates an HTTP redirect against scope redirect policy and firewall rules (S-04)."""
        redirect_policy = self.scope.network_policy.redirect_policy.lower()

        if redirect_policy == "block_all":
            return PolicyDecision(
                approved=False,
                reason="HTTP redirects are prohibited by network policy (block_all).",
            )

        parsed_init = urllib.parse.urlparse(initial_url)
        parsed_target = urllib.parse.urlparse(redirect_target_url)

        init_host = parsed_init.hostname or ""
        target_host = parsed_target.hostname or ""

        init_port = parsed_init.port or (443 if parsed_init.scheme == "https" else 80)
        target_port = parsed_target.port or (443 if parsed_target.scheme == "https" else 80)

        # Guard against loopback, metadata, reserved IP addresses
        resolved_ip = self._resolve_host(target_host)
        if not resolved_ip:
            return PolicyDecision(
                approved=False, reason=f"Cannot resolve redirect target host '{target_host}'."
            )

        try:
            ip_obj = ipaddress.ip_address(resolved_ip)
            if (
                ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_reserved
                or ip_obj.is_multicast
            ):
                return PolicyDecision(
                    approved=False,
                    reason=f"Redirect to {resolved_ip} blocked (loopback/metadata/reserved).",
                )
        except ValueError:
            return PolicyDecision(
                approved=False, reason=f"Invalid IP address for redirect target '{target_host}'."
            )

        if redirect_policy == "strict_same_host":
            if target_host != init_host or target_port != init_port:
                return PolicyDecision(
                    approved=False,
                    reason=(
                        f"Redirect from {init_host}:{init_port} to {target_host}:{target_port} "
                        "violates strict_same_host policy."
                    ),
                )

        elif redirect_policy == "in_scope_only":
            in_subnets = any(ip_obj in s for s in self._parsed_subnets)
            in_hosts = (
                resolved_ip in self._allowed_hosts_set or target_host in self._allowed_hosts_set
            )
            if not (in_subnets or in_hosts):
                return PolicyDecision(
                    approved=False,
                    reason=f"Redirect target '{target_host}' ({resolved_ip}) is out of authorized scope.",
                )
            if target_port in self.scope.ports.denied_ports or (
                self.scope.ports.allowed_ports and target_port not in self.scope.ports.allowed_ports
            ):
                return PolicyDecision(
                    approved=False,
                    reason=f"Redirect target port {target_port} is not in allowed ports.",
                )

        return PolicyDecision(
            approved=True,
            reason="Redirect target is authorized under network policy.",
            resolved_ip=resolved_ip,
        )

    def _resolve_host(self, host: str) -> str | None:
        clean_host = host.strip("[]")
        # Fast path: already an IP literal
        try:
            ipaddress.ip_address(clean_host)
            return clean_host
        except ValueError:
            pass

        # Socket DNS resolution (supporting IPv4 mock hooks and IPv6)
        try:
            return socket.gethostbyname(clean_host)
        except (OSError, socket.gaierror, socket.herror):
            pass

        try:
            addr_info = socket.getaddrinfo(clean_host, None)
            if not addr_info:
                return None
            for _, _, _, _, sockaddr in addr_info:
                ip_str = str(sockaddr[0])
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    if (
                        ip_obj.is_loopback
                        or ip_obj.is_link_local
                        or ip_obj.is_reserved
                        or ip_obj.is_multicast
                    ):
                        return ip_str
                except ValueError:
                    continue
            return str(addr_info[0][4][0])
        except (OSError, socket.gaierror, socket.herror):
            return None

    def _verify_arguments(self, args: dict[str, Any]) -> bool:
        for val in args.values():
            s_val = str(val)
            if any(token in s_val for token in self._forbidden_tokens):
                return False
        return True
