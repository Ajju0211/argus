"use client";

import { useState } from "react";
import Link from "next/link";
import { ArrowLeft, ShieldCheck, ShieldAlert, CheckCircle2, Lock, Flame } from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

export default function ScopeFirewallPage() {
  const [testHost, setTestHost] = useState("169.254.169.254");
  const [testPort, setTestPort] = useState("80");
  const [testCommand, setTestCommand] = useState("curl http://mock-target-lab:8080");

  const isBlockedHost =
    testHost.includes("169.254.169.254") ||
    testHost.includes("metadata.google.internal") ||
    testHost.includes("0.0.0.0");

  const hasDangerousTokens = [";", "&&", "||", "`", "$(", ">", "<", "|", "--exec"].some(
    (tok) => testCommand.includes(tok)
  );

  const evaluationResult = isBlockedHost
    ? { allowed: false, reason: "BLOCKED: Destination IP matches prohibited Cloud Metadata / Loopback boundary." }
    : hasDangerousTokens
    ? { allowed: false, reason: "BLOCKED: Command contains prohibited shell injection token or unquoted pipe." }
    : { allowed: true, reason: "PERMITTED: Target and tool arguments comply with authorized scope boundaries." };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Top Breadcrumb */}
      <div className="flex items-center gap-2 text-xs font-mono text-muted-foreground">
        <Link href="/" className="hover:text-foreground flex items-center gap-1 transition-colors">
          <ArrowLeft className="h-3 w-3" />
          Command Center
        </Link>
        <span>/</span>
        <span className="text-foreground">Scope & Policy Firewall Tool</span>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-xl">Deterministic Policy Firewall</CardTitle>
              <CardDescription>
                Strict authorization boundaries preventing agent drift, lateral movement, and out-of-scope attacks.
              </CardDescription>
            </div>
            <Badge variant="success" className="gap-1.5 font-mono">
              <ShieldCheck className="h-3.5 w-3.5" />
              Pre-Execution Gate Active
            </Badge>
          </div>
        </CardHeader>

        <CardContent className="space-y-6">
          {/* Active Firewall Rules Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card className="bg-muted/30">
              <CardHeader className="p-4 pb-2">
                <CardTitle className="text-xs uppercase tracking-wider text-muted-foreground">
                  Authorized Subnets (Allowlist)
                </CardTitle>
              </CardHeader>
              <CardContent className="p-4 pt-1 space-y-2 font-mono text-xs">
                <div className="flex items-center justify-between p-2 rounded bg-background border border-border">
                  <span>172.16.0.0/12</span>
                  <Badge variant="success">Docker Bridge Lab</Badge>
                </div>
                <div className="flex items-center justify-between p-2 rounded bg-background border border-border">
                  <span>192.168.100.0/24</span>
                  <Badge variant="outline">Staging Range</Badge>
                </div>
                <div className="flex items-center justify-between p-2 rounded bg-background border border-border">
                  <span>127.0.0.1/32</span>
                  <Badge variant="outline">Localhost Fixtures</Badge>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-muted/30">
              <CardHeader className="p-4 pb-2">
                <CardTitle className="text-xs uppercase tracking-wider text-muted-foreground">
                  Prohibited Zones (Denylist)
                </CardTitle>
              </CardHeader>
              <CardContent className="p-4 pt-1 space-y-2 font-mono text-xs">
                <div className="flex items-center justify-between p-2 rounded bg-background border border-border">
                  <span>169.254.169.254/32</span>
                  <Badge variant="destructive">AWS/GCP Metadata</Badge>
                </div>
                <div className="flex items-center justify-between p-2 rounded bg-background border border-border">
                  <span>0.0.0.0/8</span>
                  <Badge variant="destructive">Broadcast / Null</Badge>
                </div>
                <div className="flex items-center justify-between p-2 rounded bg-background border border-border">
                  <span>Port 22, 25, 445</span>
                  <Badge variant="destructive">Denied Ports</Badge>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Prohibited Categories */}
          <div className="space-y-2">
            <h4 className="text-xs font-mono uppercase tracking-wider text-muted-foreground font-semibold">
              Strictly Prohibited Exploitation Classes
            </h4>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 font-mono text-xs">
              {[
                "Denial of Service (DoS)",
                "Credential Brute-Force",
                "Arbitrary Command Injection",
                "Lateral Subnet Movement",
                "Host Privilege Escalation",
                "Data Exfiltration",
              ].map((category) => (
                <div
                  key={category}
                  className="p-2.5 rounded-md border border-destructive/25 bg-destructive/10 text-destructive text-[11px] font-semibold flex items-center gap-2"
                >
                  <Lock className="h-3 w-3 shrink-0" />
                  <span>{category}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Interactive Policy Inspector */}
          <div className="rounded-lg border border-border bg-card p-5 space-y-4">
            <div className="flex items-center gap-2">
              <Flame className="h-4 w-4 text-primary" />
              <h4 className="text-xs font-mono uppercase tracking-wider text-foreground font-bold">
                Live Policy Boundary Simulator
              </h4>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="space-y-1">
                <label className="text-[11px] font-mono text-muted-foreground">Target Host</label>
                <Input
                  value={testHost}
                  onChange={(e) => setTestHost(e.target.value)}
                  placeholder="e.g. 172.16.0.5"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[11px] font-mono text-muted-foreground">Target Port</label>
                <Input
                  value={testPort}
                  onChange={(e) => setTestPort(e.target.value)}
                  placeholder="e.g. 8080"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[11px] font-mono text-muted-foreground">Simulated Command</label>
                <Input
                  value={testCommand}
                  onChange={(e) => setTestCommand(e.target.value)}
                  placeholder="e.g. nmap -sV -p 8080"
                />
              </div>
            </div>

            <div
              className={`p-3 rounded-md border font-mono text-xs flex items-center gap-2.5 ${
                evaluationResult.allowed
                  ? "border-primary/30 bg-primary/10 text-primary"
                  : "border-destructive/30 bg-destructive/10 text-destructive"
              }`}
            >
              {evaluationResult.allowed ? (
                <CheckCircle2 className="h-4 w-4 shrink-0" />
              ) : (
                <ShieldAlert className="h-4 w-4 shrink-0" />
              )}
              <span>{evaluationResult.reason}</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
