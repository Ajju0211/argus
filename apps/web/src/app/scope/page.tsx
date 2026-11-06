"use client";

import { useState } from "react";
import Link from "next/link";
import { ArrowLeft, ShieldCheck, ShieldAlert, CheckCircle2, Lock, Flame } from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";

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
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <Link href="/" className="hover:text-foreground flex items-center gap-1 transition-colors">
          <ArrowLeft className="h-3 w-3" />
          Command Center
        </Link>
        <span>/</span>
        <span className="text-foreground font-medium">Scope Firewall</span>
      </div>

      <Card className="border-border/70">
        <CardHeader>
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <CardTitle className="text-base sm:text-lg">Deterministic Policy Firewall</CardTitle>
              <CardDescription>
                Strict authorization boundaries preventing agent drift, lateral movement, and out-of-scope attacks.
              </CardDescription>
            </div>
            <Badge variant="outline" className="gap-1.5 w-fit font-normal text-xs border-border/80">
              <ShieldCheck className="h-3.5 w-3.5 text-emerald-500" />
              Pre-Execution Gate Active
            </Badge>
          </div>
        </CardHeader>

        <CardContent className="space-y-6">
          {/* Active Firewall Rules Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card className="bg-muted/20 border-border/50">
              <CardHeader className="p-4 pb-2">
                <CardTitle className="text-xs uppercase tracking-wider text-muted-foreground font-medium">
                  Authorized Subnets (Allowlist)
                </CardTitle>
              </CardHeader>
              <CardContent className="p-4 pt-1 space-y-2 font-mono text-xs">
                <div className="flex items-center justify-between p-2 rounded bg-card border border-border/60">
                  <span>172.16.0.0/12</span>
                  <Badge variant="outline" className="text-[10px] font-normal">Docker Bridge Lab</Badge>
                </div>
                <div className="flex items-center justify-between p-2 rounded bg-card border border-border/60">
                  <span>192.168.100.0/24</span>
                  <Badge variant="outline" className="text-[10px] font-normal">Staging Range</Badge>
                </div>
                <div className="flex items-center justify-between p-2 rounded bg-card border border-border/60">
                  <span>127.0.0.1/32</span>
                  <Badge variant="outline" className="text-[10px] font-normal">Localhost Fixtures</Badge>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-muted/20 border-border/50">
              <CardHeader className="p-4 pb-2">
                <CardTitle className="text-xs uppercase tracking-wider text-muted-foreground font-medium">
                  Prohibited Zones (Denylist)
                </CardTitle>
              </CardHeader>
              <CardContent className="p-4 pt-1 space-y-2 font-mono text-xs">
                <div className="flex items-center justify-between p-2 rounded bg-card border border-border/60">
                  <span>169.254.169.254/32</span>
                  <Badge variant="destructive" className="text-[10px] font-normal">Cloud Metadata</Badge>
                </div>
                <div className="flex items-center justify-between p-2 rounded bg-card border border-border/60">
                  <span>0.0.0.0/8</span>
                  <Badge variant="destructive" className="text-[10px] font-normal">Broadcast / Null</Badge>
                </div>
                <div className="flex items-center justify-between p-2 rounded bg-card border border-border/60">
                  <span>Port 22, 25, 445</span>
                  <Badge variant="destructive" className="text-[10px] font-normal">Denied Ports</Badge>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Prohibited Categories */}
          <div className="space-y-2">
            <h4 className="text-xs uppercase tracking-wider text-muted-foreground font-medium">
              Strictly Prohibited Exploitation Classes
            </h4>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs">
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
                  className="p-2.5 rounded-md border border-border/60 bg-muted/20 text-foreground/80 text-[11px] font-medium flex items-center gap-2"
                >
                  <Lock className="h-3 w-3 text-muted-foreground/60 shrink-0" />
                  <span>{category}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Interactive Policy Inspector */}
          <div className="rounded-lg border border-border/70 bg-card p-4 sm:p-5 space-y-4">
            <div className="flex items-center gap-2">
              <Flame className="h-4 w-4 text-muted-foreground/60" />
              <h4 className="text-xs uppercase tracking-wider text-foreground font-semibold">
                Live Policy Boundary Simulator
              </h4>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="space-y-1">
                <label className="text-xs text-muted-foreground font-medium">Target Host</label>
                <Input
                  value={testHost}
                  onChange={(e) => setTestHost(e.target.value)}
                  placeholder="e.g. 172.16.0.5"
                  className="font-mono text-xs"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs text-muted-foreground font-medium">Target Port</label>
                <Input
                  value={testPort}
                  onChange={(e) => setTestPort(e.target.value)}
                  placeholder="e.g. 8080"
                  className="font-mono text-xs"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs text-muted-foreground font-medium">Simulated Command</label>
                <Input
                  value={testCommand}
                  onChange={(e) => setTestCommand(e.target.value)}
                  placeholder="e.g. nmap -sV -p 8080"
                  className="font-mono text-xs"
                />
              </div>
            </div>

            <div
              className={`p-3 rounded-md border text-xs flex items-center gap-2.5 ${
                evaluationResult.allowed
                  ? "border-border bg-muted/40 text-foreground"
                  : "border-rose-500/30 bg-rose-500/5 text-rose-500 dark:text-rose-400"
              }`}
            >
              {evaluationResult.allowed ? (
                <CheckCircle2 className="h-4 w-4 text-emerald-500 shrink-0" />
              ) : (
                <ShieldAlert className="h-4 w-4 text-rose-500 shrink-0" />
              )}
              <span className="font-mono text-xs">{evaluationResult.reason}</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
