"use client";

import * as React from "react";
import Link from "next/link";
import { PlusCircle, Shield, Menu, X, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ThemeToggle } from "@/components/theme-toggle";

export function AppHeader() {
  const [mobileMenuOpen, setMobileMenuOpen] = React.useState(false);

  return (
    <header className="h-16 border-b border-border bg-card/60 backdrop-blur-md px-4 sm:px-6 flex items-center justify-between sticky top-0 z-40">
      {/* Mobile brand & toggle */}
      <div className="flex items-center gap-3 md:hidden">
        <Button
          variant="ghost"
          size="icon"
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          aria-label="Toggle navigation"
        >
          {mobileMenuOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
        </Button>
        <Link href="/" className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-primary" />
          <span className="font-mono font-bold text-sm">ARGUS</span>
        </Link>
      </div>

      {/* Desktop Workspace Indicator */}
      <div className="hidden md:flex items-center gap-3">
        <div className="flex items-center gap-2 text-xs font-mono text-muted-foreground">
          <span>Environment:</span>
          <Badge variant="outline" className="font-mono text-[10px]">
            Self-Hosted Docker
          </Badge>
        </div>
        <span className="text-border">|</span>
        <div className="flex items-center gap-2 text-xs font-mono text-muted-foreground">
          <span>Routing:</span>
          <span className="text-primary font-semibold flex items-center gap-1">
            <span className="h-1.5 w-1.5 rounded-full bg-primary animate-pulse" />
            Bifrost OSS
          </span>
        </div>
      </div>

      {/* Right Actions */}
      <div className="flex items-center gap-2.5">
        <a
          href="http://localhost:8080"
          target="_blank"
          rel="noopener noreferrer"
          className="hidden sm:inline-flex"
        >
          <Button variant="outline" size="sm" className="gap-1.5 text-xs">
            <span>Bifrost Web UI</span>
            <ExternalLink className="h-3 w-3 opacity-60" />
          </Button>
        </a>

        <Link href="/new">
          <Button size="sm" className="gap-1.5">
            <PlusCircle className="h-3.5 w-3.5" />
            <span>New Assessment</span>
          </Button>
        </Link>

        <ThemeToggle className="ml-1" />
      </div>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="absolute top-16 left-0 w-full border-b border-border bg-card p-4 space-y-2 md:hidden shadow-lg animate-in fade-in slide-in-from-top-2">
          <Link
            href="/"
            onClick={() => setMobileMenuOpen(false)}
            className="block rounded-md px-3 py-2 text-xs font-mono hover:bg-muted text-foreground"
          >
            Command Center
          </Link>
          <Link
            href="/new"
            onClick={() => setMobileMenuOpen(false)}
            className="block rounded-md px-3 py-2 text-xs font-mono hover:bg-muted text-foreground"
          >
            New Assessment
          </Link>
          <Link
            href="/scope"
            onClick={() => setMobileMenuOpen(false)}
            className="block rounded-md px-3 py-2 text-xs font-mono hover:bg-muted text-foreground"
          >
            Scope Firewall
          </Link>
          <Link
            href="/evidence"
            onClick={() => setMobileMenuOpen(false)}
            className="block rounded-md px-3 py-2 text-xs font-mono hover:bg-muted text-foreground"
          >
            Merkle Audit Chain
          </Link>
        </div>
      )}
    </header>
  );
}
