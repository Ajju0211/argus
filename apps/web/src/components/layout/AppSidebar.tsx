"use client";

import * as React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Terminal,
  PlusCircle,
  ShieldCheck,
  Database,
  ExternalLink,
  Shield,
  Activity,
  Cpu,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { ThemeToggle } from "@/components/theme-toggle";

interface NavItem {
  title: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  isExternal?: boolean;
  badge?: string;
}

interface NavSection {
  domain: string;
  items: NavItem[];
}

const NAV_SECTIONS: NavSection[] = [
  {
    domain: "Assessment Operations",
    items: [
      {
        title: "Command Center",
        href: "/",
        icon: Terminal,
      },
      {
        title: "New Assessment",
        href: "/new",
        icon: PlusCircle,
        badge: "Target",
      },
    ],
  },
  {
    domain: "Policy & Governance",
    items: [
      {
        title: "Scope Firewall",
        href: "/scope",
        icon: ShieldCheck,
      },
    ],
  },
  {
    domain: "Evidence Vault",
    items: [
      {
        title: "Merkle Audit Chain",
        href: "/evidence",
        icon: Database,
      },
    ],
  },
  {
    domain: "AI Gateway Engine",
    items: [
      {
        title: "Bifrost Gateway UI",
        href: "http://localhost:8080",
        icon: Cpu,
        isExternal: true,
        badge: ":8080",
      },
    ],
  },
];

export function AppSidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-64 border-r border-border bg-card/60 backdrop-blur-md flex flex-col shrink-0 h-screen sticky top-0">
      {/* Brand & Identity */}
      <div className="h-16 border-b border-border px-5 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-2.5 group">
          <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary text-primary-foreground shadow-sm">
            <Shield className="h-4 w-4" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="font-mono text-sm font-bold tracking-wider text-foreground">
                ARGUS
              </span>
              <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-muted text-muted-foreground border border-border">
                OSS
              </span>
            </div>
            <p className="text-[10px] font-mono text-muted-foreground">
              Zero-Hallucination SecOps
            </p>
          </div>
        </Link>
      </div>

      {/* Navigation Sections (Domain-Driven) */}
      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-6">
        {NAV_SECTIONS.map((section) => (
          <div key={section.domain} className="space-y-1">
            <h4 className="px-3 text-[10px] font-mono uppercase tracking-wider text-muted-foreground font-semibold">
              {section.domain}
            </h4>
            <div className="space-y-0.5">
              {section.items.map((item) => {
                const isActive =
                  item.href === "/"
                    ? pathname === "/"
                    : !item.isExternal && pathname.startsWith(item.href);
                const Icon = item.icon;

                if (item.isExternal) {
                  return (
                    <a
                      key={item.href}
                      href={item.href}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center justify-between rounded-md px-3 py-2 text-xs font-mono text-muted-foreground hover:bg-accent hover:text-foreground transition-colors group"
                    >
                      <div className="flex items-center gap-2.5">
                        <Icon className="h-4 w-4 text-muted-foreground group-hover:text-primary transition-colors" />
                        <span>{item.title}</span>
                      </div>
                      <div className="flex items-center gap-1">
                        {item.badge && (
                          <Badge variant="outline" className="text-[9px] py-0 px-1">
                            {item.badge}
                          </Badge>
                        )}
                        <ExternalLink className="h-3 w-3 opacity-60" />
                      </div>
                    </a>
                  );
                }

                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={cn(
                      "flex items-center justify-between rounded-md px-3 py-2 text-xs font-mono transition-colors",
                      isActive
                        ? "bg-primary text-primary-foreground font-semibold shadow-sm"
                        : "text-muted-foreground hover:bg-accent hover:text-foreground"
                    )}
                  >
                    <div className="flex items-center gap-2.5">
                      <Icon
                        className={cn(
                          "h-4 w-4",
                          isActive ? "text-primary-foreground" : "text-muted-foreground"
                        )}
                      />
                      <span>{item.title}</span>
                    </div>
                    {item.badge && (
                      <Badge
                        variant={isActive ? "secondary" : "outline"}
                        className="text-[9px] py-0 px-1"
                      >
                        {item.badge}
                      </Badge>
                    )}
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Infrastructure Telemetry & Tool Health Status */}
      <div className="p-3 border-t border-border space-y-2">
        <div className="rounded-md border border-border bg-muted/40 p-2.5 space-y-1.5 text-[11px] font-mono">
          <div className="flex items-center justify-between text-muted-foreground">
            <span className="flex items-center gap-1.5">
              <Activity className="h-3 w-3 text-primary animate-pulse" />
              Bifrost Gateway
            </span>
            <span className="text-primary font-bold">ONLINE</span>
          </div>
          <div className="flex items-center justify-between text-muted-foreground">
            <span>Target Lab</span>
            <span className="text-foreground">:8888</span>
          </div>
        </div>

        {/* Footer Bar: Theme Toggle & Version */}
        <div className="flex items-center justify-between px-1">
          <ThemeToggle />
          <span className="text-[10px] font-mono text-muted-foreground">
            ARGUS v1.0
          </span>
        </div>
      </div>
    </aside>
  );
}
