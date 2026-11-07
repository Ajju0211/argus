"use client";

import * as React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  PlusCircle,
  ShieldCheck,
  Database,
  PanelLeftClose,
  PanelLeftOpen,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { useSidebar } from "@/components/layout/sidebar-context";

interface NavItem {
  title: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string;
}

interface NavSection {
  domain: string;
  items: NavItem[];
}

const NAV_SECTIONS: NavSection[] = [
  {
    domain: "Operations",
    items: [
      {
        title: "Command Center",
        href: "/",
        icon: LayoutDashboard,
      },
      {
        title: "New Assessment",
        href: "/new",
        icon: PlusCircle,
      },
    ],
  },
  {
    domain: "Security Policy",
    items: [
      {
        title: "Scope Firewall",
        href: "/scope",
        icon: ShieldCheck,
      },
    ],
  },
  {
    domain: "Compliance",
    items: [
      {
        title: "Evidence Vault",
        href: "/evidence",
        icon: Database,
      },
    ],
  },
];

export function AppSidebar() {
  const pathname = usePathname();
  const { isCollapsed, toggleSidebar } = useSidebar();

  return (
    <aside
      className={cn(
        "flex flex-col shrink-0 h-dvh bg-sidebar select-none  transition-[width] duration-200 ease-in-out overflow-hidden",
        isCollapsed ? "w-16" : "w-60"
      )}
    >
      {/* Brand & Identity Header */}
      <div className="h-[3.25rem] px-3.5 flex items-center justify-between shrink-0">
        {!isCollapsed ? (
          <>
            <Link href="/" className="flex items-center gap-2.5 min-w-0 group">
              <img
                src="/argus_logo.png"
                alt="ARGUS"
                className="h-6 w-auto object-contain shrink-0 rounded-xs dark:invert-0 invert"
              />
              <span className="font-sans text-sm sm:text-md font-semibold tracking-tight text-foreground truncate">
                ARGUS
              </span>
            </Link>
            <button
              onClick={toggleSidebar}
              type="button"
              className="text-muted-foreground hover:text-foreground hover:bg-sidebar-accent flex h-7 w-7 items-center justify-center rounded-md transition-colors shrink-0"
              aria-label="Collapse sidebar"
              title="Collapse sidebar"
            >
              <PanelLeftClose className="h-4 w-4" />
            </button>
          </>
        ) : (
          <div className="w-full flex items-center justify-center">
            <button
              onClick={toggleSidebar}
              type="button"
              className="group flex h-8 w-8 items-center justify-center rounded-md hover:bg-sidebar-accent transition-colors"
              aria-label="Expand sidebar"
              title="Expand sidebar"
            >
              <img
                src="/argus_logo.png"
                alt="ARGUS"
                className="h-6 w-full object-contain rounded-xs dark:invert-0 invert group-hover:hidden"
              />
              <PanelLeftOpen className="h-4 w-4 text-foreground hidden group-hover:block" />
            </button>
          </div>
        )}
      </div>

      {/* Navigation Sections */}
      <nav className="flex-1 overflow-y-auto px-2 py-3 space-y-4 custom-scrollbar">
        {NAV_SECTIONS.map((section) => (
          <div key={section.domain} className="space-y-1">
            {!isCollapsed && (
              <h4 className="px-2.5 text-[10px] font-medium uppercase tracking-wider text-muted-foreground/60">
                {section.domain}
              </h4>
            )}
            <div className="space-y-0.5">
              {section.items.map((item) => {
                const isActive =
                  item.href === "/"
                    ? pathname === "/"
                    : pathname.startsWith(item.href);
                const Icon = item.icon;

                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    title={isCollapsed ? item.title : undefined}
                    className={cn(
                      "flex items-center rounded-md text-xs transition-colors group",
                      isCollapsed
                        ? "h-9 w-9 mx-auto justify-center"
                        : "justify-between px-2.5 py-1.5",
                      isActive
                        ? "bg-accent text-accent-foreground font-medium shadow-2xs"
                        : "text-muted-foreground hover:bg-sidebar-accent hover:text-foreground"
                    )}
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <Icon
                        className={cn(
                          "h-4 w-4 shrink-0 transition-colors",
                          isActive
                            ? "text-foreground"
                            : "text-muted-foreground group-hover:text-foreground"
                        )}
                      />
                      {!isCollapsed && (
                        <span className="truncate">{item.title}</span>
                      )}
                    </div>
                    {!isCollapsed && item.badge && (
                      <Badge
                        variant="secondary"
                        className="text-[9px] py-0 px-1 border-border/50 font-normal"
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

      {/* Footer Bar: System Status */}
      {/* <div className="p-2.5 border-t border-border/60 shrink-0">
        {!isCollapsed ? (
          <div className="flex items-center justify-between px-2 py-1.5 rounded-md bg-muted/40 border border-border/50 text-[11px]">
            <span className="flex items-center gap-1.5 text-muted-foreground">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
              Agent Engine
            </span>
            <span className="text-foreground/80 font-medium text-[10px] tracking-wide">
              READY
            </span>
          </div>
        ) : (
          <div className="flex items-center justify-center py-1">
            <span
              className="h-2 w-2 rounded-full bg-emerald-500"
              title="Agent Engine: READY"
            />
          </div>
        )}
      </div> */}
    </aside>
  );
}
