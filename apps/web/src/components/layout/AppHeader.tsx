"use client";

import * as React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Menu, X, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ThemeToggle } from "@/components/theme-toggle";

export function AppHeader() {
  const [mobileMenuOpen, setMobileMenuOpen] = React.useState(false);
  const pathname = usePathname();

  const routeTitle = React.useMemo(() => {
    if (pathname === "/") return "Command Center";
    if (pathname === "/new") return "New Assessment";
    if (pathname === "/scope") return "Scope Firewall";
    if (pathname === "/evidence") return "Evidence Vault";
    if (pathname.startsWith("/assessments/")) {
      if (pathname.endsWith("/evidence")) return "Assessment Evidence";
      if (pathname.endsWith("/report")) return "Assessment Report";
      return "Live Assessment";
    }
    return "Command Center";
  }, [pathname]);

  return (
    <header className="h-[3.25rem] px-4 md:px-6 flex items-center justify-between shrink-0 select-none">
      {/* Left: Mobile trigger / Breadcrumbs */}
      <div className="flex items-center gap-2">
        {/* Mobile menu button */}
        <div className="flex items-center gap-2 md:hidden">
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Toggle navigation"
            className="h-8 w-8 text-muted-foreground"
          >
            {mobileMenuOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
          </Button>
          <Link href="/" className="flex items-center gap-2">
            <img
              src="/argus_logo.png"
              alt="ARGUS"
              className="h-7 w-7 object-contain rounded-xs dark:invert-0 invert"
            />
            <span className="font-sans font-semibold text-xs tracking-tight text-foreground">
              ARGUS
            </span>
          </Link>
        </div>

        {/* Desktop Breadcrumbs */}
        <div className="hidden md:flex items-center gap-1.5 text-xs">
          <Link href="/" className="text-muted-foreground hover:text-foreground transition-colors font-medium">
            ARGUS
          </Link>
          <ChevronRight className="h-3 w-3 text-muted-foreground/40" />
          <span className="font-medium text-foreground">{routeTitle}</span>
        </div>
      </div>

      {/* Right Actions: Single Theme Switch */}
      <div className="flex items-center gap-2">
        <ThemeToggle />
      </div>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="absolute top-[3.25rem] left-0 w-full border-b border-border bg-card p-4 space-y-1.5 md:hidden shadow-md z-50">
          <Link
            href="/"
            onClick={() => setMobileMenuOpen(false)}
            className="block rounded-md px-3 py-2 text-xs font-medium hover:bg-muted text-foreground"
          >
            Command Center
          </Link>
          <Link
            href="/new"
            onClick={() => setMobileMenuOpen(false)}
            className="block rounded-md px-3 py-2 text-xs font-medium hover:bg-muted text-foreground"
          >
            New Assessment
          </Link>
          <Link
            href="/scope"
            onClick={() => setMobileMenuOpen(false)}
            className="block rounded-md px-3 py-2 text-xs font-medium hover:bg-muted text-foreground"
          >
            Scope Firewall
          </Link>
          <Link
            href="/evidence"
            onClick={() => setMobileMenuOpen(false)}
            className="block rounded-md px-3 py-2 text-xs font-medium hover:bg-muted text-foreground"
          >
            Evidence Vault
          </Link>
        </div>
      )}
    </header>
  );
}
