"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Shield, Terminal, PlusCircle } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ThemeToggle } from "@/components/theme-toggle";

export function TopNav() {
  const pathname = usePathname();

  return (
    <header className="sticky top-0 z-50 w-full border-b border-border bg-card/80 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        <div className="flex items-center gap-6">
          <Link href="/" className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-md bg-primary text-primary-foreground shadow-sm">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-base font-bold tracking-wider text-foreground">
                  ARGUS
                </span>
                <Badge variant="outline" className="text-[10px]">
                  AUTONOMOUS
                </Badge>
              </div>
              <p className="text-xs text-muted-foreground hidden sm:block">
                Zero-Hallucination Security Testing
              </p>
            </div>
          </Link>

          <nav className="hidden md:flex items-center gap-1 font-mono text-xs">
            <Link
              href="/"
              className={cn(
                "flex items-center gap-2 rounded-md px-3 py-1.5 transition-colors",
                pathname === "/"
                  ? "bg-primary text-primary-foreground font-semibold"
                  : "text-muted-foreground hover:text-foreground hover:bg-muted"
              )}
            >
              <Terminal className="h-3.5 w-3.5" />
              Command Center
            </Link>
            <Link
              href="/new"
              className={cn(
                "flex items-center gap-2 rounded-md px-3 py-1.5 transition-colors",
                pathname === "/new"
                  ? "bg-primary text-primary-foreground font-semibold"
                  : "text-muted-foreground hover:text-foreground hover:bg-muted"
              )}
            >
              <PlusCircle className="h-3.5 w-3.5" />
              Launch Assessment
            </Link>
          </nav>
        </div>

        <div className="flex items-center gap-3">
          <Badge variant="success" className="gap-1.5 text-[11px]">
            <span className="h-2 w-2 rounded-full bg-primary animate-pulse" />
            Bifrost Gateway ONLINE
          </Badge>

          <ThemeToggle />

          <Link href="/new">
            <Button size="sm" className="gap-1.5">
              <PlusCircle className="h-3.5 w-3.5" />
              <span className="hidden sm:inline">New Assessment</span>
            </Button>
          </Link>
        </div>
      </div>
    </header>
  );
}
