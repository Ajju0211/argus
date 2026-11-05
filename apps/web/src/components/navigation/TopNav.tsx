"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Shield, Radio, Terminal, PlusCircle } from "lucide-react";
import { cn } from "@/lib/utils";

export function TopNav() {
  const pathname = usePathname();

  return (
    <header className="sticky top-0 z-50 w-full border-b border-cyber-border bg-cyber-bg/80 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        <div className="flex items-center gap-6">
          <Link href="/" className="flex items-center gap-3 group">
            <div className="relative flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-indigo-500 via-purple-500 to-cyan-500 p-[1px] shadow-lg shadow-indigo-500/20 group-hover:shadow-indigo-500/40 transition-shadow">
              <div className="flex h-full w-full items-center justify-center rounded-xl bg-cyber-bg">
                <Shield className="h-5 w-5 text-indigo-400 group-hover:text-cyan-400 transition-colors" />
              </div>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-lg font-black tracking-wider text-white">
                  ARGUS
                </span>
                <span className="rounded bg-indigo-500/20 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-indigo-300 border border-indigo-500/30">
                  AUTONOMOUS
                </span>
              </div>
              <p className="text-xs text-cyber-muted hidden sm:block">
                Zero-Hallucination Security Testing
              </p>
            </div>
          </Link>

          <nav className="hidden md:flex items-center gap-1">
            <Link
              href="/"
              className={cn(
                "flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-medium transition-colors",
                pathname === "/"
                  ? "bg-cyber-card text-white border border-cyber-border"
                  : "text-cyber-muted hover:text-white hover:bg-cyber-card/50"
              )}
            >
              <Terminal className="h-3.5 w-3.5 text-cyan-400" />
              Command Center
            </Link>
            <Link
              href="/new"
              className={cn(
                "flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-medium transition-colors",
                pathname === "/new"
                  ? "bg-cyber-card text-white border border-cyber-border"
                  : "text-cyber-muted hover:text-white hover:bg-cyber-card/50"
              )}
            >
              <PlusCircle className="h-3.5 w-3.5 text-indigo-400" />
              Launch Assessment
            </Link>
          </nav>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 rounded-full border border-cyber-border bg-cyber-panel/60 px-3 py-1 text-xs font-mono">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500"></span>
            </span>
            <span className="text-cyber-muted text-[11px]">Bifrost Gateway</span>
            <span className="text-emerald-400 font-semibold text-[11px]">ONLINE</span>
          </div>

          <Link
            href="/new"
            className="flex items-center gap-2 rounded-lg bg-gradient-to-r from-indigo-600 via-indigo-500 to-cyan-500 px-3.5 py-1.5 text-xs font-bold text-white shadow-md shadow-indigo-600/30 hover:brightness-110 active:scale-95 transition-all"
          >
            <PlusCircle className="h-3.5 w-3.5" />
            <span className="hidden sm:inline">New Assessment</span>
          </Link>
        </div>
      </div>
    </header>
  );
}

