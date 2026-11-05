"use client";

import * as React from "react";
import { Moon, Sun } from "lucide-react";
import { useTheme } from "@/components/theme-provider";
import { Button } from "@/components/ui/button";

export function ThemeToggle({ className }: { className?: string }) {
  const { resolvedTheme, toggleTheme } = useTheme();

  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={toggleTheme}
      className={className}
      aria-label="Toggle theme mode"
      title={`Switch to ${resolvedTheme === "dark" ? "light" : "dark"} mode`}
    >
      {resolvedTheme === "dark" ? (
        <>
          <Sun className="h-4 w-4 text-primary" />
          <span className="text-[11px] font-mono hidden sm:inline">Light</span>
        </>
      ) : (
        <>
          <Moon className="h-4 w-4 text-primary" />
          <span className="text-[11px] font-mono hidden sm:inline">Dark</span>
        </>
      )}
    </Button>
  );
}
