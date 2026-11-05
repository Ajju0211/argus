import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatBytes(bytes: number, decimals = 2): string {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + " " + sizes[i];
}

export function formatTimeAgo(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const seconds = Math.floor((now.getTime() - date.getTime()) / 1000);

  if (seconds < 60) return `${Math.max(1, seconds)}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function formatCurrency(amount: number): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 3,
    maximumFractionDigits: 4,
  }).format(amount);
}

export function truncateHash(hash: string, length = 8): string {
  if (!hash) return "—";
  if (hash.length <= length * 2) return hash;
  return `${hash.slice(0, length)}…${hash.slice(-length)}`;
}

export function getSeverityColor(severity: string) {
  switch (severity?.toUpperCase()) {
    case "CRITICAL":
    case "HIGH":
      return {
        bg: "bg-destructive/10",
        border: "border-destructive/30",
        text: "text-destructive",
        badge: "bg-destructive/15 text-destructive border-destructive/30",
      };
    case "MEDIUM":
      return {
        bg: "bg-muted",
        border: "border-border",
        text: "text-foreground",
        badge: "bg-muted text-foreground border-border",
      };
    case "LOW":
    case "INFO":
    default:
      return {
        bg: "bg-muted/50",
        border: "border-border",
        text: "text-muted-foreground",
        badge: "bg-muted text-muted-foreground border-border",
      };
  }
}

export function getStatusColor(status: string) {
  switch (status?.toUpperCase()) {
    case "RUNNING":
      return {
        badge: "bg-primary/10 text-primary border-primary/30",
        dot: "bg-primary animate-pulse",
      };
    case "SUCCESS":
    case "COMPLETED":
      return {
        badge: "bg-primary/10 text-primary border-primary/30",
        dot: "bg-primary",
      };
    case "FAILED":
    case "CANCELLED":
      return {
        badge: "bg-destructive/10 text-destructive border-destructive/30",
        dot: "bg-destructive",
      };
    case "PAUSED":
    case "READY":
    case "QUEUED":
    default:
      return {
        badge: "bg-muted text-muted-foreground border-border",
        dot: "bg-muted-foreground",
      };
  }
}

