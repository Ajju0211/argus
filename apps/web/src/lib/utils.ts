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
      return {
        bg: "bg-rose-500/10",
        border: "border-rose-500/30",
        text: "text-rose-400",
        badge: "bg-rose-500/20 text-rose-300 border-rose-500/40",
      };
    case "HIGH":
      return {
        bg: "bg-orange-500/10",
        border: "border-orange-500/30",
        text: "text-orange-400",
        badge: "bg-orange-500/20 text-orange-300 border-orange-500/40",
      };
    case "MEDIUM":
      return {
        bg: "bg-amber-500/10",
        border: "border-amber-500/30",
        text: "text-amber-400",
        badge: "bg-amber-500/20 text-amber-300 border-amber-500/40",
      };
    case "LOW":
      return {
        bg: "bg-blue-500/10",
        border: "border-blue-500/30",
        text: "text-blue-400",
        badge: "bg-blue-500/20 text-blue-300 border-blue-500/40",
      };
    default:
      return {
        bg: "bg-slate-500/10",
        border: "border-slate-500/30",
        text: "text-slate-400",
        badge: "bg-slate-500/20 text-slate-300 border-slate-500/40",
      };
  }
}

export function getStatusColor(status: string) {
  switch (status?.toUpperCase()) {
    case "RUNNING":
      return {
        badge: "bg-cyan-500/20 text-cyan-300 border-cyan-500/40",
        dot: "bg-cyan-400 animate-pulse",
      };
    case "PAUSED":
      return {
        badge: "bg-amber-500/20 text-amber-300 border-amber-500/40",
        dot: "bg-amber-400",
      };
    case "SUCCESS":
    case "COMPLETED":
      return {
        badge: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
        dot: "bg-emerald-400",
      };
    case "FAILED":
    case "CANCELLED":
      return {
        badge: "bg-rose-500/20 text-rose-300 border-rose-500/40",
        dot: "bg-rose-400",
      };
    case "READY":
    case "QUEUED":
    default:
      return {
        badge: "bg-slate-500/20 text-slate-300 border-slate-500/40",
        dot: "bg-slate-400",
      };
  }
}

