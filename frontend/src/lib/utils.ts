import type { Assessment, Severity } from "./types";
import { MODULE_META, SEVERITY, SEVERITY_ORDER } from "./constants";

export function cn(...values: (string | false | null | undefined)[]): string {
  return values.filter(Boolean).join(" ");
}

export function formatDate(value: string | null | undefined, withTime = true): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    ...(withTime ? { hour: "2-digit", minute: "2-digit" } : {}),
  });
}

export function timeAgo(value: string | null | undefined): string {
  if (!value) return "unknown";
  const date = new Date(value).getTime();
  if (Number.isNaN(date)) return "unknown";
  const seconds = Math.round((Date.now() - date) / 1000);
  if (seconds < 45) return "just now";
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
  if (seconds < 604800) return `${Math.round(seconds / 86400)}d ago`;
  return formatDate(value, false);
}

export function formatBytes(bytes: number): string {
  if (!bytes || bytes < 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** index).toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

export function riskColor(score: number): string {
  if (score >= 80) return "#FF3B5C";
  if (score >= 60) return "#FF7A45";
  if (score >= 40) return "#FFB020";
  if (score > 0) return "#38BDF8";
  return "#64748B";
}

export function riskLabel(score: number): string {
  if (score >= 80) return "Severe";
  if (score >= 60) return "Elevated";
  if (score >= 40) return "Moderate";
  if (score > 0) return "Guarded";
  return "Baseline";
}

export function moduleLabel(module: string): string {
  return MODULE_META[module]?.name || module.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export function severityRank(severity: Severity): number {
  return SEVERITY[severity]?.rank ?? 0;
}

export function severityFromScore(score: number | null): Severity {
  if (score === null || score === undefined) return "info";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "info";
}

export function countSeverities(items: { severity: Severity }[]): Record<Severity, number> {
  const counts = Object.fromEntries(SEVERITY_ORDER.map((level) => [level, 0])) as Record<Severity, number>;
  items.forEach((item) => {
    if (counts[item.severity] !== undefined) counts[item.severity] += 1;
  });
  return counts;
}

export function initials(name: string): string {
  return name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join("");
}

export function assessmentTone(assessment: Assessment): string {
  if (assessment.status === "completed") return riskColor(assessment.risk_score);
  if (assessment.status === "failed") return "#FF3B5C";
  if (assessment.status === "running" || assessment.status === "queued") return "#00E5FF";
  return "#64748B";
}

export function truncate(value: string, length = 120): string {
  if (value.length <= length) return value;
  return `${value.slice(0, length - 1)}…`;
}

export function parseCommaList(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

export function parsePortList(value: string): number[] {
  const ports = new Set<number>();
  parseCommaList(value).forEach((chunk) => {
    if (chunk.includes("-")) {
      const [start, end] = chunk.split("-").map((part) => Number(part.trim()));
      if (Number.isInteger(start) && Number.isInteger(end) && end >= start) {
        for (let port = start; port <= Math.min(end, start + 512); port += 1) ports.add(port);
      }
    } else {
      const port = Number(chunk);
      if (Number.isInteger(port)) ports.add(port);
    }
  });
  return [...ports].filter((port) => port >= 1 && port <= 65535).sort((a, b) => a - b);
}

export function safeJsonParse<T>(value: string): { ok: true; data: T } | { ok: false; error: string } {
  try {
    return { ok: true, data: JSON.parse(value) as T };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : "Invalid JSON." };
  }
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

export function percent(value: number, total: number): number {
  if (!total) return 0;
  return Math.max(0, Math.min(100, Math.round((value / total) * 100)));
}
