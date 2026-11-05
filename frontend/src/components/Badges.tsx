import type { ReactNode } from "react";
import type { Severity } from "../lib/types";
import { SEVERITY, STATUS_STYLES } from "../lib/constants";
import { cn } from "../lib/utils";

export function SeverityBadge({ severity, dot = true }: { severity: Severity; dot?: boolean }) {
  const config = SEVERITY[severity] || SEVERITY.info;
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider"
      style={{ color: config.color, backgroundColor: config.bg, borderColor: config.border }}
    >
      {dot ? <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: config.color }} /> : null}
      {config.label}
    </span>
  );
}

export function StatusBadge({ status, pulse = false }: { status: string; pulse?: boolean }) {
  const config = STATUS_STYLES[status] || { label: status.replace(/_/g, " "), color: "#94A3B8", bg: "rgba(148,163,184,0.1)" };
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-md border border-transparent px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider"
      style={{ color: config.color, backgroundColor: config.bg }}
    >
      <span
        className={cn("h-1.5 w-1.5 rounded-full", (status === "running" || pulse) && "animate-pulse")}
        style={{ backgroundColor: config.color }}
      />
      {config.label}
    </span>
  );
}

export function DemoBadge({ compact = false }: { compact?: boolean }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-md border border-amber/30 bg-amber/10 px-2 py-0.5 font-mono text-[9px] uppercase tracking-[0.16em] text-amber">
      <span className="h-1 w-1 rounded-full bg-amber" />
      {compact ? "Demo" : "Demo dataset"}
    </span>
  );
}

export function Chip({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn("chip", className)}>{children}</span>;
}

export function RiskPill({ score }: { score: number }) {
  const color = score >= 80 ? "#FF3B5C" : score >= 60 ? "#FF7A45" : score >= 40 ? "#FFB020" : score > 0 ? "#38BDF8" : "#64748B";
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-md border border-transparent px-2 py-0.5 font-mono text-[10px] font-medium"
      style={{ color, backgroundColor: `${color}18` }}
    >
      {score.toFixed(1)}
      <span className="text-[8px] uppercase tracking-wider opacity-70">risk</span>
    </span>
  );
}
