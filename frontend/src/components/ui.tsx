import type { ReactNode } from "react";
import { motion } from "framer-motion";
import { AlertTriangle, ChevronLeft, ChevronRight, Loader2, RefreshCw, type LucideIcon } from "lucide-react";
import { cn } from "../lib/utils";

export function Panel({
  children,
  className,
  hover = false,
}: {
  children: ReactNode;
  className?: string;
  hover?: boolean;
}) {
  return <div className={cn("panel", hover && "panel-hover", className)}>{children}</div>;
}

export function SectionTitle({
  eyebrow,
  title,
  action,
  className,
}: {
  eyebrow?: string;
  title: string;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex items-end justify-between gap-3", className)}>
      <div>
        {eyebrow ? <p className="eyebrow mb-1.5">{eyebrow}</p> : null}
        <h2 className="text-base font-semibold tracking-tight text-white">{title}</h2>
      </div>
      {action}
    </div>
  );
}

export function StatCard({
  label,
  value,
  hint,
  icon: IconComponent,
  accent = "#00E5FF",
  delta,
  loading = false,
}: {
  label: string;
  value: string | number;
  hint?: string;
  icon: LucideIcon;
  accent?: string;
  delta?: { value: number; label: string };
  loading?: boolean;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="panel panel-hover group relative overflow-hidden p-4"
    >
      <div
        className="pointer-events-none absolute -right-8 -top-10 h-24 w-24 rounded-full blur-2xl transition-opacity group-hover:opacity-80"
        style={{ backgroundColor: `${accent}22`, opacity: 0.4 }}
      />
      <div className="relative flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="font-mono text-[9px] uppercase tracking-[0.2em] text-mist">{label}</p>
          {loading ? (
            <div className="skeleton mt-3 h-8 w-20" />
          ) : (
            <p className="stat-value mt-2.5">{value}</p>
          )}
          {hint ? <p className="mt-1.5 text-[11px] text-mist">{hint}</p> : null}
        </div>
        <div
          className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border"
          style={{ color: accent, backgroundColor: `${accent}12`, borderColor: `${accent}30` }}
        >
          <IconComponent size={17} strokeWidth={1.8} />
        </div>
      </div>
      {delta ? (
        <div className="relative mt-3 flex items-center gap-1.5 border-t border-line/60 pt-2.5">
          <span
            className="font-mono text-[10px]"
            style={{ color: delta.value >= 0 ? "#00FF88" : "#FF3B5C" }}
          >
            {delta.value >= 0 ? "+" : ""}
            {delta.value}
          </span>
          <span className="text-[10px] text-mist">{delta.label}</span>
        </div>
      ) : null}
    </motion.div>
  );
}

export function ProgressBar({
  value,
  color = "#00E5FF",
  height = 5,
  animated = false,
}: {
  value: number;
  color?: string;
  height?: number;
  animated?: boolean;
}) {
  return (
    <div className="overflow-hidden rounded-full bg-line/60" style={{ height }}>
      <motion.div
        initial={{ width: 0 }}
        animate={{ width: `${Math.max(0, Math.min(100, value))}%` }}
        transition={{ duration: 0.7, ease: "easeOut" }}
        className={cn("h-full rounded-full", animated && "animate-pulse")}
        style={{ backgroundColor: color, boxShadow: `0 0 12px ${color}66` }}
      />
    </div>
  );
}

export function EmptyState({
  icon: IconComponent,
  title,
  description,
  action,
  className,
}: {
  icon: LucideIcon;
  title: string;
  description?: string;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col items-center justify-center px-6 py-14 text-center", className)}>
      <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl border border-line bg-abyss text-cyan/70">
        <IconComponent size={24} strokeWidth={1.5} />
      </div>
      <p className="text-sm font-medium text-white">{title}</p>
      {description ? <p className="mt-1.5 max-w-md text-xs leading-relaxed text-mist">{description}</p> : null}
      {action ? <div className="mt-5">{action}</div> : null}
    </div>
  );
}

export function InlineSpinner({ label = "Loading" }: { label?: string }) {
  return (
    <span className="inline-flex items-center gap-2 font-mono text-[10px] uppercase tracking-wider text-mist">
      <Loader2 size={13} className="animate-spin text-cyan" />
      {label}
    </span>
  );
}

export function PageLoader({ label = "Establishing secure link" }: { label?: string }) {
  return (
    <div className="flex min-h-[50vh] flex-col items-center justify-center gap-4">
      <div className="relative flex h-16 w-16 items-center justify-center">
        <span className="absolute inset-0 animate-ping rounded-full border border-cyan/20" />
        <span className="absolute inset-2 rounded-full border border-cyan/30" />
        <Loader2 size={24} className="animate-spin text-cyan" />
      </div>
      <p className="font-mono text-[10px] uppercase tracking-[0.24em] text-mist">{label}</p>
    </div>
  );
}

export function SkeletonRows({ rows = 5 }: { rows?: number }) {
  return (
    <div className="space-y-2 p-4">
      {Array.from({ length: rows }).map((_, index) => (
        <div key={index} className="skeleton h-11 w-full" style={{ opacity: 1 - index * 0.12 }} />
      ))}
    </div>
  );
}

export function ErrorState({
  message,
  onRetry,
  className,
}: {
  message: string;
  onRetry?: () => void;
  className?: string;
}) {
  return (
    <div className={cn("panel flex flex-col items-center gap-3 p-8 text-center", className)}>
      <AlertTriangle size={24} className="text-crimson" />
      <p className="text-sm text-ice">{message}</p>
      {onRetry ? (
        <button onClick={onRetry} className="btn-ghost btn-sm">
          <RefreshCw size={13} /> Retry
        </button>
      ) : null}
    </div>
  );
}

export function Toggle({
  checked,
  onChange,
  label,
  description,
  disabled = false,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
  label: string;
  description?: string;
  disabled?: boolean;
}) {
  return (
    <label className={cn("flex cursor-pointer items-start gap-3 py-2", disabled && "cursor-not-allowed opacity-50")}>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={cn(
          "relative mt-0.5 h-5 w-9 shrink-0 rounded-full border transition-colors",
          checked ? "border-cyan/60 bg-cyan/25" : "border-line bg-abyss",
        )}
      >
        <span
          className={cn(
            "absolute top-0.5 h-3.5 w-3.5 rounded-full transition-all",
            checked ? "left-[18px] bg-cyan shadow-[0_0_10px_#00E5FF]" : "left-0.5 bg-slate-500",
          )}
        />
      </button>
      <span className="min-w-0">
        <span className="block text-xs font-medium text-ice">{label}</span>
        {description ? <span className="mt-0.5 block text-[10px] leading-relaxed text-mist">{description}</span> : null}
      </span>
    </label>
  );
}

export function Pagination({
  total,
  limit,
  offset,
  onChange,
}: {
  total: number;
  limit: number;
  offset: number;
  onChange: (offset: number) => void;
}) {
  const page = Math.floor(offset / limit) + 1;
  const pages = Math.max(1, Math.ceil(total / limit));
  if (total <= limit) return null;
  return (
    <div className="flex items-center justify-between gap-3 border-t border-line/60 px-4 py-3">
      <p className="font-mono text-[10px] text-mist">
        {offset + 1}–{Math.min(offset + limit, total)} of {total}
      </p>
      <div className="flex items-center gap-2">
        <button
          className="btn-ghost btn-sm"
          disabled={offset === 0}
          onClick={() => onChange(Math.max(0, offset - limit))}
          aria-label="Previous page"
        >
          <ChevronLeft size={14} />
        </button>
        <span className="font-mono text-[10px] text-mist">
          {page} / {pages}
        </span>
        <button
          className="btn-ghost btn-sm"
          disabled={offset + limit >= total}
          onClick={() => onChange(offset + limit)}
          aria-label="Next page"
        >
          <ChevronRight size={14} />
        </button>
      </div>
    </div>
  );
}
