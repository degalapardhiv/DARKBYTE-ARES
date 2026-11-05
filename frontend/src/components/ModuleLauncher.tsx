import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowUpRight, Search, ShieldCheck } from "lucide-react";
import { MODULE_META } from "../lib/constants";
import { Icon } from "./Icon";
import { Modal } from "./Modal";

export function ModuleLauncher({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const modules = useMemo(
    () =>
      Object.values(MODULE_META).filter((module) => {
        const haystack = `${module.name} ${module.short} ${module.category} ${module.capabilities.join(" ")}`.toLowerCase();
        return haystack.includes(query.trim().toLowerCase());
      }),
    [query],
  );

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Launch a module workspace"
      eyebrow="Scoped operation"
      description="Every assessment requires a verified target and an action that appears in its authorization allowlist."
      size="xl"
    >
      <div className="relative mb-4">
        <Search size={15} className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search modules and capabilities…"
          className="input pl-10"
          autoFocus
        />
      </div>
      <div className="grid gap-2.5 sm:grid-cols-2 lg:grid-cols-3">
        {modules.map((module) => (
          <button
            key={module.id}
            onClick={() => {
              onClose();
              navigate(module.path);
            }}
            className="group relative overflow-hidden rounded-xl border border-line/80 bg-abyss/60 p-3.5 text-left transition hover:border-cyan/30 hover:bg-cyan/[0.04]"
          >
            <div
              className="pointer-events-none absolute -right-6 -top-8 h-20 w-20 rounded-full blur-2xl opacity-30 transition group-hover:opacity-60"
              style={{ backgroundColor: module.accent }}
            />
            <div className="relative flex items-start gap-3">
              <span
                className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border"
                style={{ color: module.accent, borderColor: `${module.accent}35`, backgroundColor: `${module.accent}12` }}
              >
                <Icon name={module.icon} size={16} />
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate text-xs font-medium text-white">{module.name}</span>
                  <ArrowUpRight size={13} className="shrink-0 text-slate-600 transition group-hover:text-cyan" />
                </div>
                <p className="mt-1 line-clamp-2 text-[10px] leading-relaxed text-mist">{module.short}</p>
                <div className="mt-2 flex items-center gap-2 font-mono text-[8px] uppercase tracking-wider text-slate-600">
                  <span>{module.number}</span>
                  <span>·</span>
                  <span>{module.category}</span>
                </div>
              </div>
            </div>
          </button>
        ))}
      </div>
      {!modules.length ? <p className="py-8 text-center text-xs text-mist">No module matches that search.</p> : null}
      <div className="mt-4 flex items-start gap-2 rounded-lg border border-amber/20 bg-amber/5 p-3 text-[10px] leading-relaxed text-mist">
        <ShieldCheck size={14} className="mt-0.5 shrink-0 text-amber" />
        Unverified targets cannot be assessed. An administrator must approve scope and explicitly allowlist the
        selected action before execution.
      </div>
    </Modal>
  );
}
