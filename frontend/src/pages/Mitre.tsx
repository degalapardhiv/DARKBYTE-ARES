import { useCallback, useEffect, useMemo, useState } from "react";
import {
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  Grid3X3,
  Info,
  Layers,
  RefreshCw,
  Search,
  Shield,
} from "lucide-react";
import { PageHeader } from "../components/PageHeader";
import { Panel, SectionTitle, ErrorState, PageLoader, EmptyState, ProgressBar, Toggle } from "../components/ui";
import { Modal } from "../components/Modal";
import { api } from "../lib/api";
import type { MitreCoverage, MitreTactic, MitreTechnique } from "../lib/types";
import { cn, formatDate } from "../lib/utils";

const PAGE_SIZE = 60;

export function Mitre() {
  const [tactics, setTactics] = useState<MitreTactic[]>([]);
  const [coverage, setCoverage] = useState<MitreCoverage | null>(null);
  const [techniques, setTechniques] = useState<MitreTechnique[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [query, setQuery] = useState("");
  const [debounced, setDebounced] = useState("");
  const [activeTactic, setActiveTactic] = useState("");
  const [includeSubtechniques, setIncludeSubtechniques] = useState(false);
  const [source, setSource] = useState<Record<string, any>>({});
  const [loading, setLoading] = useState(true);
  const [listLoading, setListLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<MitreTechnique | null>(null);

  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(query), 320);
    return () => window.clearTimeout(timer);
  }, [query]);

  useEffect(() => {
    Promise.all([api.mitre.tactics(), api.mitre.coverage()])
      .then(([tacticResponse, coverageResponse]) => {
        setTactics(tacticResponse.items);
        setSource(tacticResponse.source);
        setCoverage(coverageResponse);
        setError(null);
      })
      .catch((reason) => setError(reason instanceof Error ? reason.message : "Could not load ATT&CK data."))
      .finally(() => setLoading(false));
  }, []);

  const loadTechniques = useCallback(async () => {
    setListLoading(true);
    try {
      const response = await api.mitre.techniques({
        query: debounced || undefined,
        tactic: activeTactic || undefined,
        include_subtechniques: includeSubtechniques,
        limit: PAGE_SIZE,
        offset,
      });
      setTechniques(response.items);
      setTotal(response.total);
      setSource((current) => ({ ...current, ...response.source }));
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not load ATT&CK techniques.");
    } finally {
      setListLoading(false);
    }
  }, [debounced, activeTactic, includeSubtechniques, offset]);

  useEffect(() => {
    void loadTechniques();
  }, [loadTechniques]);

  const observed = useMemo(() => new Set(coverage?.observed_technique_ids || []), [coverage]);
  const tacticByShortname = useMemo(() => {
    const map = new Map<string, MitreTactic>();
    tactics.forEach((tactic) => map.set(tactic.shortname, tactic));
    return map;
  }, [tactics]);
  const coverageByShortname = useMemo(() => {
    const map = new Map<string, MitreCoverage["tactics"][number]>();
    coverage?.tactics.forEach((tactic) => map.set(tactic.shortname, tactic));
    return map;
  }, [coverage]);

  if (loading) return <PageLoader label="Loading MITRE ATT&CK matrix" />;

  return (
    <div>
      <PageHeader
        eyebrow="Detection engineering"
        title="MITRE ATT&CK coverage"
        description="Observed techniques are derived from finding mappings across every assessment. Coverage is a planning signal, not proof of detection efficacy — validate controls in an isolated lab."
        actions={
          <button className="btn-ghost" onClick={() => void loadTechniques()} disabled={listLoading}>
            <RefreshCw size={14} className={listLoading ? "animate-spin" : ""} /> Refresh
          </button>
        }
      />

      {error ? <ErrorState message={error} onRetry={() => void loadTechniques()} /> : null}

      <div className="grid gap-4 xl:grid-cols-[1.1fr_0.9fr]">
        <Panel className="relative overflow-hidden p-5">
          <div className="pointer-events-none absolute -right-16 -top-16 h-48 w-48 rounded-full bg-cyan/10 blur-3xl" />
          <div className="relative">
            <SectionTitle
              eyebrow="Coverage snapshot"
              title="Observed ATT&CK surface"
              action={
                <span className="chip border-cyan/25 text-cyan">
                  <Shield size={11} /> {coverage?.total || 0} techniques
                </span>
              }
            />
            <div className="mt-5 flex flex-col gap-5 sm:flex-row sm:items-center">
              <div
                className="relative flex h-32 w-32 shrink-0 items-center justify-center rounded-full"
                style={{
                  background: `conic-gradient(#00FF88 ${coverage?.percentage || 0}%, #162334 0)`,
                }}
              >
                <div className="flex h-[104px] w-[104px] flex-col items-center justify-center rounded-full bg-panel">
                  <span className="font-mono text-2xl font-semibold text-white">{coverage?.percentage || 0}%</span>
                  <span className="font-mono text-[8px] uppercase tracking-wider text-mist">covered</span>
                </div>
              </div>
              <div className="grid flex-1 grid-cols-2 gap-2">
                <div className="rounded-xl border border-line/70 bg-abyss/40 p-3">
                  <p className="font-mono text-[8px] uppercase tracking-wider text-slate-600">Observed</p>
                  <p className="mt-1 font-mono text-xl text-neon">{coverage?.covered || 0}</p>
                </div>
                <div className="rounded-xl border border-line/70 bg-abyss/40 p-3">
                  <p className="font-mono text-[8px] uppercase tracking-wider text-slate-600">Unmapped</p>
                  <p className="mt-1 font-mono text-xl text-mist">{(coverage?.total || 0) - (coverage?.covered || 0)}</p>
                </div>
                <div className="rounded-xl border border-line/70 bg-abyss/40 p-3">
                  <p className="font-mono text-[8px] uppercase tracking-wider text-slate-600">Tactics</p>
                  <p className="mt-1 font-mono text-xl text-cyan">{tactics.length}</p>
                </div>
                <div className="rounded-xl border border-line/70 bg-abyss/40 p-3">
                  <p className="font-mono text-[8px] uppercase tracking-wider text-slate-600">Source</p>
                  <p className="mt-1 truncate font-mono text-[9px] text-ice">{String(source.source || "MITRE ATT&CK")}</p>
                </div>
              </div>
            </div>
            <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-line/60 pt-3 font-mono text-[8px] uppercase tracking-wider text-slate-600">
              <Layers size={11} /> Enterprise · {String(source.technique_count || 706)} bundled techniques · retrieved{" "}
              {source.retrieved_at ? formatDate(String(source.retrieved_at), false) : "—"}
            </div>
          </div>
        </Panel>

        <Panel className="p-5">
          <SectionTitle eyebrow="Tactic coverage" title="Select a tactic" />
          <div className="mt-4 grid grid-cols-1 gap-1.5 sm:grid-cols-2">
            {tactics.map((tactic) => {
              const tacticCoverage = coverageByShortname.get(tactic.shortname);
              const percentage = tacticCoverage?.percentage ?? 0;
              return (
                <button
                  key={tactic.id}
                  onClick={() => {
                    setActiveTactic(activeTactic === tactic.shortname ? "" : tactic.shortname);
                    setOffset(0);
                  }}
                  className={cn(
                    "rounded-lg border px-2.5 py-2 text-left transition",
                    activeTactic === tactic.shortname
                      ? "border-cyan/40 bg-cyan/[0.07]"
                      : "border-line/60 bg-abyss/30 hover:border-white/15",
                  )}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-[10px] text-ice">{tactic.name}</span>
                    <span className="font-mono text-[8px] text-slate-600">{tacticCoverage ? `${tacticCoverage.covered}/${tacticCoverage.total}` : "—"}</span>
                  </div>
                  <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-line/70">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-neon/60 to-cyan/60"
                      style={{ width: `${Math.min(100, percentage)}%` }}
                    />
                  </div>
                </button>
              );
            })}
          </div>
          {activeTactic ? (
            <button className="mt-3 font-mono text-[9px] uppercase tracking-wider text-cyan hover:text-white" onClick={() => { setActiveTactic(""); setOffset(0); }}>
              Clear tactic filter
            </button>
          ) : null}
        </Panel>
      </div>

      <Panel className="mt-4 p-5">
        <SectionTitle
          eyebrow="Technique explorer"
          title={activeTactic ? `${tactics.find((tactic) => tactic.shortname === activeTactic)?.name || "Tactic"} techniques` : "All techniques"}
          action={<span className="chip">{total} matching</span>}
        />
        <div className="mt-4 flex flex-col gap-3 lg:flex-row lg:items-center">
          <div className="relative flex-1">
            <Search size={15} className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              value={query}
              onChange={(event) => {
                setQuery(event.target.value);
                setOffset(0);
              }}
              placeholder="Search by technique ID, name or description…"
              className="input pl-10"
            />
          </div>
          <Toggle
            checked={includeSubtechniques}
            onChange={(value) => {
              setIncludeSubtechniques(value);
              setOffset(0);
            }}
            label="Include sub-techniques"
          />
        </div>

        <div className="mt-4">
          {listLoading ? (
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {Array.from({ length: 9 }).map((_, index) => (
                <div key={index} className="skeleton h-[86px]" />
              ))}
            </div>
          ) : techniques.length ? (
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {techniques.map((technique) => {
                const covered = observed.has(technique.id);
                return (
                  <button
                    key={technique.id}
                    onClick={() => setSelected(technique)}
                    className={cn(
                      "group relative overflow-hidden rounded-xl border p-3 text-left transition hover:border-cyan/30 hover:bg-cyan/[0.03]",
                      covered ? "border-neon/20 bg-neon/[0.025]" : "border-line/70 bg-abyss/35",
                    )}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <span className={cn("font-mono text-[9px]", covered ? "text-neon" : "text-cyan/80")}>{technique.id}</span>
                      {covered ? (
                        <span className="flex items-center gap-1 font-mono text-[8px] uppercase tracking-wider text-neon">
                          <CheckCircle2 size={10} /> observed
                        </span>
                      ) : null}
                    </div>
                    <p className="mt-1.5 line-clamp-2 text-[11px] font-medium leading-relaxed text-ice">{technique.name}</p>
                    <div className="mt-2 flex flex-wrap items-center gap-1">
                      {(technique.tactics || []).slice(0, 3).map((shortname) => (
                        <span key={shortname} className="rounded border border-line/70 px-1 py-0.5 font-mono text-[7px] uppercase tracking-wider text-slate-600">
                          {tacticByShortname.get(shortname)?.name || shortname}
                        </span>
                      ))}
                      {technique.subtechnique ? <span className="chip border-violet/20 text-[7px] text-violet">sub</span> : null}
                    </div>
                  </button>
                );
              })}
            </div>
          ) : (
            <EmptyState
              icon={Grid3X3}
              title="No techniques match"
              description="Try a broader search term, clear the tactic filter, or include sub-techniques."
            />
          )}
        </div>

        {total > PAGE_SIZE ? (
          <div className="mt-4 flex items-center justify-between border-t border-line/60 pt-3">
            <p className="font-mono text-[10px] text-mist">
              {offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}
            </p>
            <div className="flex items-center gap-2">
              <button className="btn-ghost btn-sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
                <ChevronLeft size={13} />
              </button>
              <span className="font-mono text-[10px] text-mist">
                {Math.floor(offset / PAGE_SIZE) + 1} / {Math.max(1, Math.ceil(total / PAGE_SIZE))}
              </span>
              <button className="btn-ghost btn-sm" disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset(offset + PAGE_SIZE)}>
                <ChevronRight size={13} />
              </button>
            </div>
          </div>
        ) : null}
      </Panel>

      <div className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line/60 bg-abyss/40 px-4 py-3 font-mono text-[8px] uppercase tracking-wider text-slate-600">
        <span className="flex items-center gap-1.5">
          <Info size={11} /> ATT&CK® is a registered trademark of The MITRE Corporation.
        </span>
        <a href="https://attack.mitre.org/" target="_blank" rel="noreferrer" className="flex items-center gap-1 text-cyan/70 transition hover:text-cyan">
          attack.mitre.org <ExternalLink size={10} />
        </a>
      </div>

      <Modal
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        title={selected ? `${selected.id} — ${selected.name}` : "Technique"}
        eyebrow={selected ? selected.tactics.map((shortname) => tacticByShortname.get(shortname)?.name || shortname).join(" · ") : "MITRE ATT&CK"}
        size="lg"
        footer={
          selected ? (
            <>
              <button className="btn-ghost btn-sm" onClick={() => setSelected(null)}>
                Close
              </button>
              <a href={selected.url || `https://attack.mitre.org/techniques/${selected.id}/`} target="_blank" rel="noreferrer" className="btn-primary btn-sm">
                Open in ATT&CK <ExternalLink size={12} />
              </a>
            </>
          ) : null
        }
      >
        {selected ? (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              <span className="chip border-cyan/25 text-cyan">{selected.id}</span>
              {observed.has(selected.id) ? (
                <span className="chip border-neon/25 text-neon">
                  <CheckCircle2 size={10} /> observed in findings
                </span>
              ) : (
                <span className="chip">not observed</span>
              )}
              {selected.subtechnique ? <span className="chip border-violet/20 text-violet">sub-technique</span> : null}
              {selected.parent_id ? <span className="chip">parent {selected.parent_id}</span> : null}
            </div>
            <p className="text-sm leading-relaxed text-mist">{selected.description || "No description available."}</p>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="rounded-lg border border-line/70 bg-abyss/40 p-3">
                <p className="font-mono text-[8px] uppercase tracking-wider text-slate-600">Tactics</p>
                <div className="mt-1.5 flex flex-wrap gap-1">
                  {(selected.tactics || []).map((shortname) => (
                    <span key={shortname} className="chip text-[9px]">
                      {tacticByShortname.get(shortname)?.name || shortname}
                    </span>
                  ))}
                </div>
              </div>
              <div className="rounded-lg border border-line/70 bg-abyss/40 p-3">
                <p className="font-mono text-[8px] uppercase tracking-wider text-slate-600">Platforms</p>
                <div className="mt-1.5 flex flex-wrap gap-1">
                  {(selected.platforms || []).map((platform) => (
                    <span key={platform} className="chip text-[9px]">
                      {platform}
                    </span>
                  ))}
                  {!selected.platforms?.length ? <span className="text-[9px] text-slate-600">Not specified</span> : null}
                </div>
              </div>
            </div>
            <div className="rounded-lg border border-line/70 bg-abyss/40 p-3">
              <p className="font-mono text-[8px] uppercase tracking-wider text-slate-600">Coverage context</p>
              <p className="mt-1.5 text-[10px] leading-relaxed text-mist">
                {observed.has(selected.id)
                  ? "At least one finding references this technique. Confirm that the corresponding detection is implemented, tuned and validated — mapping alone does not equal coverage."
                  : "No finding currently maps to this technique. Consider a tabletop exercise to define the detection requirements and evidence sources."}
              </p>
              <div className="mt-2">
                <ProgressBar
                  value={observed.has(selected.id) ? 100 : 0}
                  color={observed.has(selected.id) ? "#00FF88" : "#64748B"}
                  height={4}
                />
              </div>
            </div>
            <p className="font-mono text-[8px] text-slate-600">
              Coverage reference: {coverage?.covered || 0}/{coverage?.total || 0} ({coverage?.percentage || 0}%)
            </p>
          </div>
        ) : null}
      </Modal>
    </div>
  );
}
