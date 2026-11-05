import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  ExternalLink,
  Filter,
  Search,
  ShieldAlert,
  ShieldCheck,
  Eye,
  RefreshCw,
  X,
} from "lucide-react";
import { PageHeader } from "../components/PageHeader";
import { Panel, Pagination, ErrorState, PageLoader, EmptyState, SectionTitle } from "../components/ui";
import { SeverityBadge, StatusBadge, DemoBadge } from "../components/Badges";
import { Modal } from "../components/Modal";
import { api } from "../lib/api";
import type { Finding, Severity } from "../lib/types";
import { MODULE_META, SEVERITY_ORDER } from "../lib/constants";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { cn, formatDate, moduleLabel } from "../lib/utils";

const STATUS_OPTIONS = ["", "open", "accepted", "remediated", "false_positive"];
const FINDING_STATUSES = ["open", "accepted", "remediated", "false_positive"] as const;

export function Findings() {
  const { user } = useAuth();
  const { notify } = useToast();
  const [params, setParams] = useSearchParams();
  const findId = params.get("find");
  const initialAssessment = params.get("assessment") || "";
  const [items, setItems] = useState<Finding[]>([]);
  const [total, setTotal] = useState(0);
  const [limit] = useState(25);
  const [offset, setOffset] = useState(0);
  const [query, setQuery] = useState("");
  const [debounced, setDebounced] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [module, setModule] = useState("");
  const [assessmentId, setAssessmentId] = useState(initialAssessment);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [statusBusy, setStatusBusy] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [severityCounts, setSeverityCounts] = useState<Record<Severity, number> | null>(null);

  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(query), 320);
    return () => window.clearTimeout(timer);
  }, [query]);

  const load = useCallback(async (silent = false) => {
    if (!silent) setRefreshing(true);
    try {
      const response = await api.findings.list({
        q: debounced || undefined,
        severity: severity || undefined,
        status: status || undefined,
        module: module || undefined,
        assessment_id: assessmentId || undefined,
        limit,
        offset,
      });
      setItems(response.items);
      setTotal(response.total);
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not load findings.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [debounced, severity, status, module, assessmentId, limit, offset]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    api.dashboard
      .overview()
      .then((data) => {
        const counts = Object.fromEntries(SEVERITY_ORDER.map((level) => [level, 0])) as Record<Severity, number>;
        data.severity.forEach((entry) => {
          counts[entry.name] = entry.value;
        });
        setSeverityCounts(counts);
      })
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    if (!findId || !items.length) return;
    const match = items.find((item) => item.id === findId);
    if (match) {
      setSelected(match);
      const next = new URLSearchParams(params);
      next.delete("find");
      setParams(next, { replace: true });
    }
  }, [findId, items, params, setParams]);

  const canEdit = user?.role === "admin" || user?.role === "analyst";

  const updateStatus = async (nextStatus: string) => {
    if (!selected) return;
    setStatusBusy(true);
    try {
      const updated = await api.findings.updateStatus(selected.id, nextStatus);
      setSelected(updated);
      setItems((current) => current.map((item) => (item.id === updated.id ? updated : item)));
      notify({ title: "Finding triaged", message: updated.title.slice(0, 70), tone: "success" });
      await load(true);
    } catch (reason) {
      notify({ title: "Could not update finding", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" });
    } finally {
      setStatusBusy(false);
    }
  };

  const clearAssessmentFilter = () => {
    setAssessmentId("");
    setOffset(0);
    const next = new URLSearchParams(params);
    next.delete("assessment");
    setParams(next, { replace: true });
  };

  const summary = useMemo(
    () =>
      SEVERITY_ORDER.map((level) => ({
        level,
        count: severityCounts?.[level] ?? 0,
      })),
    [severityCounts],
  );

  if (loading) return <PageLoader label="Loading findings queue" />;

  return (
    <div>
      <PageHeader
        eyebrow="Triage operations"
        title="Findings"
        description="A single evidence-backed queue across every module. Findings retain their CVSS vector, ATT&CK mapping and remediation guidance; triage changes are audited."
        actions={
          <>
            <button className="btn-ghost" onClick={() => void load()} disabled={refreshing}>
              <RefreshCw size={14} className={refreshing ? "animate-spin" : ""} /> Refresh
            </button>
            <Link to="/assessments" className="btn-primary">
              <ShieldAlert size={15} /> Assessments
            </Link>
          </>
        }
      />

      <div className="mb-4 grid gap-2 sm:grid-cols-3 lg:grid-cols-5">
        {summary.map((item) => (
          <button
            key={item.level}
            onClick={() => {
              setSeverity(severity === item.level ? "" : item.level);
              setOffset(0);
            }}
            className={cn(
              "rounded-xl border p-3 text-left transition",
              severity === item.level ? "border-cyan/40 bg-cyan/[0.06]" : "border-line/70 bg-panel/60 hover:border-white/15",
            )}
          >
            <div className="flex items-center justify-between">
              <SeverityBadge severity={item.level} />
              <span className="font-mono text-lg font-semibold text-white">{item.count}</span>
            </div>
            <p className="mt-1.5 font-mono text-[8px] uppercase tracking-wider text-slate-600">
              {severity === item.level ? "filter active" : "click to filter"}
            </p>
          </button>
        ))}
      </div>

      <Panel className="mb-4 p-3">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
          <div className="relative flex-1">
            <Search size={15} className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              value={query}
              onChange={(event) => {
                setQuery(event.target.value);
                setOffset(0);
              }}
              placeholder="Search title or CVE…"
              className="input pl-10"
            />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Filter size={13} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <select
                value={severity}
                onChange={(event) => {
                  setSeverity(event.target.value);
                  setOffset(0);
                }}
                className="input w-auto py-2 pl-8 pr-8 text-xs"
                aria-label="Filter by severity"
              >
                <option value="">All severities</option>
                {SEVERITY_ORDER.map((level) => (
                  <option key={level} value={level}>
                    {level}
                  </option>
                ))}
              </select>
            </div>
            <select
              value={status}
              onChange={(event) => {
                setStatus(event.target.value);
                setOffset(0);
              }}
              className="input w-auto py-2 pr-8 text-xs"
              aria-label="Filter by triage status"
            >
              {STATUS_OPTIONS.map((option) => (
                <option key={option || "all"} value={option}>
                  {option ? option.replace(/_/g, " ") : "All statuses"}
                </option>
              ))}
            </select>
            <select
              value={module}
              onChange={(event) => {
                setModule(event.target.value);
                setOffset(0);
              }}
              className="input w-auto py-2 pr-8 text-xs"
              aria-label="Filter by module"
            >
              <option value="">All modules</option>
              {Object.values(MODULE_META).map((meta) => (
                <option key={meta.id} value={meta.id}>
                  {meta.name}
                </option>
              ))}
            </select>
            <span className="chip ml-auto">{total} matching</span>
          </div>
        </div>
        {assessmentId ? (
          <div className="mt-3 flex items-center gap-2 border-t border-line/60 pt-3">
            <span className="chip border-cyan/25 text-cyan">Assessment filter active</span>
            <button className="chip transition hover:text-ice" onClick={clearAssessmentFilter}>
              <X size={10} /> Clear
            </button>
          </div>
        ) : null}
      </Panel>

      {error ? (
        <ErrorState message={error} onRetry={() => void load()} />
      ) : !items.length ? (
        <Panel>
          <EmptyState
            icon={ShieldCheck}
            title="No findings match this view"
            description="Either the scope is clean or the filters exclude current records. Adjust filters or run a new assessment."
          />
        </Panel>
      ) : (
        <div className="table-shell">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[880px]">
              <thead className="table-head">
                <tr>
                  <th className="px-4 py-3 text-left">Severity</th>
                  <th className="px-3 py-3 text-left">Finding</th>
                  <th className="px-3 py-3 text-left">Module</th>
                  <th className="px-3 py-3 text-left">CVSS</th>
                  <th className="px-3 py-3 text-left">Status</th>
                  <th className="px-3 py-3 text-left">Created</th>
                  <th className="px-4 py-3 text-right">View</th>
                </tr>
              </thead>
              <tbody>
                {items.map((finding) => (
                  <tr key={finding.id} className="table-row">
                    <td className="px-4 py-3">
                      <SeverityBadge severity={finding.severity} />
                    </td>
                    <td className="max-w-[360px] px-3 py-3">
                      <button className="block w-full text-left" onClick={() => setSelected(finding)}>
                        <span className="line-clamp-2 text-[11.5px] leading-relaxed text-ice transition hover:text-cyan">
                          {finding.title}
                        </span>
                        <span className="mt-1 flex items-center gap-2 font-mono text-[8px] uppercase tracking-wider text-slate-600">
                          {finding.cve_id ? <span className="text-amber/80">{finding.cve_id}</span> : null}
                          {finding.technique_ids.slice(0, 3).map((technique) => (
                            <span key={technique} className="text-cyan/50">
                              {technique}
                            </span>
                          ))}
                          {finding.is_demo ? <DemoBadge compact /> : null}
                        </span>
                      </button>
                    </td>
                    <td className="whitespace-nowrap px-3 py-3 text-[10px] text-mist">{moduleLabel(finding.module)}</td>
                    <td className="px-3 py-3 font-mono text-[10px] text-ice">
                      {finding.cvss_score !== null ? finding.cvss_score.toFixed(1) : "—"}
                    </td>
                    <td className="px-3 py-3">
                      <StatusBadge status={finding.status} />
                    </td>
                    <td className="whitespace-nowrap px-3 py-3 font-mono text-[9px] text-slate-600">
                      {formatDate(finding.created_at, false)}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        className="rounded-md border border-line p-1.5 text-mist transition hover:border-cyan/40 hover:text-cyan"
                        onClick={() => setSelected(finding)}
                        aria-label="Open finding"
                      >
                        <Eye size={13} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination total={total} limit={limit} offset={offset} onChange={setOffset} />
        </div>
      )}

      <Modal
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        title={selected?.title || "Finding"}
        eyebrow={selected ? `${selected.cve_id || "No CVE"} · ${moduleLabel(selected.module)}` : "Finding detail"}
        size="xl"
        footer={
          selected ? (
            <>
              <Link
                to={`/assessments/${selected.assessment_id}`}
                className="btn-ghost btn-sm"
                onClick={() => setSelected(null)}
              >
                Open assessment
              </Link>
              {canEdit ? (
                <>
                  <span className="font-mono text-[9px] uppercase tracking-wider text-mist">Triage</span>
                  <select
                    value={selected.status}
                    onChange={(event) => void updateStatus(event.target.value)}
                    disabled={statusBusy}
                    className="input w-auto py-2 text-xs"
                  >
                    {FINDING_STATUSES.map((option) => (
                      <option key={option} value={option}>
                        {option.replace(/_/g, " ")}
                      </option>
                    ))}
                  </select>
                </>
              ) : null}
            </>
          ) : null
        }
      >
        {selected ? (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={selected.severity} />
              <StatusBadge status={selected.status} />
              {selected.cvss_score !== null ? (
                <span className="chip border-amber/25 text-amber">CVSS {selected.cvss_score.toFixed(1)}</span>
              ) : null}
              {selected.is_demo ? <DemoBadge /> : null}
              <span className="ml-auto font-mono text-[9px] text-slate-600">{formatDate(selected.created_at)}</span>
            </div>

            <p className="text-sm leading-relaxed text-mist">{selected.description}</p>

            <div className="rounded-xl border border-neon/20 bg-neon/[0.035] p-4">
              <SectionTitle eyebrow="Remediation guidance" title="Recommended action" />
              <p className="mt-2 text-xs leading-relaxed text-ice">{selected.remediation || "No remediation guidance recorded."}</p>
            </div>

            {selected.cvss_vector ? (
              <div className="rounded-lg border border-line/70 bg-abyss/50 px-3 py-2">
                <p className="font-mono text-[8px] uppercase tracking-[0.18em] text-slate-600">CVSS vector</p>
                <p className="mt-1 break-all font-mono text-[10px] text-ice">{selected.cvss_vector}</p>
              </div>
            ) : null}

            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <p className="mb-1.5 font-mono text-[8px] uppercase tracking-[0.18em] text-mist">Evidence</p>
                <pre className="max-h-64 overflow-auto rounded-lg border border-line/70 bg-void/60 p-3 font-mono text-[9px] leading-relaxed text-mist">
                  {JSON.stringify(selected.evidence, null, 2)}
                </pre>
              </div>
              <div>
                <p className="mb-1.5 font-mono text-[8px] uppercase tracking-[0.18em] text-mist">ATT&CK mapping</p>
                <div className="flex flex-wrap gap-1.5">
                  {selected.technique_ids.length ? (
                    selected.technique_ids.map((technique) => (
                      <a
                        key={technique}
                        href={`https://attack.mitre.org/techniques/${technique.replace(".", "/")}/`}
                        target="_blank"
                        rel="noreferrer"
                        className="chip border-cyan/20 text-cyan transition hover:bg-cyan/10"
                      >
                        {technique} <ExternalLink size={9} />
                      </a>
                    ))
                  ) : (
                    <span className="text-[10px] text-slate-600">No technique mapped.</span>
                  )}
                </div>
                <p className="mb-1.5 mt-4 font-mono text-[8px] uppercase tracking-[0.18em] text-mist">References</p>
                <div className="space-y-1">
                  {selected.references.length ? (
                    selected.references.map((reference) => (
                      <a
                        key={reference}
                        href={reference}
                        target="_blank"
                        rel="noreferrer"
                        className="flex items-center gap-1 break-all font-mono text-[9px] text-cyan/80 hover:text-cyan"
                      >
                        <ExternalLink size={9} className="shrink-0" /> {reference}
                      </a>
                    ))
                  ) : (
                    <span className="text-[10px] text-slate-600">No external references.</span>
                  )}
                </div>
                {selected.cve_id ? (
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${selected.cve_id}`}
                    target="_blank"
                    rel="noreferrer"
                    className="btn-ghost btn-sm mt-4 w-full"
                  >
                    NVD record <ExternalLink size={11} />
                  </a>
                ) : null}
              </div>
            </div>
            <p className="font-mono text-[8px] uppercase tracking-wider text-slate-600">
              Finding ID · <span className="break-all text-mist">{selected.id}</span>
            </p>
          </div>
        ) : null}
      </Modal>
    </div>
  );
}
