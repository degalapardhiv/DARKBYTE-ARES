import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Ban,
  ChevronRight,
  CirclePlay,
  Filter,
  Plus,
  Radar,
  RefreshCw,
  Search,
  Trash2,
} from "lucide-react";
import { PageHeader } from "../components/PageHeader";
import { Panel, EmptyState, ErrorState, Pagination, ProgressBar, SkeletonRows } from "../components/ui";
import { StatusBadge, RiskPill, DemoBadge } from "../components/Badges";
import { ModuleLauncher } from "../components/ModuleLauncher";
import { ConfirmDialog } from "../components/Modal";
import { api } from "../lib/api";
import type { Assessment } from "../lib/types";
import { MODULE_META } from "../lib/constants";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { cn, moduleLabel, timeAgo } from "../lib/utils";

const STATUS_OPTIONS = ["", "draft", "queued", "running", "completed", "failed", "cancelled"];

export function Assessments() {
  const { user } = useAuth();
  const { notify } = useToast();
  const [items, setItems] = useState<Assessment[]>([]);
  const [total, setTotal] = useState(0);
  const [limit] = useState(25);
  const [offset, setOffset] = useState(0);
  const [query, setQuery] = useState("");
  const [debounced, setDebounced] = useState("");
  const [status, setStatus] = useState("");
  const [module, setModule] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [launcher, setLauncher] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<Assessment | null>(null);
  const [confirmBusy, setConfirmBusy] = useState(false);

  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(query), 320);
    return () => window.clearTimeout(timer);
  }, [query]);

  const load = useCallback(async () => {
    try {
      const response = await api.assessments.list({
        q: debounced || undefined,
        status: status || undefined,
        module: module || undefined,
        limit,
        offset,
      });
      setItems(response.items);
      setTotal(response.total);
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not load assessments.");
    } finally {
      setLoading(false);
    }
  }, [debounced, status, module, limit, offset]);

  useEffect(() => {
    void load();
  }, [load]);

  const run = async (assessment: Assessment) => {
    setBusyId(assessment.id);
    try {
      await api.assessments.run(assessment.id);
      notify({ title: "Assessment queued", message: `${assessment.name} entered the bounded worker queue.`, tone: "success" });
      await load();
    } catch (reason) {
      notify({ title: "Could not queue assessment", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" });
    } finally {
      setBusyId(null);
    }
  };

  const cancel = async (assessment: Assessment) => {
    setBusyId(assessment.id);
    try {
      await api.assessments.cancel(assessment.id);
      notify({ title: "Assessment cancelled", message: assessment.name, tone: "info" });
      await load();
    } catch (reason) {
      notify({ title: "Could not cancel", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" });
    } finally {
      setBusyId(null);
    }
  };

  const remove = async () => {
    if (!pendingDelete) return;
    setConfirmBusy(true);
    try {
      await api.assessments.remove(pendingDelete.id);
      notify({ title: "Assessment deleted", message: pendingDelete.name, tone: "success" });
      setPendingDelete(null);
      await load();
    } catch (reason) {
      notify({ title: "Could not delete", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" });
    } finally {
      setConfirmBusy(false);
    }
  };

  return (
    <div>
      <PageHeader
        eyebrow="Operations ledger"
        title="Assessments"
        description="Every queued operation is bound to a verified target, an allowlisted action and a bounded execution window. Drafts never execute until explicitly launched."
        actions={
          <>
            <button className="btn-ghost" onClick={() => void load()}>
              <RefreshCw size={14} /> Refresh
            </button>
            {user?.role !== "viewer" ? (
              <button className="btn-primary" onClick={() => setLauncher(true)}>
                <Plus size={15} /> New assessment
              </button>
            ) : null}
          </>
        }
      />

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
              placeholder="Search assessment name or module…"
              className="input pl-10"
            />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Filter size={13} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <select
                value={status}
                onChange={(event) => {
                  setStatus(event.target.value);
                  setOffset(0);
                }}
                className="input w-auto py-2 pl-8 pr-8 text-xs"
                aria-label="Filter by status"
              >
                {STATUS_OPTIONS.map((option) => (
                  <option key={option || "all"} value={option}>
                    {option ? option.replace(/_/g, " ") : "All statuses"}
                  </option>
                ))}
              </select>
            </div>
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
            <span className="chip ml-auto">{total} records</span>
          </div>
        </div>
      </Panel>

      {loading ? (
        <Panel className="overflow-hidden">
          <SkeletonRows rows={6} />
        </Panel>
      ) : error ? (
        <ErrorState message={error} onRetry={() => void load()} />
      ) : !items.length ? (
        <Panel>
          <EmptyState
            icon={Radar}
            title="No assessments match this view"
            description="Adjust the filters or launch a module workspace to create a scoped assessment."
            action={
              <button className="btn-primary btn-sm" onClick={() => setLauncher(true)}>
                <Plus size={14} /> Launch module
              </button>
            }
          />
        </Panel>
      ) : (
        <div className="table-shell">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px]">
              <thead className="table-head">
                <tr>
                  <th className="px-5 py-3 text-left">Assessment</th>
                  <th className="px-3 py-3 text-left">Module</th>
                  <th className="px-3 py-3 text-left">Authorization</th>
                  <th className="px-3 py-3 text-left">Execution</th>
                  <th className="px-3 py-3 text-left">Risk</th>
                  <th className="px-3 py-3 text-left">Created</th>
                  <th className="px-5 py-3 text-right">Controls</th>
                </tr>
              </thead>
              <tbody>
                {items.map((assessment) => {
                  const canManage = user?.role === "admin" || assessment.created_by === user?.id;
                  const isBusy = busyId === assessment.id;
                  return (
                    <tr key={assessment.id} className="table-row">
                      <td className="max-w-[300px] px-5 py-3.5">
                        <Link
                          to={`/assessments/${assessment.id}`}
                          className="group flex items-center gap-1.5 text-xs font-medium text-ice hover:text-cyan"
                        >
                          <span className="truncate">{assessment.name}</span>
                          <ChevronRight size={12} className="shrink-0 text-slate-600 transition group-hover:translate-x-0.5 group-hover:text-cyan" />
                        </Link>
                        <div className="mt-1 flex items-center gap-2">
                          <span className="truncate font-mono text-[9px] text-slate-600">
                            {assessment.target_name || assessment.target_value || "Unknown target"}
                          </span>
                          {assessment.is_demo ? <DemoBadge compact /> : null}
                        </div>
                      </td>
                      <td className="whitespace-nowrap px-3 py-3.5">
                        <span className="text-[10px] text-mist">{moduleLabel(assessment.module)}</span>
                      </td>
                      <td className="max-w-[160px] px-3 py-3.5">
                        <p className="truncate font-mono text-[9px] text-ice" title={assessment.target_value || ""}>
                          {assessment.target_value || "—"}
                        </p>
                        <p className="mt-1 font-mono text-[8px] uppercase tracking-wider text-slate-600">
                          {assessment.target_name ? "verified scope" : "—"}
                        </p>
                      </td>
                      <td className="w-[170px] px-3 py-3.5">
                        <StatusBadge status={assessment.status} />
                        <div className="mt-2">
                          <ProgressBar
                            value={assessment.progress}
                            height={3}
                            animated={assessment.status === "running"}
                            color={assessment.status === "failed" ? "#FF3B5C" : assessment.status === "completed" ? "#00FF88" : "#00E5FF"}
                          />
                        </div>
                        <p className="mt-1 font-mono text-[8px] text-slate-600">{assessment.progress}%</p>
                      </td>
                      <td className="px-3 py-3.5">
                        <RiskPill score={assessment.risk_score} />
                      </td>
                      <td className="whitespace-nowrap px-3 py-3.5 font-mono text-[9px] text-slate-600">
                        {timeAgo(assessment.created_at)}
                      </td>
                      <td className="px-5 py-3.5">
                        <div className="flex items-center justify-end gap-1.5">
                          {canManage && user?.role !== "viewer" ? (
                            <>
                              {["draft", "failed", "cancelled", "completed"].includes(assessment.status) ? (
                                <button
                                  className="rounded-md border border-line p-1.5 text-mist transition hover:border-neon/40 hover:text-neon disabled:opacity-40"
                                  title={assessment.status === "completed" ? "Re-run assessment" : "Run assessment"}
                                  onClick={() => void run(assessment)}
                                  disabled={isBusy}
                                >
                                  <CirclePlay size={13} />
                                </button>
                              ) : null}
                              {assessment.status === "queued" ? (
                                <button
                                  className="rounded-md border border-line p-1.5 text-mist transition hover:border-amber/40 hover:text-amber disabled:opacity-40"
                                  title="Cancel queued assessment"
                                  onClick={() => void cancel(assessment)}
                                  disabled={isBusy}
                                >
                                  <Ban size={13} />
                                </button>
                              ) : null}
                            </>
                          ) : null}
                          {user?.role === "admin" ? (
                            <button
                              className="rounded-md border border-line p-1.5 text-mist transition hover:border-crimson/40 hover:text-crimson"
                              title="Delete assessment"
                              onClick={() => setPendingDelete(assessment)}
                              disabled={isBusy}
                            >
                              <Trash2 size={13} />
                            </button>
                          ) : null}
                          <Link
                            to={`/assessments/${assessment.id}`}
                            className={cn("rounded-md border border-line p-1.5 text-mist transition hover:border-cyan/40 hover:text-cyan")}
                            title="Open assessment"
                          >
                            <ChevronRight size={13} />
                          </Link>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <Pagination total={total} limit={limit} offset={offset} onChange={setOffset} />
        </div>
      )}

      <ModuleLauncher open={launcher} onClose={() => setLauncher(false)} />
      <ConfirmDialog
        open={Boolean(pendingDelete)}
        title="Delete assessment?"
        description={`This permanently removes "${pendingDelete?.name}" and its findings, reports and queue jobs. The deletion is written to the immutable audit chain.`}
        confirmLabel="Delete assessment"
        danger
        busy={confirmBusy}
        onConfirm={() => void remove()}
        onClose={() => setPendingDelete(null)}
      />
    </div>
  );
}
