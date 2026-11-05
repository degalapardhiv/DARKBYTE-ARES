import { Fragment, useCallback, useEffect, useState } from "react";
import {
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Copy,
  Fingerprint,
  History,
  Lock,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { PageHeader } from "../components/PageHeader";
import { Panel, SectionTitle, Pagination, ErrorState, PageLoader, EmptyState } from "../components/ui";
import { api } from "../lib/api";
import type { AuditEntry } from "../lib/types";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { cn, formatDate } from "../lib/utils";

const RESOURCE_TYPES = ["", "assessment", "target", "report", "user", "workspace", "notification", "plugin"];
const OUTCOMES = ["", "success", "denied", "error", "failure"];

function OutcomeBadge({ outcome }: { outcome: string }) {
  const success = ["success", "ok", "completed"].includes(outcome);
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wider",
        success ? "border-neon/25 bg-neon/5 text-neon" : "border-crimson/25 bg-crimson/5 text-crimson",
      )}
    >
      <span className={cn("h-1 w-1 rounded-full", success ? "bg-neon" : "bg-crimson")} />
      {outcome}
    </span>
  );
}

export function Audit() {
  const { user } = useAuth();
  const { notify } = useToast();
  const isAdmin = user?.role === "admin";
  const [items, setItems] = useState<AuditEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [limit] = useState(50);
  const [offset, setOffset] = useState(0);
  const [action, setAction] = useState("");
  const [resourceType, setResourceType] = useState("");
  const [outcome, setOutcome] = useState("");
  const [loading, setLoading] = useState(isAdmin);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [verification, setVerification] = useState<{ valid: boolean; checked: number; broken_at: number | null; head: string } | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);

  const load = useCallback(
    async (silent = false) => {
      if (!isAdmin) return;
      if (!silent) setRefreshing(true);
      try {
        const response = await api.platform.audit({
          action: action || undefined,
          resource_type: resourceType || undefined,
          outcome: outcome || undefined,
          limit,
          offset,
        });
        setItems(response.items);
        setTotal(response.total);
        setError(null);
      } catch (reason) {
        setError(reason instanceof Error ? reason.message : "Could not load the audit trail.");
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [action, resourceType, outcome, limit, offset, isAdmin],
  );

  useEffect(() => {
    void load();
  }, [load]);

  const verify = async () => {
    setVerifying(true);
    try {
      const result = await api.platform.auditVerify();
      setVerification(result);
      notify({
        title: result.valid ? "Audit chain verified" : "Audit chain broken",
        message: result.valid ? `${result.checked} entries linked without divergence.` : `Integrity failure at sequence ${result.broken_at}.`,
        tone: result.valid ? "success" : "error",
      });
    } catch (reason) {
      notify({ title: "Verification failed", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" });
    } finally {
      setVerifying(false);
    }
  };

  const copy = async (value: string, key: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(key);
      window.setTimeout(() => setCopied(null), 1600);
    } catch {
      notify({ title: "Clipboard unavailable", tone: "error" });
    }
  };

  if (!isAdmin) {
    return (
      <div>
        <PageHeader eyebrow="Immutable audit" title="Audit trail" description="Only administrators can inspect the hash-chained audit log." />
        <Panel>
          <EmptyState
            icon={Lock}
            title="Administrator access required"
            description="Your role does not include audit visibility. Ask an administrator to review the event or adjust your role."
          />
        </Panel>
      </div>
    );
  }

  if (loading) return <PageLoader label="Loading immutable audit chain" />;

  return (
    <div>
      <PageHeader
        eyebrow="Immutable audit"
        title="Audit trail"
        description="Every security-relevant action is appended to a SHA-256 hash chain. Entries cannot be modified or removed through the application; verification recomputes the chain from genesis."
        actions={
          <>
            <button className="btn-ghost" onClick={() => void load()} disabled={refreshing}>
              <RefreshCw size={14} className={refreshing ? "animate-spin" : ""} /> Refresh
            </button>
            <button className="btn-neon" onClick={() => void verify()} disabled={verifying}>
              <Fingerprint size={15} className={verifying ? "animate-pulse" : ""} /> {verifying ? "Verifying…" : "Verify chain"}
            </button>
          </>
        }
      />

      <div className="mb-4 grid gap-4 xl:grid-cols-3">
        <Panel className={cn("relative overflow-hidden p-5 xl:col-span-2", verification?.valid === false && "border-crimson/40")}>
          <div className="pointer-events-none absolute -right-16 -top-16 h-40 w-40 rounded-full bg-cyan/10 blur-3xl" />
          <div className="relative flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-start gap-3">
              <span
                className={cn(
                  "flex h-12 w-12 shrink-0 items-center justify-center rounded-xl border",
                  verification?.valid === false
                    ? "border-crimson/30 bg-crimson/10 text-crimson"
                    : verification?.valid
                      ? "border-neon/30 bg-neon/10 text-neon"
                      : "border-cyan/25 bg-cyan/10 text-cyan",
                )}
              >
                {verification?.valid === false ? <ShieldAlert size={22} /> : <ShieldCheck size={22} />}
              </span>
              <div>
                <p className="eyebrow">Chain integrity</p>
                <p className="mt-1 text-lg font-semibold text-white">
                  {verification ? (verification.valid ? "Verified" : "Divergence detected") : "Awaiting verification"}
                </p>
                <p className="mt-1 max-w-xl text-[11px] leading-relaxed text-mist">
                  {verification
                    ? verification.valid
                      ? `${verification.checked} entries recomputed successfully. The current chain head is shown below.`
                      : `The hash chain breaks at entry ${verification.broken_at}. Treat this as a security incident and preserve database state.`
                    : "Run a verification pass to recompute every entry hash from the genesis block."}
                </p>
              </div>
            </div>
            <div className="shrink-0">
              <p className="font-mono text-[8px] uppercase tracking-wider text-slate-600">Entries</p>
              <p className="font-mono text-2xl font-semibold text-white">{verification?.checked ?? total}</p>
            </div>
          </div>
          {verification ? (
            <div className="relative mt-4 flex flex-wrap items-center gap-2 rounded-lg border border-line/70 bg-abyss/40 px-3 py-2">
              <span className="font-mono text-[8px] uppercase tracking-wider text-slate-600">Head</span>
              <span className="break-all font-mono text-[9px] text-cyan">{verification.head}</span>
              <button
                className="ml-auto inline-flex items-center gap-1 rounded border border-line px-1.5 py-0.5 font-mono text-[8px] uppercase tracking-wider text-mist transition hover:text-cyan"
                onClick={() => void copy(verification.head, "head")}
              >
                {copied === "head" ? <Check size={9} className="text-neon" /> : <Copy size={9} />} copy
              </button>
            </div>
          ) : null}
        </Panel>

        <Panel className="p-5">
          <SectionTitle eyebrow="Chain design" title="Tamper evidence" />
          <div className="mt-4 space-y-2.5 font-mono text-[9px] leading-relaxed text-mist">
            <p className="flex items-start gap-2">
              <span className="text-cyan">01</span> Canonical UTC timestamp + actor + action + details
            </p>
            <p className="flex items-start gap-2">
              <span className="text-cyan">02</span> Previous entry hash becomes the next entry's link
            </p>
            <p className="flex items-start gap-2">
              <span className="text-cyan">03</span> SHA-256 digest seals each append-only record
            </p>
            <p className="flex items-start gap-2">
              <span className="text-neon">04</span> Verification recomputes genesis → head
            </p>
          </div>
          <div className="mt-4 flex items-center gap-2 rounded-lg border border-line/70 bg-abyss/40 p-2.5 text-[10px] text-mist">
            <History size={13} className="text-cyan" /> {total} entries in the filtered view
          </div>
        </Panel>
      </div>

      <Panel className="mb-4 p-3">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
          <div className="relative flex-1">
            <History size={15} className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              value={action}
              onChange={(event) => {
                setAction(event.target.value);
                setOffset(0);
              }}
              placeholder="Filter by exact action (for example assessment.queued)…"
              className="input pl-10 font-mono text-xs"
            />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={resourceType}
              onChange={(event) => {
                setResourceType(event.target.value);
                setOffset(0);
              }}
              className="input w-auto py-2 pr-8 text-xs"
              aria-label="Filter by resource type"
            >
              {RESOURCE_TYPES.map((option) => (
                <option key={option || "all"} value={option}>
                  {option || "All resources"}
                </option>
              ))}
            </select>
            <select
              value={outcome}
              onChange={(event) => {
                setOutcome(event.target.value);
                setOffset(0);
              }}
              className="input w-auto py-2 pr-8 text-xs"
              aria-label="Filter by outcome"
            >
              {OUTCOMES.map((option) => (
                <option key={option || "all"} value={option}>
                  {option || "All outcomes"}
                </option>
              ))}
            </select>
            <span className="chip ml-auto">{total} audit entries</span>
          </div>
        </div>
      </Panel>

      {error ? (
        <ErrorState message={error} onRetry={() => void load()} />
      ) : !items.length ? (
        <Panel>
          <EmptyState icon={ShieldCheck} title="No audit entries match" description="Adjust the filters or perform an action to populate the ledger." />
        </Panel>
      ) : (
        <div className="table-shell">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[1000px]">
              <thead className="table-head">
                <tr>
                  <th className="w-8 px-3 py-3" />
                  <th className="px-3 py-3 text-left">Time</th>
                  <th className="px-3 py-3 text-left">Actor</th>
                  <th className="px-3 py-3 text-left">Action</th>
                  <th className="px-3 py-3 text-left">Resource</th>
                  <th className="px-3 py-3 text-left">Outcome</th>
                  <th className="px-3 py-3 text-left">Entry hash</th>
                  <th className="px-5 py-3 text-right">Source</th>
                </tr>
              </thead>
              <tbody>
                {items.map((entry) => (
                  <Fragment key={entry.id}>
                    <tr className="table-row cursor-pointer" onClick={() => setExpandedId(expandedId === entry.id ? null : entry.id)}>
                      <td className="px-3 py-3 text-slate-600">
                        {expandedId === entry.id ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                      </td>
                      <td className="whitespace-nowrap px-3 py-3 font-mono text-[9px] text-mist">{formatDate(entry.created_at)}</td>
                      <td className="max-w-[180px] px-3 py-3">
                        <p className="truncate font-mono text-[9px] text-ice">{entry.actor_email || "system"}</p>
                        <p className="font-mono text-[8px] text-slate-600">seq {entry.id}</p>
                      </td>
                      <td className="max-w-[220px] px-3 py-3">
                        <p className="truncate font-mono text-[9px] text-cyan">{entry.action}</p>
                      </td>
                      <td className="max-w-[180px] px-3 py-3">
                        <p className="truncate text-[10px] text-mist">{entry.resource_type}</p>
                        {entry.resource_id ? (
                          <p className="truncate font-mono text-[8px] text-slate-600">{entry.resource_id.slice(0, 16)}…</p>
                        ) : null}
                      </td>
                      <td className="px-3 py-3">
                        <OutcomeBadge outcome={entry.outcome} />
                      </td>
                      <td className="px-3 py-3">
                        <p className="font-mono text-[9px] text-mist">{entry.entry_hash.slice(0, 18)}…</p>
                      </td>
                      <td className="whitespace-nowrap px-5 py-3 text-right font-mono text-[8px] text-slate-600">
                        {entry.ip_address || "—"}
                      </td>
                    </tr>
                    {expandedId === entry.id ? (
                      <tr className="bg-abyss/50">
                        <td colSpan={8} className="px-5 py-4">
                          <div className="grid gap-4 lg:grid-cols-2">
                            <div>
                              <p className="mb-1 font-mono text-[8px] uppercase tracking-[0.18em] text-mist">Event details</p>
                              <pre className="max-h-60 overflow-auto rounded-lg border border-line/70 bg-void/60 p-3 font-mono text-[9px] leading-relaxed text-mist">
                                {JSON.stringify(entry.details, null, 2)}
                              </pre>
                            </div>
                            <div>
                              <p className="mb-1 font-mono text-[8px] uppercase tracking-[0.18em] text-mist">Hash chain</p>
                              <div className="space-y-2 rounded-lg border border-line/70 bg-void/60 p-3">
                                <div>
                                  <p className="font-mono text-[8px] uppercase tracking-wider text-slate-600">Entry hash</p>
                                  <div className="mt-0.5 flex items-start gap-2">
                                    <p className="break-all font-mono text-[9px] text-cyan">{entry.entry_hash}</p>
                                    <button
                                      className="shrink-0 rounded border border-line p-1 text-mist transition hover:text-cyan"
                                      onClick={(event) => {
                                        event.stopPropagation();
                                        void copy(entry.entry_hash, `hash-${entry.id}`);
                                      }}
                                      aria-label="Copy entry hash"
                                    >
                                      {copied === `hash-${entry.id}` ? <Check size={9} className="text-neon" /> : <Copy size={9} />}
                                    </button>
                                  </div>
                                </div>
                                <div>
                                  <p className="font-mono text-[8px] uppercase tracking-wider text-slate-600">Previous hash</p>
                                  <p className="mt-0.5 break-all font-mono text-[9px] text-slate-600">{entry.prev_hash}</p>
                                </div>
                              </div>
                              <div className="mt-2 flex items-center gap-2 font-mono text-[8px] uppercase tracking-wider text-slate-600">
                                {entry.outcome === "success" ? <CheckCircle2 size={10} className="text-neon" /> : <XCircle size={10} className="text-crimson" />}
                                {entry.outcome} · actor {entry.actor_id || "system"}
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination total={total} limit={limit} offset={offset} onChange={setOffset} />
        </div>
      )}
    </div>
  );
}
