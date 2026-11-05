import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Ban,
  Check,
  CheckCircle2,
  ChevronRight,
  Crosshair,
  Eye,
  FileCheck2,
  Filter,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  Trash2,
  X,
} from "lucide-react";
import { PageHeader } from "../components/PageHeader";
import { Panel, Pagination, ErrorState, PageLoader, EmptyState, SectionTitle, StatCard } from "../components/ui";
import { DemoBadge, StatusBadge } from "../components/Badges";
import { ConfirmDialog, Modal } from "../components/Modal";
import { api } from "../lib/api";
import type { Target } from "../lib/types";
import { ENVIRONMENTS, TARGET_ACTIONS, TARGET_TYPES } from "../lib/constants";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { cn, formatDate, timeAgo } from "../lib/utils";

const TYPE_LABELS: Record<string, string> = {
  domain: "Domain",
  ip: "IP address",
  cidr: "CIDR range",
  url: "Web URL",
  api: "API origin",
  cloud_account: "Cloud account",
  ad_config: "AD snapshot",
  password_policy: "Password policy",
  local: "Local workspace",
};

const TYPE_ACTIONS: Record<string, string[]> = {
  domain: ["recon", "web_scan", "vulnerability_lookup", "osint", "simulation"],
  ip: ["network_scan", "simulation"],
  cidr: ["network_scan", "simulation"],
  url: ["web_scan", "vulnerability_lookup", "api_scan", "simulation"],
  api: ["api_scan", "vulnerability_lookup", "simulation"],
  cloud_account: ["cloud_audit", "simulation"],
  ad_config: ["config_audit", "simulation"],
  password_policy: ["password_audit", "simulation"],
  local: ["password_audit", "config_audit", "cloud_audit", "simulation"],
};

function toLocalInput(value: string | null | undefined): string {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const offset = date.getTimezoneOffset();
  return new Date(date.getTime() - offset * 60000).toISOString().slice(0, 16);
}

function defaultExpiry(days = 90): string {
  return toLocalInput(new Date(Date.now() + days * 86400000).toISOString());
}

export function Targets() {
  const { user } = useAuth();
  const { notify } = useToast();
  const [items, setItems] = useState<Target[]>([]);
  const [total, setTotal] = useState(0);
  const [limit] = useState(25);
  const [offset, setOffset] = useState(0);
  const [query, setQuery] = useState("");
  const [debounced, setDebounced] = useState("");
  const [status, setStatus] = useState("");
  const [targetType, setTargetType] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [selected, setSelected] = useState<Target | null>(null);
  const [verifyTarget, setVerifyTarget] = useState<Target | null>(null);
  const [rejectTarget, setRejectTarget] = useState<Target | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Target | null>(null);
  const [busy, setBusy] = useState(false);
  const [counts, setCounts] = useState({ verified: 0, pending: 0, rejected: 0, expired: 0 });
  const [form, setForm] = useState({
    name: "",
    target_type: "domain",
    value: "",
    environment: "lab",
    authorization_ref: "",
    authorized_by: "",
    authorization_expires: defaultExpiry(),
    notes: "",
    allowed_actions: TYPE_ACTIONS.domain,
  });
  const [verifyForm, setVerifyForm] = useState({ allowed_actions: [] as string[], authorization_expires: "", note: "" });
  const [rejectReason, setRejectReason] = useState("");

  const canCreate = user?.role === "admin" || user?.role === "analyst";
  const isAdmin = user?.role === "admin";

  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(query), 320);
    return () => window.clearTimeout(timer);
  }, [query]);

  const load = useCallback(async (silent = false) => {
    if (!silent) setRefreshing(true);
    try {
      const response = await api.targets.list({
        q: debounced || undefined,
        status: status || undefined,
        target_type: targetType || undefined,
        limit,
        offset,
      });
      setItems(response.items);
      setTotal(response.total);
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not load targets.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [debounced, status, targetType, limit, offset]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    api.dashboard
      .overview()
      .then((data) => {
        setCounts((current) => ({
          ...current,
          verified: data.stats.verified_targets,
          pending: data.stats.pending_targets,
        }));
      })
      .catch(() => undefined);
    Promise.all([
      api.targets.list({ status: "rejected", limit: 1 }),
      api.targets.list({ status: "expired", limit: 1 }),
    ])
      .then(([rejected, expired]) => {
        setCounts((current) => ({ ...current, rejected: rejected.total, expired: expired.total }));
      })
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    if (!selected) return;
    const refreshed = items.find((item) => item.id === selected.id);
    if (refreshed) setSelected(refreshed);
  }, [items, selected]);

  const closeCreate = () => {
    setCreateOpen(false);
    setForm({
      name: "",
      target_type: "domain",
      value: "",
      environment: "lab",
      authorization_ref: "",
      authorized_by: "",
      authorization_expires: defaultExpiry(),
      notes: "",
      allowed_actions: TYPE_ACTIONS.domain,
    });
  };

  const submitCreate = async () => {
    setBusy(true);
    try {
      await api.targets.create({
        name: form.name.trim(),
        target_type: form.target_type,
        value: form.value.trim(),
        environment: form.environment,
        authorization_ref: form.authorization_ref.trim(),
        authorized_by: form.authorized_by.trim(),
        authorization_expires: form.authorization_expires ? new Date(form.authorization_expires).toISOString() : null,
        allowed_actions: form.allowed_actions,
        notes: form.notes,
      });
      notify({
        title: "Authorization record created",
        message: "The target is pending administrator verification and cannot be assessed yet.",
        tone: "success",
      });
      closeCreate();
      await load(true);
    } catch (reason) {
      notify({ title: "Could not create target", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" });
    } finally {
      setBusy(false);
    }
  };

  const openVerify = (target: Target) => {
    setVerifyTarget(target);
    setVerifyForm({
      allowed_actions: target.allowed_actions.length ? target.allowed_actions : TYPE_ACTIONS[target.target_type] || [],
      authorization_expires: toLocalInput(target.authorization_expires) || defaultExpiry(),
      note: "",
    });
  };

  const submitVerify = async () => {
    if (!verifyTarget) return;
    if (!verifyForm.allowed_actions.length) {
      notify({ title: "Select at least one action", tone: "warning" });
      return;
    }
    setBusy(true);
    try {
      await api.targets.verify(verifyTarget.id, {
        allowed_actions: verifyForm.allowed_actions,
        authorization_expires: verifyForm.authorization_expires
          ? new Date(verifyForm.authorization_expires).toISOString()
          : null,
        note: verifyForm.note.trim(),
      });
      notify({ title: "Scope verified", message: `${verifyTarget.name} is now eligible for allowlisted actions.`, tone: "success" });
      setVerifyTarget(null);
      await load(true);
    } catch (reason) {
      notify({ title: "Verification failed", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" });
    } finally {
      setBusy(false);
    }
  };

  const submitReject = async () => {
    if (!rejectTarget) return;
    if (rejectReason.trim().length < 3) {
      notify({ title: "Provide a rejection reason", tone: "warning" });
      return;
    }
    setBusy(true);
    try {
      await api.targets.reject(rejectTarget.id, rejectReason.trim());
      notify({ title: "Scope rejected", message: rejectTarget.name, tone: "info" });
      setRejectTarget(null);
      setRejectReason("");
      await load(true);
    } catch (reason) {
      notify({ title: "Could not reject target", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" });
    } finally {
      setBusy(false);
    }
  };

  const submitDelete = async () => {
    if (!deleteTarget) return;
    setBusy(true);
    try {
      await api.targets.remove(deleteTarget.id);
      notify({ title: "Target deleted", message: deleteTarget.name, tone: "success" });
      setDeleteTarget(null);
      if (selected?.id === deleteTarget.id) setSelected(null);
      await load(true);
    } catch (reason) {
      notify({ title: "Could not delete target", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" });
    } finally {
      setBusy(false);
    }
  };

  if (loading) return <PageLoader label="Loading authorization register" />;

  return (
    <div>
      <PageHeader
        eyebrow="Authorization register"
        title="Targets & scope"
        description="No assessment can run without a verified target record. Each record binds the scope to a written authorization reference, an expiry and an explicit action allowlist."
        actions={
          <>
            <button className="btn-ghost" onClick={() => void load()} disabled={refreshing}>
              <RefreshCw size={14} className={refreshing ? "animate-spin" : ""} /> Refresh
            </button>
            {canCreate ? (
              <button className="btn-primary" onClick={() => setCreateOpen(true)}>
                <Plus size={15} /> Register target
              </button>
            ) : null}
          </>
        }
      />

      <div className="mb-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Total in view" value={total} hint="Matching current filters" icon={Crosshair} accent="#00E5FF" />
        <StatCard label="Verified scope" value={counts.verified} hint="Eligible for allowlisted actions" icon={ShieldCheck} accent="#00FF88" />
        <StatCard label="Pending review" value={counts.pending} hint="Administrator approval required" icon={FileCheck2} accent="#FFB020" />
        <StatCard label="Rejected / expired" value={counts.rejected + counts.expired} hint="Denied or out of policy" icon={Ban} accent="#FF3B5C" />
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
              placeholder="Search name, value or authorization reference…"
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
                <option value="">All statuses</option>
                {["pending", "verified", "rejected", "expired"].map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
            </div>
            <select
              value={targetType}
              onChange={(event) => {
                setTargetType(event.target.value);
                setOffset(0);
              }}
              className="input w-auto py-2 pr-8 text-xs"
              aria-label="Filter by target type"
            >
              <option value="">All types</option>
              {TARGET_TYPES.map((type) => (
                <option key={type} value={type}>
                  {TYPE_LABELS[type] || type}
                </option>
              ))}
            </select>
            <span className="chip ml-auto">{total} targets</span>
          </div>
        </div>
      </Panel>

      {error ? (
        <ErrorState message={error} onRetry={() => void load()} />
      ) : !items.length ? (
        <Panel>
          <EmptyState
            icon={Crosshair}
            title="No authorization records"
            description="Register a target with a written authorization reference, then have an administrator verify the exact actions allowed."
            action={
              canCreate ? (
                <button className="btn-primary btn-sm" onClick={() => setCreateOpen(true)}>
                  <Plus size={14} /> Register target
                </button>
              ) : undefined
            }
          />
        </Panel>
      ) : (
        <div className="grid gap-3 lg:grid-cols-2">
          {items.map((target) => {
            const expired = target.authorization_expires ? new Date(target.authorization_expires).getTime() < Date.now() : false;
            return (
              <Panel key={target.id} hover className="p-4">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <StatusBadge status={expired && target.status === "verified" ? "expired" : target.status} />
                      <span className="chip">{TYPE_LABELS[target.target_type] || target.target_type}</span>
                      <span className="chip">{target.environment}</span>
                      {target.is_demo ? <DemoBadge compact /> : null}
                    </div>
                    <button className="mt-2.5 text-left" onClick={() => setSelected(target)}>
                      <p className="truncate text-sm font-medium text-ice transition hover:text-cyan">{target.name}</p>
                    </button>
                    <p className="mt-1 truncate font-mono text-[10px] text-cyan/80">{target.value}</p>
                  </div>
                  <button
                    className="rounded-md border border-line p-1.5 text-mist transition hover:border-cyan/40 hover:text-cyan"
                    onClick={() => setSelected(target)}
                    aria-label="Target details"
                  >
                    <Eye size={13} />
                  </button>
                </div>

                <div className="mt-3 grid grid-cols-2 gap-2 text-[10px]">
                  <div className="rounded-lg border border-line/60 bg-abyss/40 p-2">
                    <p className="font-mono text-[8px] uppercase tracking-wider text-slate-600">Authorization</p>
                    <p className="mt-1 truncate font-mono text-[9px] text-ice">{target.authorization_ref}</p>
                  </div>
                  <div className="rounded-lg border border-line/60 bg-abyss/40 p-2">
                    <p className="font-mono text-[8px] uppercase tracking-wider text-slate-600">Expires</p>
                    <p className={cn("mt-1 font-mono text-[9px]", expired ? "text-crimson" : "text-ice")}>
                      {target.authorization_expires ? formatDate(target.authorization_expires, false) : "No expiry"}
                    </p>
                  </div>
                </div>

                <div className="mt-3">
                  <p className="mb-1.5 font-mono text-[8px] uppercase tracking-[0.18em] text-slate-600">Allowlisted actions</p>
                  <div className="flex flex-wrap gap-1">
                    {target.allowed_actions.length ? (
                      target.allowed_actions.map((action) => (
                        <span key={action} className="chip border-cyan/15 text-[9px] text-ice">
                          {action.replace(/_/g, " ")}
                        </span>
                      ))
                    ) : (
                      <span className="text-[9px] text-slate-600">No actions allowlisted.</span>
                    )}
                  </div>
                </div>

                <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-line/60 pt-3">
                  <span className="font-mono text-[8px] uppercase tracking-wider text-slate-600">
                    {target.verified_at ? `Verified ${timeAgo(target.verified_at)}` : `Created ${timeAgo(target.created_at)}`}
                  </span>
                  <div className="flex items-center gap-1.5">
                    {isAdmin && target.status === "pending" ? (
                      <>
                        <button className="btn-neon btn-sm" onClick={() => openVerify(target)}>
                          <Check size={12} /> Verify
                        </button>
                        <button className="btn-ghost btn-sm" onClick={() => { setRejectTarget(target); setRejectReason(""); }}>
                          <X size={12} /> Reject
                        </button>
                      </>
                    ) : null}
                    {isAdmin ? (
                      <button
                        className="rounded-md border border-line p-1.5 text-mist transition hover:border-crimson/40 hover:text-crimson"
                        onClick={() => setDeleteTarget(target)}
                        aria-label="Delete target"
                      >
                        <Trash2 size={12} />
                      </button>
                    ) : null}
                    <button className="rounded-md border border-line p-1.5 text-mist transition hover:border-cyan/40 hover:text-cyan" onClick={() => setSelected(target)} aria-label="Open target">
                      <ChevronRight size={12} />
                    </button>
                  </div>
                </div>
              </Panel>
            );
          })}
        </div>
      )}

      <div className="mt-4">
        <Panel className="overflow-hidden">
          <Pagination total={total} limit={limit} offset={offset} onChange={setOffset} />
        </Panel>
      </div>

      <div className="mt-4 flex items-start gap-2 rounded-xl border border-amber/20 bg-amber/[0.04] px-4 py-3 text-[10px] leading-relaxed text-mist">
        <ShieldCheck size={14} className="mt-0.5 shrink-0 text-amber" />
        Scope verification is an administrative control, not a formality. Verify that the authorization reference,
        action allowlist and expiry match the written approval before granting access. Every action is audited.
      </div>

      <Modal
        open={createOpen}
        onClose={closeCreate}
        title="Register authorized target"
        eyebrow="Scope intake"
        description="The target starts in pending state and cannot be assessed until an administrator verifies it."
        size="lg"
        footer={
          <>
            <button className="btn-ghost btn-sm" onClick={closeCreate} disabled={busy}>
              Cancel
            </button>
            <button className="btn-primary btn-sm" onClick={() => void submitCreate()} disabled={busy || !form.allowed_actions.length}>
              {busy ? "Creating…" : "Create authorization record"}
            </button>
          </>
        }
      >
        <div className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label className="label" htmlFor="target-name">
                Display name
              </label>
              <input
                id="target-name"
                className="input"
                value={form.name}
                onChange={(event) => setForm({ ...form, name: event.target.value })}
                placeholder="Production web application"
              />
            </div>
            <div>
              <label className="label" htmlFor="target-type">
                Target type
              </label>
              <select
                id="target-type"
                className="input"
                value={form.target_type}
                onChange={(event) => {
                  const nextType = event.target.value;
                  setForm({ ...form, target_type: nextType, allowed_actions: TYPE_ACTIONS[nextType] || [] });
                }}
              >
                {TARGET_TYPES.map((type) => (
                  <option key={type} value={type}>
                    {TYPE_LABELS[type] || type}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div className="grid gap-4 sm:grid-cols-[1fr_160px]">
            <div>
              <label className="label" htmlFor="target-value">
                Scope value
              </label>
              <input
                id="target-value"
                className="input-mono"
                value={form.value}
                onChange={(event) => setForm({ ...form, value: event.target.value })}
                placeholder={
                  form.target_type === "domain"
                    ? "app.example.com"
                    : form.target_type === "cidr"
                      ? "192.0.2.0/28"
                      : form.target_type === "api"
                        ? "https://api.example.com"
                        : form.target_type === "local"
                          ? "local-audit"
                          : "10.0.0.5"
                }
              />
              <p className="mt-1.5 text-[9px] text-slate-600">
                Private, loopback and reserved ranges require lab configuration. Credentials are never accepted in a scope value.
              </p>
            </div>
            <div>
              <label className="label" htmlFor="target-environment">
                Environment
              </label>
              <select
                id="target-environment"
                className="input"
                value={form.environment}
                onChange={(event) => setForm({ ...form, environment: event.target.value })}
              >
                {ENVIRONMENTS.map((environment) => (
                  <option key={environment} value={environment}>
                    {environment}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label className="label" htmlFor="authorization-ref">
                Written authorization reference
              </label>
              <input
                id="authorization-ref"
                className="input-mono"
                value={form.authorization_ref}
                onChange={(event) => setForm({ ...form, authorization_ref: event.target.value })}
                placeholder="ENG-2026-042 / SOW §4.2"
              />
            </div>
            <div>
              <label className="label" htmlFor="authorized-by">
                Authorized by
              </label>
              <input
                id="authorized-by"
                className="input"
                value={form.authorized_by}
                onChange={(event) => setForm({ ...form, authorized_by: event.target.value })}
                placeholder="Name and role of approving authority"
              />
            </div>
          </div>
          <div>
            <label className="label" htmlFor="authorization-expires">
              Authorization expiry
            </label>
            <input
              id="authorization-expires"
              type="datetime-local"
              className="input"
              value={form.authorization_expires}
              onChange={(event) => setForm({ ...form, authorization_expires: event.target.value })}
            />
          </div>
          <div>
            <p className="label">Allowed actions</p>
            <div className="grid gap-1.5 rounded-xl border border-line/70 bg-abyss/40 p-3 sm:grid-cols-2">
              {TARGET_ACTIONS.map((action) => (
                <label key={action} className="flex cursor-pointer items-center gap-2 rounded-lg px-1.5 py-1 text-[11px] text-mist transition hover:bg-white/[0.03]">
                  <input
                    type="checkbox"
                    checked={form.allowed_actions.includes(action)}
                    onChange={(event) =>
                      setForm({
                        ...form,
                        allowed_actions: event.target.checked
                          ? [...form.allowed_actions, action]
                          : form.allowed_actions.filter((item) => item !== action),
                      })
                    }
                    className="h-3.5 w-3.5 rounded border-line bg-abyss text-cyan focus:ring-cyan/40"
                  />
                  {action.replace(/_/g, " ")}
                </label>
              ))}
            </div>
          </div>
          <div>
            <label className="label" htmlFor="target-notes">
              Operator notes
            </label>
            <textarea
              id="target-notes"
              className="input min-h-20"
              value={form.notes}
              onChange={(event) => setForm({ ...form, notes: event.target.value })}
              placeholder="Scope boundaries, exclusions, emergency contact, change window…"
            />
          </div>
          <p className="flex items-start gap-2 rounded-lg border border-amber/20 bg-amber/[0.04] p-3 text-[10px] leading-relaxed text-mist">
            <ShieldCheck size={13} className="mt-0.5 shrink-0 text-amber" />
            Only register targets you are explicitly authorized to assess. Verification does not make an
            unauthorized scope legal.
          </p>
        </div>
      </Modal>

      <Modal
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        title={selected?.name || "Target detail"}
        eyebrow={selected ? `${TYPE_LABELS[selected.target_type] || selected.target_type} · ${selected.environment}` : "Authorization detail"}
        size="lg"
        footer={
          selected ? (
            <>
              {isAdmin && selected.status === "pending" ? (
                <button
                  className="btn-neon btn-sm"
                  onClick={() => {
                    setSelected(null);
                    openVerify(selected);
                  }}
                >
                  <Check size={13} /> Verify scope
                </button>
              ) : null}
              {isAdmin ? (
                <button className="btn-danger btn-sm" onClick={() => { setSelected(null); setDeleteTarget(selected); }}>
                  <Trash2 size={13} /> Delete
                </button>
              ) : null}
              <button className="btn-ghost btn-sm" onClick={() => setSelected(null)}>
                Close
              </button>
            </>
          ) : null
        }
      >
        {selected ? (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              <StatusBadge status={selected.status} />
              <span className="chip">{TYPE_LABELS[selected.target_type] || selected.target_type}</span>
              <span className="chip">{selected.environment}</span>
              {selected.is_demo ? <DemoBadge /> : null}
              <span className="ml-auto font-mono text-[9px] text-slate-600">{formatDate(selected.created_at)}</span>
            </div>
            <div className="rounded-xl border border-line/70 bg-abyss/50 p-3">
              <p className="font-mono text-[8px] uppercase tracking-wider text-slate-600">Scope value</p>
              <p className="mt-1 break-all font-mono text-sm text-cyan">{selected.value}</p>
            </div>
            <div className="grid gap-2 sm:grid-cols-2">
              {[
                { label: "Authorization reference", value: selected.authorization_ref },
                { label: "Authorized by", value: selected.authorized_by },
                { label: "Expires", value: selected.authorization_expires ? formatDate(selected.authorization_expires) : "No expiry" },
                { label: "Verified by", value: selected.verified_by || "Pending verification" },
                { label: "Verified at", value: selected.verified_at ? formatDate(selected.verified_at) : "—" },
                { label: "Created by", value: selected.created_by },
              ].map((row) => (
                <div key={row.label} className="rounded-lg border border-line/60 bg-abyss/40 p-3">
                  <p className="font-mono text-[8px] uppercase tracking-wider text-slate-600">{row.label}</p>
                  <p className="mt-1 break-all font-mono text-[10px] text-ice">{row.value}</p>
                </div>
              ))}
            </div>
            <div>
              <SectionTitle eyebrow="Permission boundary" title="Allowlisted actions" />
              <div className="mt-2 flex flex-wrap gap-1.5">
                {selected.allowed_actions.map((action) => (
                  <span key={action} className="chip border-cyan/20 text-cyan">
                    {action.replace(/_/g, " ")}
                  </span>
                ))}
                {!selected.allowed_actions.length ? <span className="text-[10px] text-slate-600">No actions allowlisted.</span> : null}
              </div>
            </div>
            <div>
              <p className="mb-1 font-mono text-[8px] uppercase tracking-[0.18em] text-mist">Operator notes</p>
              <p className="rounded-lg border border-line/70 bg-abyss/40 p-3 text-[11px] leading-relaxed text-mist">
                {selected.notes || "No notes recorded."}
              </p>
            </div>
            <Link to={`/assessments`} className="btn-ghost btn-sm w-full" onClick={() => setSelected(null)}>
              Open assessments
            </Link>
          </div>
        ) : null}
      </Modal>

      <Modal
        open={Boolean(verifyTarget)}
        onClose={() => setVerifyTarget(null)}
        title="Verify target scope"
        eyebrow="Administrator control"
        description={`Confirm that ${verifyTarget?.authorization_ref || "the authorization record"} is valid for the actions below.`}
        footer={
          <>
            <button className="btn-ghost btn-sm" onClick={() => setVerifyTarget(null)} disabled={busy}>
              Cancel
            </button>
            <button className="btn-neon btn-sm" onClick={() => void submitVerify()} disabled={busy}>
              <CheckCircle2 size={13} /> {busy ? "Verifying…" : "Verify scope"}
            </button>
          </>
        }
      >
        <div className="space-y-4">
          <div>
            <p className="label">Allowed actions</p>
            <div className="grid gap-1.5 rounded-xl border border-line/70 bg-abyss/40 p-3 sm:grid-cols-2">
              {TARGET_ACTIONS.map((action) => (
                <label key={action} className="flex cursor-pointer items-center gap-2 rounded-lg px-1.5 py-1 text-[11px] text-mist transition hover:bg-white/[0.03]">
                  <input
                    type="checkbox"
                    checked={verifyForm.allowed_actions.includes(action)}
                    onChange={(event) =>
                      setVerifyForm({
                        ...verifyForm,
                        allowed_actions: event.target.checked
                          ? [...verifyForm.allowed_actions, action]
                          : verifyForm.allowed_actions.filter((item) => item !== action),
                      })
                    }
                    className="h-3.5 w-3.5 rounded border-line bg-abyss text-cyan focus:ring-cyan/40"
                  />
                  {action.replace(/_/g, " ")}
                </label>
              ))}
            </div>
          </div>
          <div>
            <label className="label" htmlFor="verify-expiry">
              Authorization expiry
            </label>
            <input
              id="verify-expiry"
              type="datetime-local"
              className="input"
              value={verifyForm.authorization_expires}
              onChange={(event) => setVerifyForm({ ...verifyForm, authorization_expires: event.target.value })}
            />
          </div>
          <div>
            <label className="label" htmlFor="verify-note">
              Verification note
            </label>
            <textarea
              id="verify-note"
              className="input min-h-20"
              value={verifyForm.note}
              onChange={(event) => setVerifyForm({ ...verifyForm, note: event.target.value })}
              placeholder="Ticket checked, scope boundaries confirmed, approvals on file…"
            />
          </div>
        </div>
      </Modal>

      <Modal
        open={Boolean(rejectTarget)}
        onClose={() => setRejectTarget(null)}
        title="Reject target scope"
        eyebrow="Administrator control"
        description="Rejecting this target prevents all assessments until a corrected record is submitted and verified."
        size="sm"
        footer={
          <>
            <button className="btn-ghost btn-sm" onClick={() => setRejectTarget(null)} disabled={busy}>
              Cancel
            </button>
            <button className="btn-danger btn-sm" onClick={() => void submitReject()} disabled={busy}>
              {busy ? "Rejecting…" : "Reject scope"}
            </button>
          </>
        }
      >
        <div>
          <label className="label" htmlFor="reject-reason">
            Reason
          </label>
          <textarea
            id="reject-reason"
            className="input min-h-24"
            value={rejectReason}
            onChange={(event) => setRejectReason(event.target.value)}
            placeholder="Describe the missing authorization, incorrect scope or policy violation."
          />
          <p className="mt-1.5 text-[9px] text-slate-600">Minimum 3 characters. The reason is stored in the audit trail.</p>
        </div>
      </Modal>

      <ConfirmDialog
        open={Boolean(deleteTarget)}
        title="Delete target record?"
        description={`Remove "${deleteTarget?.name}" from the authorization register? Existing assessments retain their historical evidence, but no new runs can use this target.`}
        confirmLabel="Delete target"
        danger
        busy={busy}
        onConfirm={() => void submitDelete()}
        onClose={() => setDeleteTarget(null)}
      />
    </div>
  );
}
