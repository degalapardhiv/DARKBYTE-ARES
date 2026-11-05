import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  ArrowLeft,
  Ban,
  Check,
  ChevronDown,
  ChevronRight,
  CirclePlay,
  Clock,
  Copy,
  Download,
  ExternalLink,
  FileJson,
  FileText,
  Network,
  Play,
  RefreshCw,
  Server,
  ShieldAlert,
  Trash2,
} from "lucide-react";
import { PageHeader } from "../components/PageHeader";
import { Panel, SectionTitle, ProgressBar, ErrorState, PageLoader, EmptyState, InlineSpinner } from "../components/ui";
import { SeverityBadge, StatusBadge, RiskPill, DemoBadge } from "../components/Badges";
import { ConfirmDialog, Modal } from "../components/Modal";
import { NetworkTopology } from "../components/Topology";
import { api, saveBlob } from "../lib/api";
import type { Assessment, Finding, Report } from "../lib/types";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { MODULE_META } from "../lib/constants";
import { cn, formatBytes, formatDate, moduleLabel, riskLabel, timeAgo } from "../lib/utils";

const FINDING_STATUSES = ["open", "accepted", "remediated", "false_positive"] as const;

function CopyValue({ value, label }: { value: string; label?: string }) {
  const { notify } = useToast();
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      title={`Copy ${label || "value"}`}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1600);
        } catch {
          notify({ title: "Clipboard unavailable", tone: "error" });
        }
      }}
      className="inline-flex items-center gap-1 rounded border border-line/70 bg-abyss px-1.5 py-0.5 font-mono text-[9px] text-mist transition hover:border-cyan/30 hover:text-cyan"
    >
      {copied ? <Check size={10} className="text-neon" /> : <Copy size={10} />}
      <span className="max-w-[180px] truncate">{value}</span>
    </button>
  );
}

function MetricTiles({ summary }: { summary: Record<string, any> }) {
  const entries = Object.entries(summary)
    .filter(([, value]) => ["string", "number", "boolean"].includes(typeof value))
    .slice(0, 8);
  if (!entries.length) return null;
  return (
    <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
      {entries.map(([key, value]) => (
        <div key={key} className="rounded-xl border border-line/70 bg-abyss/50 p-3">
          <p className="truncate font-mono text-[8px] uppercase tracking-[0.18em] text-mist">{key.replace(/_/g, " ")}</p>
          <p className="mt-1.5 truncate font-mono text-sm text-ice">
            {typeof value === "boolean" ? (value ? "true" : "false") : String(value)}
          </p>
        </div>
      ))}
    </div>
  );
}

function NetworkHosts({ summary }: { summary: Record<string, any> }) {
  const hosts: any[] = Array.isArray(summary.hosts) ? summary.hosts : [];
  if (!hosts.length) return null;
  return (
    <div className="overflow-x-auto rounded-xl border border-line/70">
      <table className="w-full min-w-[560px]">
        <thead className="table-head">
          <tr>
            <th className="px-3 py-2 text-left">Host</th>
            <th className="px-3 py-2 text-left">Hostnames</th>
            <th className="px-3 py-2 text-left">Open services</th>
            <th className="px-3 py-2 text-right">Ports</th>
          </tr>
        </thead>
        <tbody>
          {hosts.map((host) => (
            <tr key={host.address} className="table-row">
              <td className="whitespace-nowrap px-3 py-2 font-mono text-[10px] text-cyan">{host.address}</td>
              <td className="px-3 py-2 text-[10px] text-mist">{host.hostnames?.join(", ") || "—"}</td>
              <td className="px-3 py-2">
                <div className="flex flex-wrap gap-1">
                  {(host.services || []).map((service: any) => (
                    <span
                      key={`${host.address}-${service.port}`}
                      className="rounded border border-line bg-white/[0.02] px-1.5 py-0.5 font-mono text-[9px] text-ice"
                    >
                      {service.port}/{service.service || service.name || "tcp"}
                    </span>
                  ))}
                </div>
              </td>
              <td className="px-3 py-2 text-right font-mono text-[10px] text-mist">{host.open_port_count ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SubdomainList({ summary }: { summary: Record<string, any> }) {
  const subdomains: any[] = Array.isArray(summary.subdomains) ? summary.subdomains : [];
  if (!subdomains.length) return null;
  return (
    <div className="flex flex-wrap gap-2">
      {subdomains.map((subdomain) => (
        <span key={subdomain.hostname || subdomain.label} className="chip border-cyan/20 text-ice">
          {subdomain.hostname || subdomain.label}
          {Array.isArray(subdomain.addresses) && subdomain.addresses.length ? (
            <span className="text-slate-600">{subdomain.addresses[0]}</span>
          ) : null}
        </span>
      ))}
    </div>
  );
}

function EndpointTable({ summary }: { summary: Record<string, any> }) {
  const endpoints: any[] = Array.isArray(summary.endpoints) ? summary.endpoints : [];
  if (!endpoints.length) return null;
  return (
    <div className="overflow-x-auto rounded-xl border border-line/70">
      <table className="w-full min-w-[520px]">
        <thead className="table-head">
          <tr>
            <th className="px-3 py-2 text-left">Endpoint</th>
            <th className="px-3 py-2 text-left">Status</th>
            <th className="px-3 py-2 text-left">Content type</th>
            <th className="px-3 py-2 text-right">Bytes</th>
          </tr>
        </thead>
        <tbody>
          {endpoints.map((endpoint) => (
            <tr key={endpoint.path} className="table-row">
              <td className="px-3 py-2 font-mono text-[10px] text-cyan">{endpoint.path}</td>
              <td className="px-3 py-2 font-mono text-[10px]">
                <span className={Number(endpoint.status_code) < 400 ? "text-neon" : "text-amber"}>{endpoint.status_code}</span>
              </td>
              <td className="px-3 py-2 font-mono text-[10px] text-mist">{endpoint.content_type || "—"}</td>
              <td className="px-3 py-2 text-right font-mono text-[10px] text-mist">{endpoint.bytes ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function EvidenceList({ summary }: { summary: Record<string, any> }) {
  const evidence: any[] = Array.isArray(summary.evidence) ? summary.evidence : [];
  if (!evidence.length) return null;
  return (
    <div className="space-y-2">
      {evidence.map((item, index) => (
        <div key={`${item.type}-${index}`} className="rounded-xl border border-line/70 bg-abyss/40 p-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="font-mono text-[10px] text-ice">
              {item.type} · {item.source}
            </span>
            {item.sha256 ? <CopyValue value={item.sha256} label="SHA-256 evidence hash" /> : null}
          </div>
          {item.summary ? (
            <p className="mt-1.5 font-mono text-[9px] text-mist">{JSON.stringify(item.summary)}</p>
          ) : null}
        </div>
      ))}
    </div>
  );
}

function SimulationSteps({ summary }: { summary: Record<string, any> }) {
  const steps: any[] = Array.isArray(summary.steps) ? summary.steps : [];
  if (!steps.length) return null;
  return (
    <div className="space-y-2">
      {steps.map((step) => (
        <div key={step.step} className="flex items-center gap-3 rounded-xl border border-line/70 bg-abyss/40 px-3 py-2.5">
          <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-lg border border-crimson/25 bg-crimson/10 font-mono text-[9px] text-crimson">
            {String(step.step).padStart(2, "0")}
          </span>
          <div className="min-w-0 flex-1">
            <p className="truncate text-[11px] text-ice">{step.technique || step.title || "Tabletop step"}</p>
            <p className="font-mono text-[9px] text-slate-600">
              {step.technique_id} · {step.simulation_mode || "tabletop-only"}
            </p>
          </div>
          <a
            href={`https://attack.mitre.org/techniques/${String(step.technique_id || "").replace(".", "/")}/`}
            target="_blank"
            rel="noreferrer"
            className="text-slate-600 transition hover:text-cyan"
            aria-label={`Open ${step.technique_id} in MITRE ATT&CK`}
          >
            <ExternalLink size={13} />
          </a>
        </div>
      ))}
    </div>
  );
}

function FindingCard({
  finding,
  canEdit,
  onStatus,
}: {
  finding: Finding;
  canEdit: boolean;
  onStatus: (finding: Finding, status: string) => Promise<void>;
}) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  return (
    <div className="rounded-xl border border-line/70 bg-abyss/35">
      <button
        className="flex w-full items-start gap-3 px-4 py-3 text-left"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
      >
        <span className="mt-1">
          <SeverityBadge severity={finding.severity} />
        </span>
        <span className="min-w-0 flex-1">
          <span className="block text-[11.5px] font-medium leading-relaxed text-ice">{finding.title}</span>
          <span className="mt-1 flex flex-wrap items-center gap-2 font-mono text-[8px] uppercase tracking-wider text-slate-600">
            {finding.cve_id ? <span className="text-amber/80">{finding.cve_id}</span> : null}
            {finding.cvss_score !== null ? <span>CVSS {finding.cvss_score.toFixed(1)}</span> : null}
            <span>{moduleLabel(finding.module)}</span>
            <span className="text-cyan/50">{finding.technique_ids.join(" · ") || "unmapped"}</span>
          </span>
        </span>
        <span className="flex shrink-0 items-center gap-2">
          <StatusBadge status={finding.status} />
          <ChevronDown size={14} className={cn("text-mist transition", open && "rotate-180")} />
        </span>
      </button>
      {open ? (
        <div className="border-t border-line/60 px-4 py-4">
          <p className="text-xs leading-relaxed text-mist">{finding.description}</p>
          <div className="mt-3 rounded-lg border border-neon/15 bg-neon/[0.03] p-3">
            <p className="font-mono text-[8px] uppercase tracking-[0.18em] text-neon/70">Remediation</p>
            <p className="mt-1.5 text-[11px] leading-relaxed text-ice">{finding.remediation || "No remediation guidance recorded."}</p>
          </div>
          {finding.cvss_vector ? (
            <p className="mt-3 font-mono text-[9px] text-slate-600">Vector: {finding.cvss_vector}</p>
          ) : null}
          <div className="mt-3">
            <p className="mb-1 font-mono text-[8px] uppercase tracking-[0.18em] text-mist">Evidence</p>
            <pre className="max-h-56 overflow-auto rounded-lg border border-line/70 bg-void/60 p-3 font-mono text-[9px] leading-relaxed text-mist">
              {JSON.stringify(finding.evidence, null, 2)}
            </pre>
          </div>
          <div className="mt-3 flex flex-wrap items-center gap-3">
            {canEdit ? (
              <label className="flex items-center gap-2 font-mono text-[9px] uppercase tracking-wider text-mist">
                Triage status
                <select
                  value={finding.status}
                  disabled={busy}
                  onChange={async (event) => {
                    setBusy(true);
                    try {
                      await onStatus(finding, event.target.value);
                    } finally {
                      setBusy(false);
                    }
                  }}
                  className="input w-auto py-1.5 text-[10px] normal-case tracking-normal"
                >
                  {FINDING_STATUSES.map((status) => (
                    <option key={status} value={status}>
                      {status.replace(/_/g, " ")}
                    </option>
                  ))}
                </select>
              </label>
            ) : (
              <StatusBadge status={finding.status} />
            )}
            {finding.references.map((reference) => (
              <a
                key={reference}
                href={reference}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 font-mono text-[9px] text-cyan/80 hover:text-cyan"
              >
                <ExternalLink size={10} /> reference
              </a>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}

export function AssessmentDetail() {
  const { assessmentId } = useParams<{ assessmentId: string }>();
  const { user } = useAuth();
  const { notify } = useToast();
  const navigate = useNavigate();
  const [assessment, setAssessment] = useState<Assessment | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [refreshBusy, setRefreshBusy] = useState(false);
  const [showConfig, setShowConfig] = useState(false);
  const [showSummary, setShowSummary] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [reportOpen, setReportOpen] = useState(false);
  const [reportFormat, setReportFormat] = useState<"pdf" | "html" | "json">("pdf");
  const [reportTitle, setReportTitle] = useState("");
  const [reportBusy, setReportBusy] = useState(false);
  const [pendingReportDelete, setPendingReportDelete] = useState<Report | null>(null);

  const load = useCallback(
    async (silent = false) => {
      if (!assessmentId) return;
      if (!silent) setRefreshBusy(true);
      try {
        const [detail, findingResponse, reportResponse] = await Promise.all([
          api.assessments.get(assessmentId),
          api.assessments.findings(assessmentId, { limit: 500 }),
          api.reports.list({ assessment_id: assessmentId, limit: 100 }),
        ]);
        setAssessment(detail);
        setFindings(findingResponse.items);
        setReports(reportResponse.items);
        setError(null);
      } catch (reason) {
        setError(reason instanceof Error ? reason.message : "Could not load this assessment.");
      } finally {
        setLoading(false);
        setRefreshBusy(false);
      }
    },
    [assessmentId],
  );

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (!assessment || !["queued", "running"].includes(assessment.status)) return;
    const timer = window.setInterval(() => void load(true), 3000);
    return () => window.clearInterval(timer);
  }, [assessment, load]);

  const summary = useMemo<Record<string, any>>(() => assessment?.summary || {}, [assessment]);
  const canManage = Boolean(assessment && user && (user.role === "admin" || assessment.created_by === user.id));
  const canEditFindings = user?.role === "admin" || user?.role === "analyst";
  const isActive = assessment ? ["queued", "running"].includes(assessment.status) : false;

  const updateStatus = async (finding: Finding, status: string) => {
    try {
      const updated = await api.findings.updateStatus(finding.id, status);
      setFindings((current) => current.map((item) => (item.id === updated.id ? updated : item)));
      notify({ title: "Finding updated", message: `${finding.title.slice(0, 60)} → ${status.replace(/_/g, " ")}`, tone: "success" });
    } catch (reason) {
      notify({ title: "Update failed", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" });
    }
  };

  const run = async () => {
    if (!assessment) return;
    setBusy(true);
    try {
      const updated = await api.assessments.run(assessment.id);
      setAssessment(updated);
      notify({ title: "Assessment queued", message: "Bounded workers will process the operation.", tone: "success" });
      await load(true);
    } catch (reason) {
      notify({ title: "Could not queue assessment", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" });
    } finally {
      setBusy(false);
    }
  };

  const cancel = async () => {
    if (!assessment) return;
    setBusy(true);
    try {
      const updated = await api.assessments.cancel(assessment.id);
      setAssessment(updated);
      notify({ title: "Assessment cancelled", tone: "info" });
      await load(true);
    } catch (reason) {
      notify({ title: "Could not cancel", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" });
    } finally {
      setBusy(false);
    }
  };

  const remove = async () => {
    if (!assessment) return;
    setDeleteBusy(true);
    try {
      await api.assessments.remove(assessment.id);
      notify({ title: "Assessment deleted", tone: "success" });
      navigate("/assessments", { replace: true });
    } catch (reason) {
      notify({ title: "Could not delete", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" });
      setDeleteBusy(false);
    }
  };

  const generateReport = async () => {
    if (!assessment) return;
    setReportBusy(true);
    try {
      const report = await api.reports.create({
        assessment_id: assessment.id,
        format: reportFormat,
        title: reportTitle.trim() || undefined,
      });
      notify({ title: "Report generated", message: `${report.format.toUpperCase()} · ${formatBytes(report.size_bytes)}`, tone: "success" });
      setReportOpen(false);
      setReportTitle("");
      await load(true);
    } catch (reason) {
      notify({ title: "Report generation failed", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" });
    } finally {
      setReportBusy(false);
    }
  };

  const download = async (report: Report) => {
    try {
      const { blob, filename } = await api.reports.download(report.id);
      saveBlob(blob, filename);
      notify({ title: "Download started", message: filename, tone: "success" });
    } catch (reason) {
      notify({ title: "Download failed", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" });
    }
  };

  const deleteReport = async () => {
    if (!pendingReportDelete) return;
    try {
      await api.reports.remove(pendingReportDelete.id);
      notify({ title: "Report deleted", tone: "success" });
      setPendingReportDelete(null);
      await load(true);
    } catch (reason) {
      notify({ title: "Could not delete report", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" });
    }
  };

  if (loading) return <PageLoader label="Loading assessment evidence" />;
  if (error || !assessment) {
    return (
      <div>
        <PageHeader eyebrow="Assessment detail" title="Unable to load assessment" description={error || "The record was not found."} />
        <ErrorState message={error || "Assessment not found."} onRetry={() => void load()} />
        <div className="mt-4">
          <Link to="/assessments" className="btn-ghost btn-sm">
            <ArrowLeft size={14} /> Back to assessments
          </Link>
        </div>
      </div>
    );
  }

  const meta = MODULE_META[assessment.module];

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2 font-mono text-[9px] uppercase tracking-wider text-slate-600">
        <Link to="/assessments" className="transition hover:text-cyan">
          Assessments
        </Link>
        <ChevronRight size={11} />
        <span className="text-mist">{assessment.module}</span>
        <span className="ml-auto flex items-center gap-2">
          {assessment.is_demo ? <DemoBadge /> : null}
          <span className="chip">ID {assessment.id.slice(0, 12)}</span>
        </span>
      </div>

      <Panel className="relative overflow-hidden p-5">
        <div
          className="pointer-events-none absolute -right-20 -top-24 h-64 w-64 rounded-full blur-3xl"
          style={{ backgroundColor: `${meta?.accent || "#00E5FF"}18` }}
        />
        <div className="relative flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <StatusBadge status={assessment.status} pulse={assessment.status === "running"} />
              <span className="chip border-cyan/20 text-cyan">{moduleLabel(assessment.module)}</span>
              <RiskPill score={assessment.risk_score} />
              <span className="chip">{riskLabel(assessment.risk_score)}</span>
            </div>
            <h1 className="mt-3 text-balance text-xl font-semibold tracking-tight text-white md:text-2xl">
              {assessment.name}
            </h1>
            <div className="mt-3 grid gap-x-6 gap-y-2 text-[10px] text-mist sm:grid-cols-2 lg:grid-cols-4">
              <p>
                <span className="font-mono text-[8px] uppercase tracking-wider text-slate-600">Target · </span>
                {assessment.target_name || "—"}
              </p>
              <p className="truncate font-mono">
                <span className="text-[8px] uppercase tracking-wider text-slate-600">Scope · </span>
                {assessment.target_value || "—"}
              </p>
              <p>
                <span className="font-mono text-[8px] uppercase tracking-wider text-slate-600">Created · </span>
                {formatDate(assessment.created_at)}
              </p>
              <p>
                <span className="font-mono text-[8px] uppercase tracking-wider text-slate-600">Finished · </span>
                {assessment.finished_at ? formatDate(assessment.finished_at) : "—"}
              </p>
            </div>
            {isActive ? (
              <div className="mt-4 max-w-xl">
                <div className="mb-1.5 flex items-center justify-between font-mono text-[9px] uppercase tracking-wider text-mist">
                  <span className="flex items-center gap-2">
                    <InlineSpinner label={assessment.status === "queued" ? "Awaiting worker" : "Executing"} />
                  </span>
                  <span>{assessment.progress}%</span>
                </div>
                <ProgressBar value={assessment.progress} animated color="#00E5FF" height={5} />
              </div>
            ) : null}
            {assessment.error ? (
              <div className="mt-4 flex items-start gap-2 rounded-lg border border-crimson/30 bg-crimson/10 px-3 py-2 text-[11px] text-crimson">
                <ShieldAlert size={14} className="mt-0.5 shrink-0" /> {assessment.error}
              </div>
            ) : null}
          </div>

          <div className="flex flex-wrap items-center gap-2 lg:max-w-md lg:justify-end">
            <button className="btn-ghost btn-sm" onClick={() => void load()} disabled={refreshBusy}>
              <RefreshCw size={13} className={refreshBusy ? "animate-spin" : ""} /> {refreshBusy ? "Refreshing" : "Refresh"}
            </button>
            {canManage && ["draft", "failed", "cancelled", "completed"].includes(assessment.status) && assessment.module !== "password" ? (
              <button className="btn-primary btn-sm" disabled={busy} onClick={() => void run()}>
                <CirclePlay size={14} /> {assessment.status === "completed" ? "Re-run" : "Run now"}
              </button>
            ) : null}
            {canManage && assessment.status === "queued" ? (
              <button className="btn-ghost btn-sm" disabled={busy} onClick={() => void cancel()}>
                <Ban size={13} /> Cancel
              </button>
            ) : null}
            {canManage && assessment.status === "completed" ? (
              <button
                className="btn-neon btn-sm"
                onClick={() => {
                  setReportTitle(`${assessment.name} · Assessment Report`);
                  setReportOpen(true);
                }}
              >
                <FileText size={14} /> Generate report
              </button>
            ) : null}
            {user?.role === "admin" ? (
              <button className="btn-danger btn-sm" onClick={() => setDeleteOpen(true)}>
                <Trash2 size={13} /> Delete
              </button>
            ) : null}
          </div>
        </div>
      </Panel>

      <div className="grid gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          <Panel className="p-5">
            <SectionTitle eyebrow="Evidence snapshot" title="Result summary" />
            <div className="mt-4 space-y-4">
              <MetricTiles summary={summary} />
              {assessment.module === "network" ? <NetworkHosts summary={summary} /> : null}
              {assessment.module === "network" && summary.topology ? (
                <div className="rounded-xl border border-line/70 bg-abyss/30 p-2">
                  <NetworkTopology topology={summary.topology} />
                </div>
              ) : null}
              {["recon", "osint"].includes(assessment.module) ? <SubdomainList summary={summary} /> : null}
              {assessment.module === "osint" ? <EvidenceList summary={summary} /> : null}
              {assessment.module === "api_security" ? <EndpointTable summary={summary} /> : null}
              {assessment.module === "red_team" ? <SimulationSteps summary={summary} /> : null}
              {Object.keys(summary).length ? (
                <div>
                  <button
                    className="flex items-center gap-1.5 font-mono text-[9px] uppercase tracking-wider text-mist transition hover:text-cyan"
                    onClick={() => setShowSummary((value) => !value)}
                  >
                    <ChevronDown size={12} className={cn("transition", showSummary && "rotate-180")} />
                    {showSummary ? "Hide" : "Show"} normalized result JSON
                  </button>
                  {showSummary ? (
                    <pre className="mt-2 max-h-80 overflow-auto rounded-lg border border-line/70 bg-void/70 p-3 font-mono text-[9px] leading-relaxed text-mist">
                      {JSON.stringify(summary, null, 2)}
                    </pre>
                  ) : null}
                </div>
              ) : (
                <p className="rounded-lg border border-line/60 bg-abyss/40 px-3 py-4 text-center text-[11px] text-mist">
                  No result payload recorded yet. Run the assessment to populate evidence.
                </p>
              )}
            </div>
          </Panel>

          <Panel className="p-5">
            <SectionTitle
              eyebrow="Triage queue"
              title={`Findings · ${findings.length}`}
              action={
                <Link to={`/findings?assessment=${assessment.id}`} className="font-mono text-[9px] uppercase tracking-wider text-cyan hover:text-white">
                  Open full queue
                </Link>
              }
            />
            <div className="mt-4 space-y-2">
              {findings.length ? (
                findings.map((finding) => (
                  <FindingCard key={finding.id} finding={finding} canEdit={canEditFindings} onStatus={updateStatus} />
                ))
              ) : (
                <EmptyState
                  icon={ShieldAlert}
                  title="No findings recorded"
                  description="A clean result is still evidence. Review the summary payload and consider an independent validation pass."
                />
              )}
            </div>
          </Panel>

          <Panel className="p-5">
            <SectionTitle
              eyebrow="Evidence preservation"
              title="Generated reports"
              action={
                assessment.status === "completed" && canManage ? (
                  <button
                    className="btn-primary btn-sm"
                    onClick={() => {
                      setReportTitle(`${assessment.name} · Assessment Report`);
                      setReportOpen(true);
                    }}
                  >
                    <FileText size={13} /> New report
                  </button>
                ) : null
              }
            />
            <div className="mt-4 space-y-2">
              {reports.length ? (
                reports.map((report) => (
                  <div key={report.id} className="flex flex-wrap items-center gap-3 rounded-xl border border-line/70 bg-abyss/40 px-3 py-2.5">
                    <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-cyan/20 bg-cyan/5 text-cyan">
                      <FileJson size={15} />
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-[11px] text-ice">{report.title}</p>
                      <p className="font-mono text-[9px] uppercase tracking-wider text-slate-600">
                        {report.format} · {formatBytes(report.size_bytes)} · {timeAgo(report.created_at)}
                      </p>
                    </div>
                    <button className="btn-ghost btn-sm" onClick={() => void download(report)}>
                      <Download size={12} /> Download
                    </button>
                    {user?.role === "admin" || report.created_by === user?.id ? (
                      <button
                        className="rounded-md border border-line p-1.5 text-mist transition hover:border-crimson/40 hover:text-crimson"
                        onClick={() => setPendingReportDelete(report)}
                        aria-label="Delete report"
                      >
                        <Trash2 size={12} />
                      </button>
                    ) : null}
                  </div>
                ))
              ) : (
                <p className="rounded-lg border border-line/60 bg-abyss/40 px-3 py-5 text-center text-[11px] text-mist">
                  No reports generated for this assessment yet.
                </p>
              )}
            </div>
          </Panel>
        </div>

        <div className="space-y-4">
          <Panel className="p-5">
            <SectionTitle eyebrow="Execution contract" title="Assessment details" />
            <dl className="mt-4 space-y-3 text-[11px]">
              {[
                { label: "Module", value: moduleLabel(assessment.module) },
                { label: "Status", value: assessment.status },
                { label: "Progress", value: `${assessment.progress}%` },
                { label: "Risk score", value: assessment.risk_score.toFixed(1) },
                { label: "Created by", value: assessment.created_by },
                { label: "Started", value: assessment.started_at ? formatDate(assessment.started_at) : "—" },
                { label: "Completed", value: assessment.finished_at ? formatDate(assessment.finished_at) : "—" },
              ].map((row) => (
                <div key={row.label} className="flex items-start justify-between gap-3 border-b border-line/40 pb-2 last:border-0">
                  <dt className="font-mono text-[8px] uppercase tracking-[0.16em] text-slate-600">{row.label}</dt>
                  <dd className="max-w-[60%] break-all text-right text-mist">{row.value}</dd>
                </div>
              ))}
            </dl>
            <button
              className="mt-4 flex w-full items-center justify-between rounded-lg border border-line/70 bg-abyss/40 px-3 py-2 font-mono text-[9px] uppercase tracking-wider text-mist transition hover:border-cyan/25 hover:text-cyan"
              onClick={() => setShowConfig((value) => !value)}
            >
              <span className="flex items-center gap-1.5">
                <Server size={12} /> Execution config
              </span>
              <ChevronDown size={12} className={cn("transition", showConfig && "rotate-180")} />
            </button>
            {showConfig ? (
              <pre className="mt-2 max-h-72 overflow-auto rounded-lg border border-line/70 bg-void/70 p-3 font-mono text-[9px] leading-relaxed text-mist">
                {JSON.stringify(assessment.config, null, 2)}
              </pre>
            ) : null}
          </Panel>

          <Panel className="p-5">
            <SectionTitle eyebrow="Scope integrity" title="Authorization context" />
            <div className="mt-4 space-y-3">
              <div className="flex items-start gap-2 rounded-lg border border-neon/20 bg-neon/[0.04] p-3">
                <Network size={14} className="mt-0.5 shrink-0 text-neon" />
                <p className="text-[10px] leading-relaxed text-mist">
                  Execution was gated by a verified target record. The engine received only the approved target
                  context and hard resource ceilings.
                </p>
              </div>
              <div className="rounded-lg border border-line/70 bg-abyss/40 p-3 font-mono text-[9px] leading-relaxed text-mist">
                <p className="text-slate-600">Assessment ID</p>
                <CopyValue value={assessment.id} label="assessment id" />
                <p className="mt-2 text-slate-600">Target</p>
                <p className="break-all text-ice">{assessment.target_value || "—"}</p>
              </div>
              <div className="flex items-center gap-2 font-mono text-[9px] uppercase tracking-wider text-slate-600">
                <Clock size={11} /> Demo data: {assessment.is_demo ? "yes" : "no"}
              </div>
            </div>
          </Panel>

          <Panel className="p-5">
            <SectionTitle eyebrow="Next steps" title="Pivot" />
            <div className="mt-3 space-y-2">
              <Link to="/findings" className="flex items-center justify-between rounded-lg border border-line/70 px-3 py-2 text-[11px] text-mist transition hover:border-cyan/25 hover:text-ice">
                Global findings queue <ChevronRight size={12} />
              </Link>
              <Link to="/mitre" className="flex items-center justify-between rounded-lg border border-line/70 px-3 py-2 text-[11px] text-mist transition hover:border-cyan/25 hover:text-ice">
                ATT&CK coverage view <ChevronRight size={12} />
              </Link>
              <Link to="/reports" className="flex items-center justify-between rounded-lg border border-line/70 px-3 py-2 text-[11px] text-mist transition hover:border-cyan/25 hover:text-ice">
                Report library <ChevronRight size={12} />
              </Link>
            </div>
          </Panel>
        </div>
      </div>

      <Modal
        open={reportOpen}
        onClose={() => setReportOpen(false)}
        title="Generate assessment report"
        eyebrow="Evidence export"
        description="Reports are rendered from stored findings and evidence. Demo data remains labelled in every format."
        footer={
          <>
            <button className="btn-ghost btn-sm" onClick={() => setReportOpen(false)} disabled={reportBusy}>
              Cancel
            </button>
            <button className="btn-primary btn-sm" onClick={() => void generateReport()} disabled={reportBusy}>
              {reportBusy ? <InlineSpinner label="Generating" /> : <Play size={13} />} Generate
            </button>
          </>
        }
      >
        <div className="space-y-4">
          <div>
            <label className="label" htmlFor="report-title">
              Report title
            </label>
            <input
              id="report-title"
              value={reportTitle}
              onChange={(event) => setReportTitle(event.target.value)}
              className="input"
              placeholder={`${assessment.name} · Assessment Report`}
            />
          </div>
          <div>
            <p className="label">Format</p>
            <div className="grid grid-cols-3 gap-2">
              {(["pdf", "html", "json"] as const).map((format) => (
                <button
                  key={format}
                  type="button"
                  onClick={() => setReportFormat(format)}
                  className={cn(
                    "rounded-xl border px-3 py-3 text-center transition",
                    reportFormat === format ? "border-cyan/40 bg-cyan/10 text-cyan" : "border-line bg-abyss/50 text-mist hover:text-ice",
                  )}
                >
                  <FileText size={16} className="mx-auto mb-1.5" />
                  <span className="font-mono text-[10px] uppercase tracking-wider">{format}</span>
                </button>
              ))}
            </div>
          </div>
          <p className="flex items-start gap-2 rounded-lg border border-line/70 bg-abyss/40 p-3 text-[10px] leading-relaxed text-mist">
            <ShieldAlert size={13} className="mt-0.5 shrink-0 text-amber" />
            The generated artifact is stored on the platform and downloaded only with an authenticated session.
            Review it before sharing outside your organization.
          </p>
        </div>
      </Modal>

      <ConfirmDialog
        open={deleteOpen}
        title="Delete assessment?"
        description={`This permanently removes "${assessment.name}", its findings, queue jobs and generated reports. The action is recorded in the immutable audit chain.`}
        confirmLabel="Delete assessment"
        danger
        busy={deleteBusy}
        onConfirm={() => void remove()}
        onClose={() => setDeleteOpen(false)}
      />
      <ConfirmDialog
        open={Boolean(pendingReportDelete)}
        title="Delete report?"
        description={`Remove "${pendingReportDelete?.title}" and its stored artifact? This cannot be undone.`}
        confirmLabel="Delete report"
        danger
        onConfirm={() => void deleteReport()}
        onClose={() => setPendingReportDelete(null)}
      />
    </div>
  );
}
