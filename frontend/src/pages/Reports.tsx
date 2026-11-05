import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Download,
  Eye,
  FileJson,
  FileText,
  FileType2,
  Loader2,
  Plus,
  RefreshCw,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import { PageHeader } from "../components/PageHeader";
import { Panel, Pagination, ErrorState, PageLoader, EmptyState, SectionTitle, InlineSpinner } from "../components/ui";
import { DemoBadge } from "../components/Badges";
import { ConfirmDialog, Modal } from "../components/Modal";
import { api, saveBlob } from "../lib/api";
import type { Assessment, Report } from "../lib/types";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { cn, formatBytes, formatDate, moduleLabel, timeAgo } from "../lib/utils";

const FORMATS = ["pdf", "html", "json"] as const;

function FormatIcon({ format, size = 18 }: { format: string; size?: number }) {
  if (format === "json") return <FileJson size={size} />;
  if (format === "html") return <FileType2 size={size} />;
  return <FileText size={size} />;
}

export function Reports() {
  const { user } = useAuth();
  const { notify } = useToast();
  const [items, setItems] = useState<Report[]>([]);
  const [total, setTotal] = useState(0);
  const [limit] = useState(25);
  const [offset, setOffset] = useState(0);
  const [format, setFormat] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [assessmentId, setAssessmentId] = useState("");
  const [newFormat, setNewFormat] = useState<"pdf" | "html" | "json">("pdf");
  const [title, setTitle] = useState("");
  const [creating, setCreating] = useState(false);
  const [loadingAssessments, setLoadingAssessments] = useState(false);
  const [selected, setSelected] = useState<Report | null>(null);
  const [pendingDelete, setPendingDelete] = useState<Report | null>(null);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  const load = useCallback(async (silent = false) => {
    if (!silent) setRefreshing(true);
    try {
      const response = await api.reports.list({ fmt: format || undefined, limit, offset });
      setItems(response.items);
      setTotal(response.total);
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not load reports.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [format, limit, offset]);

  useEffect(() => {
    void load();
  }, [load]);

  const openCreate = async () => {
    setCreateOpen(true);
    setTitle("");
    setAssessmentId("");
    if (!assessments.length) {
      setLoadingAssessments(true);
      try {
        const response = await api.assessments.list({ status: "completed", limit: 100 });
        setAssessments(response.items);
        if (response.items[0]) setAssessmentId(response.items[0].id);
      } catch (reason) {
        notify({ title: "Could not load completed assessments", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" });
      } finally {
        setLoadingAssessments(false);
      }
    }
  };

  const create = async () => {
    if (!assessmentId) {
      notify({ title: "Select an assessment", message: "Reports are generated from completed assessments with stored evidence.", tone: "warning" });
      return;
    }
    setCreating(true);
    try {
      const report = await api.reports.create({
        assessment_id: assessmentId,
        format: newFormat,
        title: title.trim() || undefined,
      });
      notify({ title: "Report generated", message: `${report.format.toUpperCase()} · ${formatBytes(report.size_bytes)}`, tone: "success" });
      setCreateOpen(false);
      await load(true);
    } catch (reason) {
      notify({ title: "Report generation failed", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" });
    } finally {
      setCreating(false);
    }
  };

  const download = async (report: Report) => {
    setDownloadingId(report.id);
    try {
      const { blob, filename } = await api.reports.download(report.id);
      saveBlob(blob, filename);
      notify({ title: "Download started", message: filename, tone: "success" });
    } catch (reason) {
      notify({ title: "Download failed", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" });
    } finally {
      setDownloadingId(null);
    }
  };

  const remove = async () => {
    if (!pendingDelete) return;
    try {
      await api.reports.remove(pendingDelete.id);
      notify({ title: "Report deleted", message: pendingDelete.title, tone: "success" });
      if (selected?.id === pendingDelete.id) setSelected(null);
      setPendingDelete(null);
      await load(true);
    } catch (reason) {
      notify({ title: "Could not delete report", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" });
    }
  };

  const totalBytes = items.reduce((sum, report) => sum + report.size_bytes, 0);
  const selectedAssessment = selected ? assessments.find((assessment) => assessment.id === selected.assessment_id) : null;
  const canCreate = user?.role === "admin" || user?.role === "analyst";

  if (loading) return <PageLoader label="Loading report library" />;

  return (
    <div>
      <PageHeader
        eyebrow="Evidence exports"
        title="Reports"
        description="Generate and distribute PDF, HTML and JSON artifacts from stored assessment evidence. Downloads require an authenticated session and are written to the audit trail."
        actions={
          <>
            <button className="btn-ghost" onClick={() => void load()} disabled={refreshing}>
              <RefreshCw size={14} className={refreshing ? "animate-spin" : ""} /> Refresh
            </button>
            {canCreate ? (
              <button className="btn-primary" onClick={() => void openCreate()}>
                <Plus size={15} /> Generate report
              </button>
            ) : null}
          </>
        }
      />

      <div className="mb-4 grid gap-3 sm:grid-cols-3">
        <Panel className="p-4">
          <p className="font-mono text-[9px] uppercase tracking-[0.18em] text-mist">Reports</p>
          <p className="stat-value mt-2">{total}</p>
          <p className="mt-1 text-[10px] text-mist">Artifacts retained in the evidence store</p>
        </Panel>
        <Panel className="p-4">
          <p className="font-mono text-[9px] uppercase tracking-[0.18em] text-mist">Visible payload</p>
          <p className="stat-value mt-2">{formatBytes(totalBytes)}</p>
          <p className="mt-1 text-[10px] text-mist">Across this page of results</p>
        </Panel>
        <Panel className="p-4">
          <p className="font-mono text-[9px] uppercase tracking-[0.18em] text-mist">Available formats</p>
          <p className="mt-2.5 flex gap-2">
            {FORMATS.map((item) => (
              <span key={item} className="chip border-cyan/20 text-cyan">
                {item}
              </span>
            ))}
          </p>
          <p className="mt-2 flex items-center gap-1.5 text-[10px] text-mist">
            <ShieldCheck size={11} className="text-neon" /> Demo labels preserved in exports
          </p>
        </Panel>
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-2 rounded-xl border border-line/70 bg-panel/60 p-3">
        <span className="font-mono text-[9px] uppercase tracking-wider text-slate-600">Format filter</span>
        <button
          onClick={() => {
            setFormat("");
            setOffset(0);
          }}
          className={cn("chip transition", !format && "border-cyan/30 text-cyan")}
        >
          All
        </button>
        {FORMATS.map((item) => (
          <button
            key={item}
            onClick={() => {
              setFormat(item);
              setOffset(0);
            }}
            className={cn("chip transition", format === item && "border-cyan/30 text-cyan")}
          >
            {item}
          </button>
        ))}
        <span className="ml-auto font-mono text-[9px] uppercase tracking-wider text-slate-600">{total} artifacts</span>
      </div>

      {error ? (
        <ErrorState message={error} onRetry={() => void load()} />
      ) : !items.length ? (
        <Panel>
          <EmptyState
            icon={FileText}
            title="No reports generated"
            description="Complete an assessment, then generate a PDF, HTML or JSON artifact from its evidence."
            action={
              canCreate ? (
                <button className="btn-primary btn-sm" onClick={() => void openCreate()}>
                  <Plus size={14} /> Generate the first report
                </button>
              ) : undefined
            }
          />
        </Panel>
      ) : (
        <div className="grid gap-3 lg:grid-cols-2 xl:grid-cols-3">
          {items.map((report) => (
            <Panel key={report.id} hover className="flex flex-col p-4">
              <div className="flex items-start justify-between gap-3">
                <span
                  className={cn(
                    "flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border",
                    report.format === "pdf"
                      ? "border-crimson/25 bg-crimson/10 text-crimson"
                      : report.format === "html"
                        ? "border-violet/30 bg-violet/10 text-violet"
                        : "border-cyan/25 bg-cyan/10 text-cyan",
                  )}
                >
                  <FormatIcon format={report.format} />
                </span>
                <div className="flex items-center gap-1.5">
                  {report.is_demo ? <DemoBadge compact /> : null}
                  <span className="chip">{report.format}</span>
                </div>
              </div>
              <button className="mt-3 text-left" onClick={() => setSelected(report)}>
                <p className="line-clamp-2 text-xs font-medium leading-relaxed text-ice transition hover:text-cyan">{report.title}</p>
              </button>
              <p className="mt-1.5 flex-1 line-clamp-2 text-[10px] leading-relaxed text-mist">
                {report.executive_summary || "Executive summary unavailable."}
              </p>
              <div className="mt-3 flex items-center justify-between border-t border-line/60 pt-2.5 font-mono text-[8px] uppercase tracking-wider text-slate-600">
                <span>{formatBytes(report.size_bytes)}</span>
                <span>{timeAgo(report.created_at)}</span>
              </div>
              <div className="mt-3 flex items-center gap-1.5">
                <button className="btn-primary btn-sm flex-1" onClick={() => void download(report)} disabled={downloadingId === report.id}>
                  {downloadingId === report.id ? <Loader2 size={12} className="animate-spin" /> : <Download size={12} />} Download
                </button>
                <button
                  className="rounded-md border border-line p-1.5 text-mist transition hover:border-cyan/40 hover:text-cyan"
                  onClick={() => setSelected(report)}
                  aria-label="Report details"
                >
                  <Eye size={13} />
                </button>
                {(user?.role === "admin" || report.created_by === user?.id) ? (
                  <button
                    className="rounded-md border border-line p-1.5 text-mist transition hover:border-crimson/40 hover:text-crimson"
                    onClick={() => setPendingDelete(report)}
                    aria-label="Delete report"
                  >
                    <Trash2 size={13} />
                  </button>
                ) : null}
              </div>
            </Panel>
          ))}
        </div>
      )}

      <div className="mt-4">
        <Panel className="overflow-hidden">
          <Pagination total={total} limit={limit} offset={offset} onChange={setOffset} />
        </Panel>
      </div>

      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title="Generate evidence report"
        eyebrow="Report builder"
        description="Only completed assessments can be exported. The report is rendered server-side from stored findings and evidence."
        footer={
          <>
            <button className="btn-ghost btn-sm" onClick={() => setCreateOpen(false)} disabled={creating}>
              Cancel
            </button>
            <button className="btn-primary btn-sm" onClick={() => void create()} disabled={creating || loadingAssessments}>
              {creating ? <InlineSpinner label="Rendering" /> : <FileText size={13} />} Generate
            </button>
          </>
        }
      >
        {loadingAssessments ? (
          <div className="py-8 text-center">
            <InlineSpinner label="Loading completed assessments" />
          </div>
        ) : (
          <div className="space-y-4">
            <div>
              <label className="label" htmlFor="report-assessment">
                Source assessment
              </label>
              <select
                id="report-assessment"
                value={assessmentId}
                onChange={(event) => setAssessmentId(event.target.value)}
                className="input"
              >
                <option value="">Select a completed assessment</option>
                {assessments.map((assessment) => (
                  <option key={assessment.id} value={assessment.id}>
                    {assessment.name} · {moduleLabel(assessment.module)}
                  </option>
                ))}
              </select>
              {!assessments.length ? (
                <p className="mt-2 text-[10px] text-amber">
                  No completed assessments are available. Complete one first, then return to generate a report.
                </p>
              ) : null}
            </div>
            <div>
              <label className="label" htmlFor="report-title-create">
                Title <span className="normal-case tracking-normal text-slate-600">(optional)</span>
              </label>
              <input
                id="report-title-create"
                value={title}
                onChange={(event) => setTitle(event.target.value)}
                className="input"
                placeholder="Generated from the assessment name when blank"
              />
            </div>
            <div>
              <p className="label">Format</p>
              <div className="grid grid-cols-3 gap-2">
                {FORMATS.map((item) => (
                  <button
                    key={item}
                    type="button"
                    onClick={() => setNewFormat(item)}
                    className={cn(
                      "rounded-xl border px-3 py-3 text-center transition",
                      newFormat === item ? "border-cyan/40 bg-cyan/10 text-cyan" : "border-line bg-abyss/50 text-mist hover:text-ice",
                    )}
                  >
                    <FormatIcon format={item} size={16} />
                    <span className="mt-1.5 block font-mono text-[10px] uppercase tracking-wider">{item}</span>
                  </button>
                ))}
              </div>
            </div>
            <p className="rounded-lg border border-line/70 bg-abyss/40 p-3 text-[10px] leading-relaxed text-mist">
              Report artifacts are stored under the configured data directory and require authorization to download.
              Demo records remain labelled in every format.
            </p>
          </div>
        )}
      </Modal>

      <Modal
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        title={selected?.title || "Report"}
        eyebrow={selected ? `${selected.format.toUpperCase()} · ${formatBytes(selected.size_bytes)}` : "Report detail"}
        size="lg"
        footer={
          selected ? (
            <>
              <button className="btn-ghost btn-sm" onClick={() => setSelected(null)}>
                Close
              </button>
              <button className="btn-primary btn-sm" onClick={() => void download(selected)}>
                <Download size={13} /> Download
              </button>
            </>
          ) : null
        }
      >
        {selected ? (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              <span className="chip border-cyan/25 text-cyan">{selected.format}</span>
              <span className="chip">{selected.status}</span>
              {selected.is_demo ? <DemoBadge /> : null}
              <span className="ml-auto font-mono text-[9px] text-slate-600">{formatDate(selected.created_at)}</span>
            </div>
            <div>
              <SectionTitle eyebrow="Executive summary" title="Assessment narrative" />
              <p className="mt-2 text-xs leading-relaxed text-mist">
                {selected.executive_summary || "No executive summary was recorded for this artifact."}
              </p>
            </div>
            <div className="grid gap-2 sm:grid-cols-2">
              <div className="rounded-lg border border-line/70 bg-abyss/40 p-3">
                <p className="font-mono text-[8px] uppercase tracking-wider text-slate-600">Assessment</p>
                <p className="mt-1 break-all font-mono text-[9px] text-ice">{selected.assessment_id}</p>
              </div>
              <div className="rounded-lg border border-line/70 bg-abyss/40 p-3">
                <p className="font-mono text-[8px] uppercase tracking-wider text-slate-600">Generated by</p>
                <p className="mt-1 break-all font-mono text-[9px] text-ice">{selected.created_by}</p>
              </div>
            </div>
            {selectedAssessment ? (
              <Link
                to={`/assessments/${selectedAssessment.id}`}
                className="btn-ghost btn-sm w-full"
                onClick={() => setSelected(null)}
              >
                Open source assessment
              </Link>
            ) : null}
            <div>
              <p className="mb-1.5 font-mono text-[8px] uppercase tracking-[0.18em] text-mist">Report metadata</p>
              <pre className="max-h-56 overflow-auto rounded-lg border border-line/70 bg-void/60 p-3 font-mono text-[9px] leading-relaxed text-mist">
                {JSON.stringify(selected.meta, null, 2)}
              </pre>
            </div>
          </div>
        ) : null}
      </Modal>

      <ConfirmDialog
        open={Boolean(pendingDelete)}
        title="Delete report?"
        description={`Permanently remove "${pendingDelete?.title}" and its stored artifact? This action is recorded in the audit chain.`}
        confirmLabel="Delete report"
        danger
        onConfirm={() => void remove()}
        onClose={() => setPendingDelete(null)}
      />
    </div>
  );
}
