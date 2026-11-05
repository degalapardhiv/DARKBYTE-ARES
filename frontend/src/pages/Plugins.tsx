import { useCallback, useEffect, useState } from "react";
import {
  Boxes,
  Code2,
  Loader2,
  Play,
  Plug,
  RefreshCw,
  ShieldCheck,
  Terminal,
  ToggleLeft,
  ToggleRight,
} from "lucide-react";
import { PageHeader } from "../components/PageHeader";
import { Panel, SectionTitle, ErrorState, PageLoader, EmptyState, InlineSpinner } from "../components/ui";
import { Modal } from "../components/Modal";
import { api } from "../lib/api";
import type { Assessment, Plugin } from "../lib/types";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { cn, moduleLabel } from "../lib/utils";

export function Plugins() {
  const { user } = useAuth();
  const { notify } = useToast();
  const [items, setItems] = useState<Plugin[]>([]);
  const [policy, setPolicy] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [runPlugin, setRunPlugin] = useState<Plugin | null>(null);
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [assessmentId, setAssessmentId] = useState("");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [loadingAssessments, setLoadingAssessments] = useState(false);

  const isAdmin = user?.role === "admin";
  const canRun = user?.role === "admin" || user?.role === "analyst";

  const load = useCallback(async (silent = false) => {
    if (!silent) setRefreshing(true);
    try {
      const response = await api.plugins.list();
      setItems(response.items);
      setPolicy(response.policy);
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not load extensions.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const toggle = async (plugin: Plugin) => {
    setBusyId(plugin.id);
    try {
      if (plugin.enabled) await api.plugins.disable(plugin.id);
      else await api.plugins.enable(plugin.id);
      notify({ title: plugin.enabled ? "Extension disabled" : "Extension enabled", message: plugin.name, tone: "success" });
      await load(true);
    } catch (reason) {
      notify({ title: "Could not update extension", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" });
    } finally {
      setBusyId(null);
    }
  };

  const openRun = async (plugin: Plugin) => {
    setRunPlugin(plugin);
    setResult(null);
    setAssessmentId("");
    if (!assessments.length) {
      setLoadingAssessments(true);
      try {
        const response = await api.assessments.list({ status: "completed", limit: 100 });
        setAssessments(response.items);
        if (response.items[0]) setAssessmentId(response.items[0].id);
      } catch (reason) {
        notify({ title: "Could not load assessments", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" });
      } finally {
        setLoadingAssessments(false);
      }
    }
  };

  const run = async () => {
    if (!runPlugin || !assessmentId) return;
    setRunning(true);
    try {
      const response = await api.plugins.run(runPlugin.id, assessmentId);
      setResult(response.result);
      notify({ title: "Extension executed", message: `${runPlugin.name} processed assessment evidence.`, tone: "success" });
    } catch (reason) {
      notify({ title: "Extension failed", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" });
    } finally {
      setRunning(false);
    }
  };

  if (loading) return <PageLoader label="Loading trusted extensions" />;

  return (
    <div>
      <PageHeader
        eyebrow="Extensibility"
        title="Extensions"
        description="Trusted local plugins extend ARES with additional evidence processing. Plugins run in the platform process, are disabled by default and require administrator approval."
        actions={
          <button className="btn-ghost" onClick={() => void load()} disabled={refreshing}>
            <RefreshCw size={14} className={refreshing ? "animate-spin" : ""} /> Refresh
          </button>
        }
      />

      <div className="mb-4 flex items-start gap-3 rounded-xl border border-amber/20 bg-amber/[0.04] px-4 py-3">
        <ShieldCheck size={16} className="mt-0.5 shrink-0 text-amber" />
        <div>
          <p className="font-mono text-[9px] uppercase tracking-[0.18em] text-amber">Trust boundary</p>
          <p className="mt-1 text-[11px] leading-relaxed text-mist">
            {policy || "Plugins are trusted local code. Only install extensions from sources you control and review before enabling."}
          </p>
        </div>
      </div>

      {error ? (
        <ErrorState message={error} onRetry={() => void load()} />
      ) : !items.length ? (
        <Panel>
          <EmptyState
            icon={Boxes}
            title="No extensions discovered"
            description="Drop a trusted plugin into the plugins directory and restart the API to inventory it."
          />
        </Panel>
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          {items.map((plugin) => (
            <Panel key={plugin.id} hover className="p-5">
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-start gap-3">
                  <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-cyan/25 bg-cyan/10 text-cyan">
                    <Plug size={19} />
                  </span>
                  <div>
                    <p className="text-sm font-medium text-ice">{plugin.name}</p>
                    <p className="mt-0.5 font-mono text-[9px] uppercase tracking-wider text-slate-600">
                      v{plugin.version} · by {plugin.author}
                    </p>
                  </div>
                </div>
                <span
                  className={cn(
                    "chip",
                    plugin.enabled ? "border-neon/25 bg-neon/5 text-neon" : "border-line text-mist",
                  )}
                >
                  {plugin.enabled ? "enabled" : "disabled"}
                </span>
              </div>

              <p className="mt-3 line-clamp-3 text-[11px] leading-relaxed text-mist">{plugin.description}</p>

              <div className="mt-3">
                <p className="mb-1.5 font-mono text-[8px] uppercase tracking-[0.18em] text-slate-600">Declared permissions</p>
                <div className="flex flex-wrap gap-1">
                  {plugin.permissions.length ? (
                    plugin.permissions.map((permission) => (
                      <span key={permission} className="chip text-[9px]">
                        {permission}
                      </span>
                    ))
                  ) : (
                    <span className="text-[9px] text-slate-600">No permissions declared.</span>
                  )}
                </div>
              </div>

              <div className="mt-3 flex flex-wrap items-center gap-2 rounded-lg border border-line/60 bg-abyss/40 px-2.5 py-2">
                <Code2 size={11} className="text-slate-600" />
                <span className="truncate font-mono text-[8px] text-slate-600">{plugin.path}</span>
                {plugin.min_ares_version ? (
                  <span className="ml-auto font-mono text-[8px] uppercase tracking-wider text-slate-600">
                    ARES ≥ {plugin.min_ares_version}
                  </span>
                ) : null}
              </div>

              <div className="mt-4 flex flex-wrap items-center gap-1.5">
                {isAdmin ? (
                  <button
                    className={plugin.enabled ? "btn-ghost btn-sm" : "btn-neon btn-sm"}
                    onClick={() => void toggle(plugin)}
                    disabled={busyId === plugin.id}
                  >
                    {busyId === plugin.id ? (
                      <Loader2 size={12} className="animate-spin" />
                    ) : plugin.enabled ? (
                      <ToggleLeft size={13} />
                    ) : (
                      <ToggleRight size={13} />
                    )}
                    {plugin.enabled ? "Disable" : "Enable"}
                  </button>
                ) : null}
                {canRun ? (
                  <button
                    className="btn-primary btn-sm"
                    onClick={() => void openRun(plugin)}
                    disabled={!plugin.enabled}
                    title={plugin.enabled ? "Run against a completed assessment" : "Administrator must enable this extension first"}
                  >
                    <Play size={12} /> Run
                  </button>
                ) : null}
                <span className="ml-auto flex items-center gap-1 font-mono text-[8px] uppercase tracking-wider text-slate-600">
                  <Terminal size={10} /> local code
                </span>
              </div>
            </Panel>
          ))}
        </div>
      )}

      <Panel className="mt-4 p-5">
        <SectionTitle eyebrow="Extension model" title="How plugins are handled" />
        <div className="mt-3 grid gap-3 md:grid-cols-3">
          {[
            { title: "Inventory only", detail: "Plugins are discovered from the local plugins directory. Remote installation is not supported." },
            { title: "Administrator gate", detail: "A plugin remains disabled until an administrator explicitly enables it; the change is audited." },
            { title: "Evidence scoped", detail: "Execution requires a completed assessment ID and operates on stored evidence only." },
          ].map((item) => (
            <div key={item.title} className="rounded-xl border border-line/70 bg-abyss/40 p-3">
              <p className="text-[11px] font-medium text-ice">{item.title}</p>
              <p className="mt-1 text-[10px] leading-relaxed text-mist">{item.detail}</p>
            </div>
          ))}
        </div>
      </Panel>

      <Modal
        open={Boolean(runPlugin)}
        onClose={() => {
          setRunPlugin(null);
          setResult(null);
        }}
        title={`Run ${runPlugin?.name || "extension"}`}
        eyebrow="Trusted local execution"
        description="The extension receives evidence from the selected completed assessment. Its result is returned for review and recorded in the audit log."
        footer={
          result ? (
            <>
              <button className="btn-ghost btn-sm" onClick={() => setResult(null)}>
                Run again
              </button>
              <button
                className="btn-primary btn-sm"
                onClick={() => {
                  setRunPlugin(null);
                  setResult(null);
                }}
              >
                Close
              </button>
            </>
          ) : (
            <>
              <button className="btn-ghost btn-sm" onClick={() => setRunPlugin(null)} disabled={running}>
                Cancel
              </button>
              <button className="btn-primary btn-sm" onClick={() => void run()} disabled={running || !assessmentId || loadingAssessments}>
                {running ? <InlineSpinner label="Executing" /> : <Play size={13} />} Execute
              </button>
            </>
          )
        }
      >
        {result ? (
          <div className="space-y-3">
            <div className="flex items-center gap-2 rounded-lg border border-neon/20 bg-neon/[0.04] p-3">
              <ShieldCheck size={15} className="text-neon" />
              <p className="text-[11px] text-ice">Extension completed successfully. Review the structured result below.</p>
            </div>
            <pre className="max-h-[50vh] overflow-auto rounded-lg border border-line/70 bg-void/70 p-4 font-mono text-[9px] leading-relaxed text-mist">
              {JSON.stringify(result, null, 2)}
            </pre>
          </div>
        ) : loadingAssessments ? (
          <div className="py-8 text-center">
            <InlineSpinner label="Loading completed assessments" />
          </div>
        ) : (
          <div className="space-y-4">
            <div>
              <label className="label" htmlFor="plugin-assessment">
                Completed assessment
              </label>
              <select
                id="plugin-assessment"
                value={assessmentId}
                onChange={(event) => setAssessmentId(event.target.value)}
                className="input"
              >
                <option value="">Select an assessment</option>
                {assessments.map((assessment) => (
                  <option key={assessment.id} value={assessment.id}>
                    {assessment.name} · {moduleLabel(assessment.module)}
                  </option>
                ))}
              </select>
              {!assessments.length ? (
                <p className="mt-2 text-[10px] text-amber">No completed assessments are available for plugin execution.</p>
              ) : null}
            </div>
            <div className="rounded-lg border border-line/70 bg-abyss/40 p-3 font-mono text-[9px] leading-relaxed text-mist">
              <p className="flex items-center gap-1.5 text-slate-600">
                <Code2 size={11} /> {runPlugin?.path}
              </p>
              <p className="mt-1.5">
                Permissions: {runPlugin?.permissions.length ? runPlugin.permissions.join(", ") : "none declared"}
              </p>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
