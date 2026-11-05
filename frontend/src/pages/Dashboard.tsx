import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  ArrowUpRight,
  ChevronRight,
  Crosshair,
  FileText,
  Gauge,
  Radar,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Target,
  TrendingDown,
  TrendingUp,
  Zap,
} from "lucide-react";
import { PageHeader } from "../components/PageHeader";
import { Panel, SectionTitle, StatCard, PageLoader, ErrorState, ProgressBar } from "../components/ui";
import { RiskTrendChart, SeverityDonut, SeverityLegend, ModuleRiskChart } from "../components/Charts";
import { SeverityBadge, StatusBadge, RiskPill, DemoBadge } from "../components/Badges";
import { ImageWithFallback } from "../components/ImageWithFallback";
import { Icon } from "../components/Icon";
import { ModuleLauncher } from "../components/ModuleLauncher";
import { api } from "../lib/api";
import type { DashboardData } from "../lib/types";
import { MODULE_META } from "../lib/constants";
import { useAuth } from "../context/AuthContext";
import { cn, formatDate, moduleLabel, riskLabel, timeAgo } from "../lib/utils";

export function Dashboard() {
  const { user } = useAuth();
  const [data, setData] = useState<DashboardData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [launcherOpen, setLauncherOpen] = useState(false);

  const load = useCallback(async (silent = false) => {
    if (!silent) setRefreshing(true);
    try {
      const response = await api.dashboard.overview();
      setData(response);
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not load the dashboard.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(true), 30000);
    return () => window.clearInterval(timer);
  }, [load]);

  if (loading) return <PageLoader label="Synchronizing command telemetry" />;
  if (error && !data) {
    return (
      <div>
        <PageHeader eyebrow="Command dashboard" title="Telemetry unavailable" description={error} />
        <ErrorState message={error} onRetry={() => void load()} />
      </div>
    );
  }
  if (!data) return null;

  const stats = data.stats;
  const delta = stats.assessments_last_7_days - stats.assessments_prior_7_days;
  const firstName = user?.name.split(" ")[0] || "Operator";
  const criticalWork = stats.critical_findings + stats.high_findings;

  return (
    <div className="space-y-6">
      <section className="relative overflow-hidden rounded-2xl border border-line/80 bg-panel shadow-panel">
        <ImageWithFallback
          src="/assets/cyber-hero.webp"
          alt="ARES security operations visualization"
          className="absolute inset-0 h-full w-full object-cover opacity-50"
          loading="eager"
        />
        <div className="absolute inset-0 bg-gradient-to-r from-void via-void/85 to-void/25" />
        <div className="absolute inset-0 bg-grid-faint bg-grid opacity-30" />
        <div className="relative flex flex-col gap-6 p-5 md:p-7 lg:flex-row lg:items-end lg:justify-between">
          <div className="max-w-2xl">
            <div className="flex flex-wrap items-center gap-2">
              <span className="chip border-cyan/30 bg-cyan/10 text-cyan">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-cyan" /> Console online
              </span>
              <span className="chip border-neon/25 text-neon">Authorized use only</span>
              {data.recent_assessments.some((item) => item.is_demo) ? <DemoBadge /> : null}
            </div>
            <p className="eyebrow mt-5">Command dashboard · {formatDate(new Date().toISOString(), false)}</p>
            <h1 className="mt-2 text-balance text-2xl font-semibold tracking-tight text-white md:text-3xl">
              Welcome back, {firstName}.
            </h1>
            <p className="mt-2 max-w-xl text-sm leading-relaxed text-mist">
              Ten scoped modules, one immutable evidence trail. Prioritize{" "}
              <span className="text-ice">{criticalWork} high-severity exposure{criticalWork === 1 ? "" : "s"}</span>{" "}
              across {stats.verified_targets} verified target{stats.verified_targets === 1 ? "" : "s"}.
            </p>
            <div className="mt-5 flex flex-wrap gap-2">
              <button className="btn-primary" onClick={() => setLauncherOpen(true)}>
                <Sparkles size={15} /> Launch module
              </button>
              <Link to="/findings" className="btn-ghost">
                <ShieldAlert size={15} /> Triage findings
              </Link>
              <button className="btn-ghost" onClick={() => void load()} disabled={refreshing}>
                <Activity size={15} className={refreshing ? "animate-pulse" : ""} />
                {refreshing ? "Refreshing…" : "Refresh"}
              </button>
            </div>
          </div>
          <div className="grid w-full max-w-md grid-cols-3 gap-3 lg:w-auto">
            {[
              { label: "Risk index", value: stats.avg_risk.toFixed(1), hint: riskLabel(stats.avg_risk), color: "#00E5FF" },
              { label: "Open findings", value: stats.open_findings, hint: `${stats.total_findings} total`, color: "#FFB020" },
              { label: "MITRE coverage", value: `${data.mitre.percentage}%`, hint: `${data.mitre.covered}/${data.mitre.total} techniques`, color: "#00FF88" },
            ].map((item) => (
              <div key={item.label} className="rounded-xl border border-white/10 bg-void/55 p-3 backdrop-blur">
                <p className="font-mono text-[8px] uppercase tracking-[0.18em] text-mist">{item.label}</p>
                <p className="mt-2 font-mono text-xl font-semibold" style={{ color: item.color }}>
                  {item.value}
                </p>
                <p className="mt-1 truncate text-[9px] text-mist">{item.hint}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Assessments"
          value={stats.total_assessments}
          hint={`${stats.completed_assessments} completed · ${stats.active_assessments} active`}
          icon={Radar}
          accent="#00E5FF"
          delta={{ value: delta, label: "vs prior 7 days" }}
        />
        <StatCard
          label="Critical + high"
          value={criticalWork}
          hint={`${stats.critical_findings} critical · ${stats.high_findings} high`}
          icon={ShieldAlert}
          accent="#FF3B5C"
        />
        <StatCard
          label="Verified scope"
          value={stats.verified_targets}
          hint={`${stats.pending_targets} awaiting authorization`}
          icon={Crosshair}
          accent="#00FF88"
        />
        <StatCard
          label="Average risk"
          value={stats.avg_risk.toFixed(1)}
          hint={`${stats.reports} report${stats.reports === 1 ? "" : "s"} generated`}
          icon={Gauge}
          accent="#7C3AED"
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel className="p-5 xl:col-span-2">
          <SectionTitle
            eyebrow="Exposure trajectory"
            title="Risk & assessment velocity"
            action={
              <span className="flex items-center gap-1.5 font-mono text-[9px] uppercase tracking-wider text-mist">
                {delta >= 0 ? <TrendingUp size={12} className="text-cyan" /> : <TrendingDown size={12} className="text-neon" />}
                {Math.abs(delta)} {delta >= 0 ? "more" : "fewer"} this week
              </span>
            }
          />
          <div className="mt-4">
            <RiskTrendChart data={data.risk_trend} />
          </div>
          <div className="mt-2 flex items-center gap-4 border-t border-line/60 pt-3 font-mono text-[8px] uppercase tracking-wider text-slate-600">
            <span className="flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-cyan" /> Risk score
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-violet" /> Assessments
            </span>
            <span className="ml-auto">14-day window</span>
          </div>
        </Panel>

        <Panel className="p-5">
          <SectionTitle
            eyebrow="Finding distribution"
            title="Severity posture"
            action={
              <Link to="/findings" className="font-mono text-[9px] uppercase tracking-wider text-cyan hover:text-white">
                Open findings
              </Link>
            }
          />
          <SeverityDonut data={data.severity} />
          <div className="border-t border-line/60 pt-3">
            <SeverityLegend data={data.severity} />
          </div>
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel className="p-5">
          <SectionTitle eyebrow="Module risk" title="Exposure by discipline" />
          <div className="mt-2">
            <ModuleRiskChart data={data.modules} />
          </div>
        </Panel>

        <Panel className="p-5">
          <SectionTitle
            eyebrow="Detection engineering"
            title="MITRE ATT&CK coverage"
            action={
              <Link to="/mitre" className="font-mono text-[9px] uppercase tracking-wider text-cyan hover:text-white">
                Matrix
              </Link>
            }
          />
          <div className="mt-4 flex items-end justify-between">
            <div>
              <p className="font-mono text-3xl font-semibold text-white">{data.mitre.percentage}%</p>
              <p className="mt-1 font-mono text-[9px] uppercase tracking-wider text-mist">
                {data.mitre.covered} of {data.mitre.total} techniques observed
              </p>
            </div>
            <span className="chip border-neon/25 text-neon">
              <ShieldCheck size={11} /> mapped
            </span>
          </div>
          <div className="mt-3">
            <ProgressBar value={data.mitre.percentage} color="#00FF88" height={6} />
          </div>
          <div className="mt-4 space-y-2.5">
            {data.mitre.tactics
              .slice()
              .sort((a, b) => b.percentage - a.percentage)
              .slice(0, 6)
              .map((tactic) => (
                <div key={tactic.id}>
                  <div className="mb-1 flex items-center justify-between gap-2">
                    <span className="truncate text-[10px] text-mist">{tactic.name}</span>
                    <span className="font-mono text-[9px] text-ice">
                      {tactic.covered}/{tactic.total}
                    </span>
                  </div>
                  <div className="h-1 overflow-hidden rounded-full bg-line/60">
                    <div
                      className="h-full rounded-full bg-gradient-to-r from-neon/60 to-cyan/60"
                      style={{ width: `${Math.min(100, tactic.percentage)}%` }}
                    />
                  </div>
                </div>
              ))}
          </div>
        </Panel>

        <Panel className="flex flex-col p-5">
          <SectionTitle
            eyebrow="Immutable audit"
            title="Live activity"
            action={
              <span className="flex items-center gap-1 font-mono text-[8px] uppercase tracking-wider text-neon">
                <span className="h-1 w-1 animate-pulse rounded-full bg-neon" /> streaming
              </span>
            }
          />
          <div className="mt-4 flex-1 space-y-3">
            {data.activity.map((entry) => (
              <div key={entry.id} className="flex items-start gap-2.5">
                <span
                  className={cn(
                    "mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full",
                    entry.outcome === "success" ? "bg-neon" : entry.outcome === "denied" ? "bg-crimson" : "bg-cyan",
                  )}
                />
                <div className="min-w-0 flex-1">
                  <p className="truncate font-mono text-[10px] text-ice">{entry.action}</p>
                  <p className="mt-0.5 truncate text-[9px] text-slate-600">
                    {entry.actor} · {entry.resource_type}
                  </p>
                </div>
                <span className="shrink-0 font-mono text-[8px] text-slate-600">{timeAgo(entry.created_at)}</span>
              </div>
            ))}
            {!data.activity.length ? <p className="py-6 text-center text-xs text-mist">No audit activity yet.</p> : null}
          </div>
          <Link
            to="/audit"
            className="mt-4 flex items-center justify-between border-t border-line/60 pt-3 font-mono text-[9px] uppercase tracking-wider text-mist transition hover:text-cyan"
          >
            Inspect hash chain <ChevronRight size={12} />
          </Link>
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel className="overflow-hidden xl:col-span-2">
          <div className="flex items-center justify-between border-b border-line/70 px-5 py-4">
            <SectionTitle eyebrow="Operations" title="Recent assessments" />
            <Link to="/assessments" className="font-mono text-[9px] uppercase tracking-wider text-cyan hover:text-white">
              View all
            </Link>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[620px]">
              <thead className="table-head">
                <tr>
                  <th className="px-5 py-2.5 text-left">Assessment</th>
                  <th className="px-3 py-2.5 text-left">Module</th>
                  <th className="px-3 py-2.5 text-left">Status</th>
                  <th className="px-3 py-2.5 text-left">Risk</th>
                  <th className="px-5 py-2.5 text-right">Created</th>
                </tr>
              </thead>
              <tbody>
                {data.recent_assessments.map((assessment) => (
                  <tr key={assessment.id} className="table-row">
                    <td className="max-w-[280px] px-5 py-3">
                      <Link to={`/assessments/${assessment.id}`} className="block truncate text-xs text-ice hover:text-cyan">
                        {assessment.name}
                      </Link>
                      <span className="mt-0.5 block truncate font-mono text-[9px] text-slate-600">
                        {assessment.target_name || assessment.target_value || "—"}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-3 py-3 text-[10px] text-mist">{moduleLabel(assessment.module)}</td>
                    <td className="px-3 py-3">
                      <StatusBadge status={assessment.status} />
                    </td>
                    <td className="px-3 py-3">
                      <RiskPill score={assessment.risk_score} />
                    </td>
                    <td className="whitespace-nowrap px-5 py-3 text-right font-mono text-[9px] text-slate-600">
                      {timeAgo(assessment.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!data.recent_assessments.length ? <p className="py-10 text-center text-xs text-mist">No assessments yet.</p> : null}
        </Panel>

        <Panel className="overflow-hidden">
          <div className="flex items-center justify-between border-b border-line/70 px-5 py-4">
            <SectionTitle eyebrow="Triage queue" title="Priority findings" />
            <Link to="/findings" className="font-mono text-[9px] uppercase tracking-wider text-cyan hover:text-white">
              All
            </Link>
          </div>
          <div className="divide-y divide-line/50">
            {data.top_findings.map((finding) => (
              <Link
                key={finding.id}
                to={`/findings?find=${finding.id}`}
                className="block px-5 py-3.5 transition hover:bg-cyan/[0.03]"
              >
                <div className="flex items-center justify-between gap-2">
                  <SeverityBadge severity={finding.severity} />
                  {finding.cvss_score !== null ? (
                    <span className="font-mono text-[9px] text-mist">CVSS {finding.cvss_score.toFixed(1)}</span>
                  ) : null}
                </div>
                <p className="mt-2 line-clamp-2 text-[11px] leading-relaxed text-ice">{finding.title}</p>
                <p className="mt-1.5 font-mono text-[8px] uppercase tracking-wider text-slate-600">
                  {moduleLabel(finding.module)} · {finding.cve_id || "no CVE"}
                </p>
              </Link>
            ))}
            {!data.top_findings.length ? <p className="py-10 text-center text-xs text-mist">No open findings.</p> : null}
          </div>
        </Panel>
      </div>

      <section>
        <div className="mb-3 flex items-end justify-between gap-3">
          <SectionTitle eyebrow="Module matrix" title="Ten scoped capabilities" />
          <Link to="/targets" className="flex items-center gap-1 font-mono text-[9px] uppercase tracking-wider text-cyan hover:text-white">
            <Target size={12} /> Scope register
          </Link>
        </div>
        <div className="grid gap-2.5 sm:grid-cols-2 lg:grid-cols-5">
          {Object.values(MODULE_META).map((module) => (
            <Link
              key={module.id}
              to={module.path}
              className="group relative overflow-hidden rounded-xl border border-line/70 bg-panel/70 p-3 transition hover:border-cyan/25 hover:shadow-glow-cyan"
            >
              <div
                className="absolute inset-x-0 top-0 h-px opacity-60"
                style={{ background: `linear-gradient(90deg, transparent, ${module.accent}, transparent)` }}
              />
              <div className="flex items-center justify-between">
                <span style={{ color: module.accent }}>
                  <Icon name={module.icon} size={17} />
                </span>
                <span className="font-mono text-[8px] text-slate-600">{module.number}</span>
              </div>
              <p className="mt-2.5 truncate text-[11px] font-medium text-ice transition group-hover:text-white">
                {module.name}
              </p>
              <p className="mt-1 line-clamp-2 text-[9px] leading-relaxed text-slate-600">{module.short}</p>
              <div className="mt-2 flex items-center gap-1 font-mono text-[8px] uppercase tracking-wider" style={{ color: module.accent }}>
                Launch <ArrowUpRight size={9} />
              </div>
            </Link>
          ))}
        </div>
      </section>

      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line/60 bg-abyss/40 px-4 py-3 font-mono text-[9px] uppercase tracking-wider text-slate-600">
        <span className="flex items-center gap-2">
          <Zap size={12} className="text-amber/70" /> Evidence hash chain active · rate limits enforced
        </span>
        <span className="flex items-center gap-2">
          <FileText size={12} /> Last sync {formatDate(new Date().toISOString())}
        </span>
      </div>

      <ModuleLauncher open={launcherOpen} onClose={() => setLauncherOpen(false)} />
    </div>
  );
}
