import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  ArrowUpRight,
  Braces,
  Calculator,
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  Crosshair,
  Eye,
  FileCode2,
  Flame,
  Info,
  KeyRound,
  Loader2,
  Lock,
  Play,
  Radar,
  Save,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
} from "lucide-react";
import { PageHeader } from "../../components/PageHeader";
import { Panel, SectionTitle, Toggle, ProgressBar } from "../../components/ui";
import { SeverityBadge, StatusBadge, RiskPill, DemoBadge } from "../../components/Badges";
import { Icon } from "../../components/Icon";
import { ImageWithFallback } from "../../components/ImageWithFallback";
import { NotFound } from "../NotFound";
import { api } from "../../lib/api";
import type { Assessment, PasswordAuditResult, Target } from "../../lib/types";
import { DEMO_AD_SNAPSHOT, DEMO_CLOUD_SNAPSHOT, MODULE_META, SCENARIOS } from "../../lib/constants";
import { useAuth } from "../../context/AuthContext";
import { useToast } from "../../context/ToastContext";
import { cn, formatDate, parseCommaList, parsePortList, timeAgo } from "../../lib/utils";

type Meta = (typeof MODULE_META)[string];

const MODULE_SAFETY: Record<string, string> = {
  recon: "Passive-first DNS and HTTP collection. No credential attacks, brute force, zone transfer or exploitation.",
  network: "TCP connect inventory only. Host, port and concurrency ceilings are enforced server-side; no vulnerability exploitation.",
  web: "Non-destructive OWASP baseline. Header, cookie, TLS and misconfiguration checks; injection probes are lab-gated and disabled by default.",
  vulnerability: "Metadata correlation against NVD and a bundled dated snapshot. ARES does not exploit or validate vulnerabilities on the target.",
  osint: "Public sources and authorized document metadata only. Documents are hashed for provenance; bytes are never retained.",
  password: "Analysis runs entirely in memory. Plaintext, hashes and wordlists are never persisted or returned in assessment records.",
  active_directory: "Read-only analysis of an exported configuration snapshot. No LDAP connection, credential use or domain controller contact.",
  cloud: "Read-only review of an exported configuration snapshot. Cloud credentials are never requested or stored.",
  api_security: "Bounded GET/OPTIONS probes on the authorized origin. No authorization bypass, fuzzing or destructive testing.",
  red_team: "Tabletop planning only. No technique execution, malware, credential theft or uncontrolled denial of service.",
};

const TARGET_TYPE_LABELS: Record<string, string> = {
  domain: "domain",
  ip: "IP address",
  cidr: "CIDR range",
  url: "URL",
  api: "API origin",
  cloud_account: "cloud account",
  ad_config: "AD snapshot",
  password_policy: "password policy",
  local: "local workspace",
};

function defaultConfig(moduleId: string): Record<string, any> {
  switch (moduleId) {
    case "recon":
      return {
        include_subdomains: true,
        include_whois: true,
        include_tls: true,
        include_http: true,
        max_subdomains: 30,
        extra_subdomains: "",
        timeout: 6,
      };
    case "network":
      return {
        ports:
          "21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017",
        engine: "tcp",
        timeout: 2,
        max_hosts: 16,
        concurrency: 100,
        service_banners: true,
      };
    case "web":
      return {
        include_tls: true,
        include_headers: true,
        include_misconfig: true,
        reflection_probe: false,
        sqli_probe: false,
        timeout: 8,
      };
    case "vulnerability":
      return {
        keywords: "log4j, spring",
        cve_ids: "",
        min_cvss: 0,
        max_results: 20,
        include_live_nvd: true,
        include_bundled_snapshot: true,
      };
    case "osint":
      return {
        include_crtsh: true,
        include_whois: true,
        include_dns: true,
        document_url: "",
        timeout: 10,
      };
    case "password":
      return {
        policy: {
          min_length: 12,
          require_uppercase: true,
          require_lowercase: true,
          require_digit: true,
          require_symbol: true,
          max_reuse: 5,
          lockout_after: 5,
          lockout_minutes: 15,
          mfa_required: true,
        },
        test_passwords: "",
        hashes: "",
        hash_algorithm: "auto",
        wordlist: "password\nwelcome\nletmein\nadmin\nchangeme\nqwerty",
      };
    case "active_directory":
      return {
        snapshot_text: JSON.stringify(DEMO_AD_SNAPSHOT, null, 2),
        domain_name: String(DEMO_AD_SNAPSHOT.domain_name),
      };
    case "cloud":
      return {
        provider: "aws",
        snapshot_text: JSON.stringify(DEMO_CLOUD_SNAPSHOT, null, 2),
      };
    case "api_security":
      return {
        endpoints: "/v1/users\n/v1/orders\n/health",
        include_auth_checks: true,
        include_cors_check: true,
        include_rate_limit_check: true,
        timeout: 7,
      };
    case "red_team":
      return {
        scenario: "discovery",
        technique_ids: "T1046, T1087, T1082",
        objective: "Validate detection coverage for a controlled tabletop exercise.",
      };
    default:
      return {};
  }
}

function newlineList(value: string, trim = true): string[] {
  return value
    .split("\n")
    .map((line) => {
      const cleaned = line.replace(/\r$/, "");
      return trim ? cleaned.trim() : cleaned;
    })
    .filter((line) => (trim ? line.length > 0 : line.length >= 0 && line !== ""));
}

function parseJsonObject(value: string, label: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch (reason) {
    throw new Error(`${label} is not valid JSON: ${reason instanceof Error ? reason.message : "parse error"}`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${label} must be a JSON object.`);
  }
  return parsed as Record<string, unknown>;
}

function buildConfig(moduleId: string, config: Record<string, any>): Record<string, unknown> {
  switch (moduleId) {
    case "recon":
      return {
        include_subdomains: Boolean(config.include_subdomains),
        include_whois: Boolean(config.include_whois),
        include_tls: Boolean(config.include_tls),
        include_http: Boolean(config.include_http),
        max_subdomains: Number(config.max_subdomains),
        extra_subdomains: parseCommaList(String(config.extra_subdomains || "")),
        timeout: Number(config.timeout),
      };
    case "network": {
      const ports = parsePortList(String(config.ports || ""));
      if (!ports.length) throw new Error("Provide at least one valid port or port range.");
      if (ports.length > 512) throw new Error("A single scan is limited to 512 ports.");
      return {
        ports,
        engine: config.engine,
        timeout: Number(config.timeout),
        max_hosts: Number(config.max_hosts),
        concurrency: Number(config.concurrency),
        service_banners: Boolean(config.service_banners),
      };
    }
    case "web":
      return {
        include_tls: Boolean(config.include_tls),
        include_headers: Boolean(config.include_headers),
        include_misconfig: Boolean(config.include_misconfig),
        reflection_probe: Boolean(config.reflection_probe),
        sqli_probe: Boolean(config.sqli_probe),
        timeout: Number(config.timeout),
      };
    case "vulnerability": {
      const keywords = parseCommaList(String(config.keywords || ""));
      const cve_ids = parseCommaList(String(config.cve_ids || "")).map((value) => value.toUpperCase());
      if (!keywords.length && !cve_ids.length) throw new Error("Provide at least one product keyword or CVE identifier.");
      return {
        keywords,
        cve_ids,
        min_cvss: Number(config.min_cvss),
        max_results: Number(config.max_results),
        include_live_nvd: Boolean(config.include_live_nvd),
        include_bundled_snapshot: Boolean(config.include_bundled_snapshot),
      };
    }
    case "osint":
      return {
        include_crtsh: Boolean(config.include_crtsh),
        include_whois: Boolean(config.include_whois),
        include_dns: Boolean(config.include_dns),
        document_url: String(config.document_url || "").trim() || null,
        timeout: Number(config.timeout),
      };
    case "active_directory":
      return {
        snapshot: parseJsonObject(String(config.snapshot_text || ""), "AD snapshot"),
        domain_name: String(config.domain_name || "").trim(),
      };
    case "cloud":
      return {
        provider: config.provider,
        snapshot: parseJsonObject(String(config.snapshot_text || ""), "Cloud snapshot"),
      };
    case "api_security": {
      const endpoints = newlineList(String(config.endpoints || "")).map((endpoint) => endpoint.trim()).filter(Boolean);
      return {
        endpoints,
        include_auth_checks: Boolean(config.include_auth_checks),
        include_cors_check: Boolean(config.include_cors_check),
        include_rate_limit_check: Boolean(config.include_rate_limit_check),
        timeout: Number(config.timeout),
      };
    }
    case "red_team":
      return {
        scenario: config.scenario,
        technique_ids: parseCommaList(String(config.technique_ids || "")).map((value) => value.toUpperCase()),
        objective: String(config.objective || "").trim(),
      };
    default:
      return {};
  }
}

function NumberField({
  id,
  label,
  value,
  onChange,
  min,
  max,
  step = 1,
  hint,
}: {
  id: string;
  label: string;
  value: number;
  onChange: (value: number) => void;
  min?: number;
  max?: number;
  step?: number;
  hint?: string;
}) {
  return (
    <div>
      <label className="label" htmlFor={id}>
        {label}
      </label>
      <input
        id={id}
        type="number"
        className="input-mono"
        value={Number.isFinite(value) ? value : 0}
        min={min}
        max={max}
        step={step}
        onChange={(event) => onChange(Number(event.target.value))}
      />
      {hint ? <p className="mt-1 font-mono text-[8px] uppercase tracking-wider text-slate-600">{hint}</p> : null}
    </div>
  );
}

function TargetPicker({
  targets,
  targetId,
  onChange,
  action,
  meta,
}: {
  targets: Target[];
  targetId: string;
  onChange: (value: string) => void;
  action: string;
  meta: Meta;
}) {
  const selected = targets.find((target) => target.id === targetId);
  return (
    <div className="rounded-xl border border-line/70 bg-abyss/40 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="font-mono text-[9px] uppercase tracking-[0.18em] text-cyan">Authorized target</p>
        <Link to="/targets" className="inline-flex items-center gap-1 font-mono text-[8px] uppercase tracking-wider text-mist transition hover:text-cyan">
          Manage scope <ArrowUpRight size={10} />
        </Link>
      </div>
      {targets.length ? (
        <>
          <select value={targetId} onChange={(event) => onChange(event.target.value)} className="input mt-2">
            {targets.map((target) => (
              <option key={target.id} value={target.id}>
                {target.name} · {target.value}
              </option>
            ))}
          </select>
          {selected ? (
            <div className="mt-2.5 flex flex-wrap items-center gap-2 font-mono text-[8px] uppercase tracking-wider text-slate-600">
              <span className="chip">{selected.target_type}</span>
              <span className="chip">{selected.environment}</span>
              <span className="chip border-neon/20 text-neon">
                <ShieldCheck size={9} /> verified
              </span>
              {selected.authorization_expires ? <span>expires {formatDate(selected.authorization_expires, false)}</span> : null}
            </div>
          ) : null}
          <p className="mt-2 flex items-center gap-1.5 text-[9px] text-mist">
            <Lock size={10} className="text-cyan/70" /> Action allowlisted: <span className="font-mono text-cyan">{action.replace(/_/g, " ")}</span>
          </p>
        </>
      ) : (
        <div className="mt-2 rounded-lg border border-amber/20 bg-amber/[0.04] p-3">
          <p className="flex items-start gap-2 text-[10px] leading-relaxed text-mist">
            <CircleAlert size={13} className="mt-0.5 shrink-0 text-amber" />
            No verified target allows <span className="font-mono text-amber">{action.replace(/_/g, " ")}</span> for{" "}
            {meta.target_types.map((type) => TARGET_TYPE_LABELS[type] || type).join(" / ")}.
          </p>
          <Link to="/targets" className="btn-ghost btn-sm mt-2 w-full">
            <Crosshair size={12} /> Open scope register
          </Link>
        </div>
      )}
    </div>
  );
}

function ModuleForm({ meta, config, setConfig }: { meta: Meta; config: Record<string, any>; setConfig: (value: Record<string, any>) => void }) {
  const update = (key: string, value: any) => setConfig({ ...config, [key]: value });
  const policy = (config.policy || {}) as Record<string, any>;
  const setPolicy = (key: string, value: any) => setConfig({ ...config, policy: { ...policy, [key]: value } });

  switch (meta.id) {
    case "recon":
      return (
        <div className="space-y-4">
          <div className="grid gap-2 sm:grid-cols-2">
            <Toggle checked={Boolean(config.include_subdomains)} onChange={(value) => update("include_subdomains", value)} label="Subdomain inventory" description="Resolve likely hostnames and CT-derived labels." />
            <Toggle checked={Boolean(config.include_whois)} onChange={(value) => update("include_whois", value)} label="WHOIS metadata" description="Registration and registrar context." />
            <Toggle checked={Boolean(config.include_tls)} onChange={(value) => update("include_tls", value)} label="TLS certificate review" description="Issuer, validity and certificate metadata." />
            <Toggle checked={Boolean(config.include_http)} onChange={(value) => update("include_http", value)} label="HTTP fingerprint" description="Safe response and technology metadata." />
          </div>
          <div className="grid gap-4 sm:grid-cols-3">
            <NumberField id="recon-max-subdomains" label="Max subdomains" value={Number(config.max_subdomains)} onChange={(value) => update("max_subdomains", value)} min={0} max={80} hint="0–80" />
            <NumberField id="recon-timeout" label="Timeout (s)" value={Number(config.timeout)} onChange={(value) => update("timeout", value)} min={2} max={15} step={0.5} hint="2–15" />
            <div className="sm:col-span-1" />
          </div>
          <div>
            <label className="label" htmlFor="recon-extra">
              Extra subdomain labels
            </label>
            <input
              id="recon-extra"
              className="input-mono"
              value={config.extra_subdomains}
              onChange={(event) => update("extra_subdomains", event.target.value)}
              placeholder="api, staging, dev"
            />
            <p className="mt-1 font-mono text-[8px] uppercase tracking-wider text-slate-600">Comma-separated labels, resolved beneath the authorized domain.</p>
          </div>
        </div>
      );

    case "network":
      return (
        <div className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label className="label" htmlFor="network-ports">
                Ports / ranges
              </label>
              <input
                id="network-ports"
                className="input-mono"
                value={config.ports}
                onChange={(event) => update("ports", event.target.value)}
              />
              <p className="mt-1 font-mono text-[8px] uppercase tracking-wider text-slate-600">Comma-separated; ranges allowed. Hard cap 512 ports.</p>
            </div>
            <div>
              <label className="label" htmlFor="network-engine">
                Scanner engine
              </label>
              <select id="network-engine" className="input" value={config.engine} onChange={(event) => update("engine", event.target.value)}>
                <option value="tcp">Bounded TCP connect</option>
                <option value="nmap">Nmap XML (lab)</option>
              </select>
              <p className="mt-1 font-mono text-[8px] uppercase tracking-wider text-slate-600">Nmap ingestion is restricted to lab-authorized ranges.</p>
            </div>
          </div>
          <div className="grid gap-4 sm:grid-cols-4">
            <NumberField id="network-hosts" label="Max hosts" value={Number(config.max_hosts)} onChange={(value) => update("max_hosts", value)} min={1} max={256} hint="1–256" />
            <NumberField id="network-concurrency" label="Concurrency" value={Number(config.concurrency)} onChange={(value) => update("concurrency", value)} min={1} max={300} hint="1–300" />
            <NumberField id="network-timeout" label="Timeout (s)" value={Number(config.timeout)} onChange={(value) => update("timeout", value)} min={0.4} max={10} step={0.2} hint="0.4–10" />
            <div className="flex items-end pb-1">
              <Toggle checked={Boolean(config.service_banners)} onChange={(value) => update("service_banners", value)} label="Service banners" description="Read safe protocol banners." />
            </div>
          </div>
          <div className="flex items-start gap-2 rounded-lg border border-line/70 bg-abyss/40 p-3 text-[10px] leading-relaxed text-mist">
            <Info size={13} className="mt-0.5 shrink-0 text-cyan" />
            Scanner ceilings are enforced server-side. The target must be an IP address or CIDR range, not a public hostname.
          </div>
        </div>
      );

    case "web":
      return (
        <div className="space-y-4">
          <div className="grid gap-2 sm:grid-cols-2">
            <Toggle checked={Boolean(config.include_tls)} onChange={(value) => update("include_tls", value)} label="TLS configuration" description="Protocol, cipher and certificate review." />
            <Toggle checked={Boolean(config.include_headers)} onChange={(value) => update("include_headers", value)} label="Security headers" description="CSP, HSTS, frame controls and more." />
            <Toggle checked={Boolean(config.include_misconfig)} onChange={(value) => update("include_misconfig", value)} label="Misconfiguration checks" description="Exposed files and cookie flags." />
            <Toggle checked={Boolean(config.reflection_probe)} onChange={(value) => update("reflection_probe", value)} label="Safe reflection probe" description="Observe whether benign markers are reflected." />
          </div>
          <div className="rounded-xl border border-crimson/25 bg-crimson/[0.035] p-3">
            <Toggle
              checked={Boolean(config.sqli_probe)}
              onChange={(value) => update("sqli_probe", value)}
              label="Injection probe (lab only)"
              description="Disabled by default. This does not exploit data extraction, but must only be used in an isolated, explicitly authorized lab."
            />
            {config.sqli_probe ? (
              <p className="mt-1 flex items-start gap-2 text-[9px] uppercase tracking-wider text-crimson">
                <ShieldAlert size={11} className="mt-0.5 shrink-0" /> Injection probing enabled — confirm lab authorization before execution.
              </p>
            ) : null}
          </div>
          <NumberField id="web-timeout" label="Request timeout (s)" value={Number(config.timeout)} onChange={(value) => update("timeout", value)} min={2} max={20} step={0.5} hint="2–20 seconds" />
        </div>
      );

    case "vulnerability":
      return (
        <div className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label className="label" htmlFor="vuln-keywords">
                Product keywords
              </label>
              <input
                id="vuln-keywords"
                className="input"
                value={config.keywords}
                onChange={(event) => update("keywords", event.target.value)}
                placeholder="log4j, spring, nginx"
              />
              <p className="mt-1 font-mono text-[8px] uppercase tracking-wider text-slate-600">Max 5 keywords</p>
            </div>
            <div>
              <label className="label" htmlFor="vuln-cves">
                CVE identifiers
              </label>
              <input
                id="vuln-cves"
                className="input-mono"
                value={config.cve_ids}
                onChange={(event) => update("cve_ids", event.target.value)}
                placeholder="CVE-2021-44228, CVE-2022-22965"
              />
              <p className="mt-1 font-mono text-[8px] uppercase tracking-wider text-slate-600">Max 10 exact identifiers</p>
            </div>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <NumberField id="vuln-min-cvss" label="Minimum CVSS" value={Number(config.min_cvss)} onChange={(value) => update("min_cvss", value)} min={0} max={10} step={0.1} hint="0.0 – 10.0" />
            <NumberField id="vuln-max-results" label="Maximum results" value={Number(config.max_results)} onChange={(value) => update("max_results", value)} min={1} max={50} hint="1–50" />
          </div>
          <div className="grid gap-2 sm:grid-cols-2">
            <Toggle checked={Boolean(config.include_live_nvd)} onChange={(value) => update("include_live_nvd", value)} label="Live NVD API" description="Query NVD when egress is available." />
            <Toggle checked={Boolean(config.include_bundled_snapshot)} onChange={(value) => update("include_bundled_snapshot", value)} label="Bundled snapshot" description="Dated offline dataset for resilience." />
          </div>
          <p className="flex items-start gap-2 rounded-lg border border-line/70 bg-abyss/40 p-3 text-[10px] leading-relaxed text-mist">
            <Flame size={13} className="mt-0.5 shrink-0 text-crimson" />
            Results are intelligence matches, not exploit validation. Confirm applicability against the target inventory before assigning remediation.
          </p>
        </div>
      );

    case "osint":
      return (
        <div className="space-y-4">
          <div className="grid gap-2 sm:grid-cols-3">
            <Toggle checked={Boolean(config.include_crtsh)} onChange={(value) => update("include_crtsh", value)} label="Certificate transparency" description="Public CT log names." />
            <Toggle checked={Boolean(config.include_whois)} onChange={(value) => update("include_whois", value)} label="WHOIS" description="Public registration metadata." />
            <Toggle checked={Boolean(config.include_dns)} onChange={(value) => update("include_dns", value)} label="DNS inventory" description="Public DNS record types." />
          </div>
          <div>
            <label className="label" htmlFor="osint-document">
              Authorized public document URL <span className="normal-case tracking-normal text-slate-600">(optional)</span>
            </label>
            <input
              id="osint-document"
              className="input-mono"
              value={config.document_url}
              onChange={(event) => update("document_url", event.target.value)}
              placeholder="https://example.com/public-report.pdf"
            />
            <p className="mt-1 font-mono text-[8px] uppercase tracking-wider text-slate-600">Metadata only — bytes are never retained.</p>
          </div>
          <NumberField id="osint-timeout" label="Timeout (s)" value={Number(config.timeout)} onChange={(value) => update("timeout", value)} min={3} max={25} step={1} hint="3–25 seconds" />
          <div className="flex items-start gap-2 rounded-lg border border-cyan/15 bg-cyan/[0.03] p-3 text-[10px] leading-relaxed text-mist">
            <Radar size={13} className="mt-0.5 shrink-0 text-cyan" />
            All collection is passive. The target must be an authorized public domain; no internal discovery or credential collection is performed.
          </div>
        </div>
      );

    case "password":
      return (
        <div className="space-y-5">
          <div className="flex items-start gap-2 rounded-lg border border-neon/20 bg-neon/[0.035] p-3 text-[10px] leading-relaxed text-mist">
            <Lock size={13} className="mt-0.5 shrink-0 text-neon" />
            Processed in memory only. ARES never persists or returns plaintext, password hashes or wordlist entries. Only aggregate
            results and policy findings are written to the assessment record.
          </div>
          <div>
            <p className="label">Password policy profile</p>
            <div className="grid gap-3 rounded-xl border border-line/70 bg-abyss/40 p-3 sm:grid-cols-2 lg:grid-cols-4">
              <NumberField id="policy-min" label="Min length" value={Number(policy.min_length)} onChange={(value) => setPolicy("min_length", value)} min={1} max={128} />
              <NumberField id="policy-reuse" label="Max reuse" value={Number(policy.max_reuse)} onChange={(value) => setPolicy("max_reuse", value)} min={0} max={50} />
              <NumberField id="policy-lockout" label="Lockout after" value={Number(policy.lockout_after)} onChange={(value) => setPolicy("lockout_after", value)} min={0} max={100} />
              <NumberField id="policy-lockout-min" label="Lockout (min)" value={Number(policy.lockout_minutes)} onChange={(value) => setPolicy("lockout_minutes", value)} min={1} max={1440} />
            </div>
            <div className="mt-2 grid gap-1 sm:grid-cols-2 lg:grid-cols-3">
              <Toggle checked={Boolean(policy.require_uppercase)} onChange={(value) => setPolicy("require_uppercase", value)} label="Require uppercase" />
              <Toggle checked={Boolean(policy.require_lowercase)} onChange={(value) => setPolicy("require_lowercase", value)} label="Require lowercase" />
              <Toggle checked={Boolean(policy.require_digit)} onChange={(value) => setPolicy("require_digit", value)} label="Require number" />
              <Toggle checked={Boolean(policy.require_symbol)} onChange={(value) => setPolicy("require_symbol", value)} label="Require symbol" />
              <Toggle checked={Boolean(policy.mfa_required)} onChange={(value) => setPolicy("mfa_required", value)} label="MFA required" />
            </div>
          </div>
          <div>
            <label className="label" htmlFor="password-tests">
              Test passwords <span className="normal-case tracking-normal text-slate-600">(one per line, never stored)</span>
            </label>
            <textarea
              id="password-tests"
              className="input-mono min-h-24"
              value={config.test_passwords}
              onChange={(event) => update("test_passwords", event.target.value)}
              placeholder={"Summer2026!\ncorrect-horse-battery-staple"}
              spellCheck={false}
              autoComplete="off"
            />
            <p className="mt-1 font-mono text-[8px] uppercase tracking-wider text-slate-600">Maximum 20 entries · 256 characters each</p>
          </div>
          <div className="grid gap-4 sm:grid-cols-[1fr_150px]">
            <div>
              <label className="label" htmlFor="password-hashes">
                Hashes for offline dictionary audit
              </label>
              <textarea
                id="password-hashes"
                className="input-mono min-h-24"
                value={config.hashes}
                onChange={(event) => update("hashes", event.target.value)}
                placeholder="Paste hashes, one per line"
                spellCheck={false}
                autoComplete="off"
              />
              <p className="mt-1 font-mono text-[8px] uppercase tracking-wider text-slate-600">Maximum 100 entries. No plaintext is derived from unsupported formats.</p>
            </div>
            <div>
              <label className="label" htmlFor="hash-algorithm">
                Hash algorithm
              </label>
              <select id="hash-algorithm" className="input" value={config.hash_algorithm} onChange={(event) => update("hash_algorithm", event.target.value)}>
                {["auto", "md5", "sha1", "sha256", "bcrypt", "argon2"].map((algorithm) => (
                  <option key={algorithm} value={algorithm}>
                    {algorithm}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div>
            <label className="label" htmlFor="password-wordlist">
              Local dictionary <span className="normal-case tracking-normal text-slate-600">(optional, one per line)</span>
            </label>
            <textarea
              id="password-wordlist"
              className="input-mono min-h-24"
              value={config.wordlist}
              onChange={(event) => update("wordlist", event.target.value)}
              spellCheck={false}
              autoComplete="off"
            />
            <p className="mt-1 font-mono text-[8px] uppercase tracking-wider text-slate-600">Max 2,000 entries · used only in memory</p>
          </div>
        </div>
      );

    case "active_directory":
      return (
        <div className="space-y-4">
          <div>
            <label className="label" htmlFor="ad-domain">
              Domain name
            </label>
            <input
              id="ad-domain"
              className="input-mono"
              value={config.domain_name}
              onChange={(event) => update("domain_name", event.target.value)}
              placeholder="corp.example.com"
            />
          </div>
          <div>
            <div className="flex items-center justify-between">
              <label className="label" htmlFor="ad-snapshot">
                Read-only AD configuration snapshot (JSON)
              </label>
              <button
                type="button"
                className="mb-1.5 inline-flex items-center gap-1 font-mono text-[8px] uppercase tracking-wider text-cyan hover:text-white"
                onClick={() => {
                  update("snapshot_text", JSON.stringify(DEMO_AD_SNAPSHOT, null, 2));
                  update("domain_name", String(DEMO_AD_SNAPSHOT.domain_name));
                }}
              >
                <Sparkles size={10} /> load demo snapshot
              </button>
            </div>
            <textarea
              id="ad-snapshot"
              className="input-mono min-h-72"
              value={config.snapshot_text}
              onChange={(event) => update("snapshot_text", event.target.value)}
              spellCheck={false}
            />
            <div className="mt-1 flex items-center justify-between font-mono text-[8px] uppercase tracking-wider text-slate-600">
              <span>Maximum 400 KB · no live LDAP connection</span>
              <span>{new Blob([String(config.snapshot_text)]).size.toLocaleString()} bytes</span>
            </div>
          </div>
          <div className="flex items-start gap-2 rounded-lg border border-violet/20 bg-violet/[0.04] p-3 text-[10px] leading-relaxed text-mist">
            <FileCode2 size={13} className="mt-0.5 shrink-0 text-violet" />
            Use a sanitized export from your directory documentation. Never include credentials, password hashes or
            session material in the snapshot.
          </div>
        </div>
      );

    case "cloud":
      return (
        <div className="space-y-4">
          <div>
            <label className="label" htmlFor="cloud-provider">
              Cloud provider
            </label>
            <select id="cloud-provider" className="input" value={config.provider} onChange={(event) => update("provider", event.target.value)}>
              <option value="aws">Amazon Web Services</option>
              <option value="azure">Microsoft Azure</option>
              <option value="gcp">Google Cloud Platform</option>
            </select>
          </div>
          <div>
            <div className="flex items-center justify-between">
              <label className="label" htmlFor="cloud-snapshot">
                Read-only configuration snapshot (JSON)
              </label>
              <button
                type="button"
                className="mb-1.5 inline-flex items-center gap-1 font-mono text-[8px] uppercase tracking-wider text-cyan hover:text-white"
                onClick={() => update("snapshot_text", JSON.stringify(DEMO_CLOUD_SNAPSHOT, null, 2))}
              >
                <Sparkles size={10} /> load demo snapshot
              </button>
            </div>
            <textarea
              id="cloud-snapshot"
              className="input-mono min-h-72"
              value={config.snapshot_text}
              onChange={(event) => update("snapshot_text", event.target.value)}
              spellCheck={false}
            />
            <div className="mt-1 flex items-center justify-between font-mono text-[8px] uppercase tracking-wider text-slate-600">
              <span>Maximum 400 KB · no cloud API credentials requested</span>
              <span>{new Blob([String(config.snapshot_text)]).size.toLocaleString()} bytes</span>
            </div>
          </div>
          <div className="flex items-start gap-2 rounded-lg border border-cyan/15 bg-cyan/[0.03] p-3 text-[10px] leading-relaxed text-mist">
            <Braces size={13} className="mt-0.5 shrink-0 text-cyan" />
            Provide an export of storage, identity, logging and network configuration. Redact account IDs, secrets
            and access keys before submission.
          </div>
        </div>
      );

    case "api_security":
      return (
        <div className="space-y-4">
          <div>
            <label className="label" htmlFor="api-endpoints">
              Endpoint paths
            </label>
            <textarea
              id="api-endpoints"
              className="input-mono min-h-28"
              value={config.endpoints}
              onChange={(event) => update("endpoints", event.target.value)}
              placeholder={"/v1/users\n/v1/orders\n/health"}
            />
            <p className="mt-1 font-mono text-[8px] uppercase tracking-wider text-slate-600">
              One per line. Paths only — the authorized origin is the target. Max 25 endpoints.
            </p>
          </div>
          <div className="grid gap-2 sm:grid-cols-3">
            <Toggle checked={Boolean(config.include_auth_checks)} onChange={(value) => update("include_auth_checks", value)} label="Anonymous exposure" description="Observe unauthenticated responses." />
            <Toggle checked={Boolean(config.include_cors_check)} onChange={(value) => update("include_cors_check", value)} label="CORS policy" description="OPTIONS preflight review." />
            <Toggle checked={Boolean(config.include_rate_limit_check)} onChange={(value) => update("include_rate_limit_check", value)} label="Rate-limit evidence" description="Limited, spaced requests." />
          </div>
          <NumberField id="api-timeout" label="Request timeout (s)" value={Number(config.timeout)} onChange={(value) => update("timeout", value)} min={2} max={20} step={0.5} hint="2–20 seconds" />
          <div className="flex items-start gap-2 rounded-lg border border-line/70 bg-abyss/40 p-3 text-[10px] leading-relaxed text-mist">
            <ShieldAlert size={13} className="mt-0.5 shrink-0 text-amber" />
            No authorization bypass, token theft, fuzzing or injection is attempted. Rate-limit testing is deliberately
            limited and does not constitute denial-of-service behavior.
          </div>
        </div>
      );

    case "red_team":
      return (
        <div className="space-y-4">
          <div className="flex items-start gap-2 rounded-lg border border-crimson/25 bg-crimson/[0.04] p-3 text-[10px] leading-relaxed text-mist">
            <ShieldAlert size={13} className="mt-0.5 shrink-0 text-crimson" />
            <span>
              <span className="font-medium text-crimson">Tabletop only.</span> ARES maps techniques to detection
              requirements and plans a discussion exercise. It does not execute commands, deploy payloads, steal
              credentials or generate adversary traffic.
            </span>
          </div>
          <div>
            <label className="label" htmlFor="red-scenario">
              Exercise scenario
            </label>
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {SCENARIOS.map((scenario) => (
                <button
                  key={scenario.id}
                  type="button"
                  onClick={() => update("scenario", scenario.id)}
                  className={cn(
                    "rounded-xl border p-3 text-left transition",
                    config.scenario === scenario.id
                      ? "border-crimson/40 bg-crimson/[0.06]"
                      : "border-line/70 bg-abyss/40 hover:border-white/15",
                  )}
                >
                  <p className={cn("text-[11px] font-medium", config.scenario === scenario.id ? "text-white" : "text-ice")}>
                    {scenario.name}
                  </p>
                  <p className="mt-1 text-[9px] leading-relaxed text-mist">{scenario.detail}</p>
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="label" htmlFor="red-techniques">
              Technique IDs
            </label>
            <input
              id="red-techniques"
              className="input-mono"
              value={config.technique_ids}
              onChange={(event) => update("technique_ids", event.target.value)}
              placeholder="T1046, T1087, T1082"
            />
            <p className="mt-1 font-mono text-[8px] uppercase tracking-wider text-slate-600">Comma-separated · max 20 · validated against ATT&CK format</p>
          </div>
          <div>
            <label className="label" htmlFor="red-objective">
              Exercise objective
            </label>
            <textarea
              id="red-objective"
              className="input min-h-20"
              value={config.objective}
              onChange={(event) => update("objective", event.target.value)}
              maxLength={500}
            />
            <p className="mt-1 text-right font-mono text-[8px] text-slate-600">{String(config.objective).length}/500</p>
          </div>
        </div>
      );

    default:
      return <p className="text-xs text-mist">No configuration form is registered for this module.</p>;
  }
}

function PasswordResults({ result }: { result: PasswordAuditResult }) {
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-neon/20 bg-neon/[0.04] p-4">
        <div>
          <p className="font-mono text-[9px] uppercase tracking-[0.18em] text-neon">In-memory audit complete</p>
          <p className="mt-1 text-sm font-medium text-white">{result.assessment.name}</p>
          <p className="mt-1 text-[10px] text-mist">Inputs were discarded after analysis. Only aggregate results were stored.</p>
        </div>
        <div className="flex items-center gap-2">
          <RiskPill score={result.assessment.risk_score} />
          <Link to={`/assessments/${result.assessment.id}`} className="btn-ghost btn-sm">
            Open assessment <ChevronRight size={12} />
          </Link>
        </div>
      </div>

      <Panel className="p-5">
        <SectionTitle eyebrow="Strength analysis" title={`${result.strength.length} password${result.strength.length === 1 ? "" : "s"} evaluated`} />
        {result.strength.length ? (
          <div className="mt-4 grid gap-3 md:grid-cols-2">
            {result.strength.map((entry, index) => (
              <div key={index} className="rounded-xl border border-line/70 bg-abyss/40 p-3">
                <div className="flex items-center justify-between gap-2">
                  <p className="font-mono text-[9px] uppercase tracking-wider text-slate-600">Sample {String(index + 1).padStart(2, "0")}</p>
                  <span className="chip">{entry.label}</span>
                </div>
                <div className="mt-2 flex items-end justify-between">
                  <p className="text-[11px] text-ice">{entry.label_name}</p>
                  <p className="font-mono text-lg text-white">{entry.score}/4</p>
                </div>
                <div className="mt-2">
                  <ProgressBar value={(entry.score / 4) * 100} color={entry.score >= 3 ? "#00FF88" : entry.score >= 2 ? "#FFB020" : "#FF3B5C"} height={4} />
                </div>
                <div className="mt-2 grid grid-cols-3 gap-1 font-mono text-[8px] uppercase tracking-wider text-slate-600">
                  <span>{entry.length} chars</span>
                  <span>{entry.character_classes} classes</span>
                  <span>{entry.entropy_bits.toFixed(1)} bits</span>
                </div>
                <p className="mt-1 text-[9px] text-mist">{entry.estimated_offline_time}</p>
                {entry.feedback.length ? (
                  <ul className="mt-1.5 space-y-0.5">
                    {entry.feedback.map((item) => (
                      <li key={item} className="text-[9px] leading-relaxed text-amber/80">• {item}</li>
                    ))}
                  </ul>
                ) : null}
              </div>
            ))}
          </div>
        ) : (
          <p className="mt-3 rounded-lg border border-line/60 bg-abyss/40 p-4 text-center text-[11px] text-mist">
            No plaintext samples were submitted. Policy findings still apply.
          </p>
        )}
      </Panel>

      <Panel className="p-5">
        <SectionTitle eyebrow="Offline hash audit" title="Hash hygiene" />
        <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {[
            { label: "Hashes audited", value: result.hash_audit.hashes_audited ?? 0 },
            { label: "Dictionary matches", value: result.hash_audit.match_count ?? 0 },
            { label: "Unsupported", value: result.hash_audit.unsupported_indices?.length ?? 0 },
            { label: "Dictionary size", value: result.hash_audit.dictionary_size ?? 0 },
          ].map((stat) => (
            <div key={stat.label} className="rounded-xl border border-line/70 bg-abyss/40 p-3">
              <p className="font-mono text-[8px] uppercase tracking-wider text-slate-600">{stat.label}</p>
              <p className="mt-1 font-mono text-xl text-ice">{stat.value}</p>
            </div>
          ))}
        </div>
        {result.hash_audit.match_count ? (
          <div className="mt-3 space-y-1.5">
            {result.hash_audit.matched_hashes?.map((match) => (
              <div key={match.index} className="flex items-center justify-between rounded-lg border border-crimson/20 bg-crimson/[0.04] px-3 py-2">
                <span className="font-mono text-[9px] text-ice">Hash #{match.index + 1} · {match.algorithm}</span>
                <span className="chip border-crimson/25 text-crimson">dictionary match</span>
              </div>
            ))}
          </div>
        ) : null}
        <p className="mt-3 flex items-start gap-2 rounded-lg border border-line/70 bg-abyss/40 p-3 text-[10px] leading-relaxed text-mist">
          <KeyRound size={13} className="mt-0.5 shrink-0 text-amber" />
          {result.hash_audit.notice || "Plaintext is never returned. Unsupported hash formats are reported without attempting recovery."}
        </p>
      </Panel>

      <Panel className="p-5">
        <SectionTitle eyebrow="Policy posture" title={`${result.policy_findings.length} policy finding${result.policy_findings.length === 1 ? "" : "s"}`} />
        <div className="mt-3 space-y-2">
          {result.policy_findings.map((finding) => (
            <div key={finding.key} className="rounded-xl border border-line/70 bg-abyss/40 p-3">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={finding.severity} />
                <p className="text-[11px] font-medium text-ice">{finding.title}</p>
                {finding.cvss_score ? <span className="ml-auto font-mono text-[9px] text-mist">CVSS {finding.cvss_score.toFixed(1)}</span> : null}
              </div>
              <p className="mt-1.5 text-[10px] leading-relaxed text-mist">{finding.description}</p>
              <p className="mt-1 text-[10px] leading-relaxed text-neon/80">{finding.remediation}</p>
            </div>
          ))}
          {!result.policy_findings.length ? <p className="py-4 text-center text-[11px] text-neon">No policy weaknesses detected against the supplied profile.</p> : null}
        </div>
      </Panel>
    </div>
  );
}

export function ModulePage() {
  const { moduleId } = useParams<{ moduleId: string }>();
  const meta = moduleId ? MODULE_META[moduleId] : undefined;
  if (!meta) return <NotFound />;
  return <ModuleWorkspace key={meta.id} meta={meta} />;
}

function ModuleWorkspace({ meta }: { meta: Meta }) {
  const { user } = useAuth();
  const { notify } = useToast();
  const navigate = useNavigate();
  const [targets, setTargets] = useState<Target[]>([]);
  const [targetId, setTargetId] = useState("");
  const [config, setConfig] = useState<Record<string, any>>(() => defaultConfig(meta.id));
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [recent, setRecent] = useState<Assessment[]>([]);
  const [cvssVector, setCvssVector] = useState("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  const [cvssResult, setCvssResult] = useState<{ score: number; severity: string; vector: string } | null>(null);
  const [cvssBusy, setCvssBusy] = useState(false);
  const [passwordResult, setPasswordResult] = useState<PasswordAuditResult | null>(null);
  const [targetsLoading, setTargetsLoading] = useState(true);

  const canOperate = user?.role === "admin" || user?.role === "analyst";
  const compatibleTargets = useMemo(
    () =>
      targets.filter(
        (target) => meta.target_types.includes(target.target_type) && target.allowed_actions.includes(meta.action),
      ),
    [targets, meta],
  );
  const selectedTarget = compatibleTargets.find((target) => target.id === targetId) || null;

  useEffect(() => {
    setTargetsLoading(true);
    api.targets
      .list({ status: "verified", limit: 100 })
      .then((response) => setTargets(response.items))
      .catch((reason) => notify({ title: "Could not load targets", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" }))
      .finally(() => setTargetsLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!compatibleTargets.length) {
      if (targetId) setTargetId("");
      return;
    }
    if (!compatibleTargets.some((target) => target.id === targetId)) {
      setTargetId(compatibleTargets[0].id);
    }
  }, [compatibleTargets, targetId]);

  const loadRecent = useCallback(() => {
    api.assessments
      .list({ module: meta.id, limit: 4 })
      .then((response) => setRecent(response.items))
      .catch(() => undefined);
  }, [meta.id]);

  useEffect(() => {
    loadRecent();
  }, [loadRecent]);

  const title = meta.name;
  const isPassword = meta.id === "password";

  const submit = async (start: boolean) => {
    if (!selectedTarget) {
      notify({ title: "Verified target required", message: "Register and verify a compatible scope before running this module.", tone: "warning" });
      return;
    }
    setBusy(true);
    try {
      if (isPassword) {
        const policy = config.policy || {};
        const response = await api.modules.passwordAudit({
          target_id: selectedTarget.id,
          policy: {
            min_length: Number(policy.min_length),
            require_uppercase: Boolean(policy.require_uppercase),
            require_lowercase: Boolean(policy.require_lowercase),
            require_digit: Boolean(policy.require_digit),
            require_symbol: Boolean(policy.require_symbol),
            max_reuse: Number(policy.max_reuse),
            lockout_after: Number(policy.lockout_after),
            lockout_minutes: Number(policy.lockout_minutes),
            mfa_required: Boolean(policy.mfa_required),
          },
          test_passwords: newlineList(String(config.test_passwords || ""), false),
          hashes: newlineList(String(config.hashes || "")),
          hash_algorithm: config.hash_algorithm,
          wordlist: newlineList(String(config.wordlist || ""), false),
        });
        setPasswordResult(response);
        setConfig((current) => ({ ...current, test_passwords: "", hashes: "" }));
        notify({
          title: "Password audit complete",
          message: `${response.policy_findings.length} policy finding(s). Inputs were not persisted.`,
          tone: "success",
        });
        loadRecent();
      } else {
        const prepared = buildConfig(meta.id, config);
        const assessment = await api.assessments.create({
          name: name.trim() || undefined,
          module: meta.id,
          target_id: selectedTarget.id,
          config: prepared,
          start,
        });
        notify({
          title: start ? "Assessment queued" : "Draft saved",
          message: start ? `${title} is waiting for a bounded worker.` : "Review the configuration from the assessment detail page.",
          tone: "success",
        });
        navigate(`/assessments/${assessment.id}`);
      }
    } catch (reason) {
      notify({ title: "Could not start operation", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" });
    } finally {
      setBusy(false);
    }
  };

  const calculateCvss = async () => {
    setCvssBusy(true);
    try {
      const result = await api.modules.cvss(cvssVector);
      setCvssResult(result);
    } catch (reason) {
      notify({ title: "CVSS calculation failed", message: reason instanceof Error ? reason.message : "Invalid vector.", tone: "error" });
    } finally {
      setCvssBusy(false);
    }
  };

  return (
    <div>
      <PageHeader
        eyebrow={`Module ${meta.number} · ${meta.category}`}
        title={title}
        description={meta.description}
        actions={
          <>
            <Link to="/assessments" className="btn-ghost btn-sm">
              <Terminal size={13} /> Assessment ledger
            </Link>
            {!canOperate ? <span className="chip border-amber/25 text-amber"><Eye size={10} /> read-only role</span> : null}
          </>
        }
      />

      <div className="grid gap-4 xl:grid-cols-[1fr_320px]">
        <div className="space-y-4">
          <Panel className="p-5">
            <SectionTitle
              eyebrow="Scoped operation"
              title="Configuration"
              action={
                <span className="chip border-cyan/20 text-cyan">
                  <Icon name={meta.icon} size={11} /> {meta.action.replace(/_/g, " ")}
                </span>
              }
            />
            <div className="mt-4 space-y-5">
              <TargetPicker targets={compatibleTargets} targetId={targetId} onChange={setTargetId} action={meta.action} meta={meta} />
              <div>
                <label className="label" htmlFor="assessment-name">
                  Assessment name <span className="normal-case tracking-normal text-slate-600">(optional)</span>
                </label>
                <input
                  id="assessment-name"
                  className="input"
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  placeholder={selectedTarget ? `${selectedTarget.name} · ${title}` : `${title} · ${new Date().toISOString().slice(0, 10)}`}
                  maxLength={200}
                />
              </div>

              <div className="glow-line" />

              <ModuleForm meta={meta} config={config} setConfig={setConfig} />

              {meta.id === "vulnerability" ? (
                <div className="rounded-xl border border-cyan/15 bg-cyan/[0.025] p-4">
                  <div className="flex items-center gap-2">
                    <Calculator size={14} className="text-cyan" />
                    <p className="font-mono text-[9px] uppercase tracking-[0.18em] text-cyan">CVSS v3.1 calculator</p>
                  </div>
                  <div className="mt-2.5 flex flex-col gap-2 sm:flex-row">
                    <input
                      className="input-mono flex-1"
                      value={cvssVector}
                      onChange={(event) => {
                        setCvssVector(event.target.value);
                        setCvssResult(null);
                      }}
                      aria-label="CVSS vector"
                    />
                    <button className="btn-ghost btn-sm" onClick={() => void calculateCvss()} disabled={cvssBusy}>
                      {cvssBusy ? <Loader2 size={12} className="animate-spin" /> : <Calculator size={12} />} Calculate
                    </button>
                  </div>
                  {cvssResult ? (
                    <div className="mt-2 flex flex-wrap items-center gap-2 font-mono text-[10px]">
                      <span className="text-white">Score {cvssResult.score.toFixed(1)}</span>
                      <span className="chip border-amber/25 text-amber">{cvssResult.severity}</span>
                      <span className="text-slate-600">CVSS v3.1</span>
                    </div>
                  ) : null}
                </div>
              ) : null}

              <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line/60 pt-4">
                <p className="flex items-center gap-1.5 font-mono text-[8px] uppercase tracking-wider text-slate-600">
                  <ShieldCheck size={11} className="text-neon" /> Verified target · action allowlist · immutable audit
                </p>
                <div className="flex flex-wrap items-center gap-2">
                  {!isPassword ? (
                    <button className="btn-ghost btn-sm" onClick={() => void submit(false)} disabled={busy || !canOperate || !selectedTarget}>
                      <Save size={13} /> Save draft
                    </button>
                  ) : null}
                  <button
                    className={isPassword ? "btn-neon" : "btn-primary"}
                    onClick={() => void submit(true)}
                    disabled={busy || !canOperate || !selectedTarget || targetsLoading}
                  >
                    {busy ? <Loader2 size={15} className="animate-spin" /> : isPassword ? <KeyRound size={15} /> : <Play size={15} />}
                    {busy ? "Processing…" : isPassword ? "Run in-memory audit" : "Queue assessment"}
                  </button>
                </div>
              </div>
              {!canOperate ? (
                <p className="text-[10px] text-amber">Your role is read-only. An administrator or analyst must run this operation.</p>
              ) : null}
            </div>
          </Panel>

          {isPassword && passwordResult ? <PasswordResults result={passwordResult} /> : null}

          <Panel className="p-5">
            <SectionTitle eyebrow="Recent activity" title={`${title} assessments`} />
            <div className="mt-3 space-y-2">
              {recent.length ? (
                recent.map((assessment) => (
                  <Link
                    key={assessment.id}
                    to={`/assessments/${assessment.id}`}
                    className="flex flex-wrap items-center gap-2 rounded-lg border border-line/60 bg-abyss/30 px-3 py-2.5 transition hover:border-cyan/25 hover:bg-cyan/[0.02]"
                  >
                    <StatusBadge status={assessment.status} />
                    <span className="min-w-0 flex-1 truncate text-[10px] text-ice">{assessment.name}</span>
                    {assessment.is_demo ? <DemoBadge compact /> : null}
                    <span className="font-mono text-[8px] uppercase tracking-wider text-slate-600">{timeAgo(assessment.created_at)}</span>
                    <ChevronRight size={12} className="text-slate-600" />
                  </Link>
                ))
              ) : (
                <p className="rounded-lg border border-line/60 bg-abyss/30 px-3 py-5 text-center text-[11px] text-mist">
                  No assessments have been run with this module yet.
                </p>
              )}
            </div>
          </Panel>
        </div>

        <div className="space-y-4">
          <Panel className="overflow-hidden">
            <div className="relative h-36 overflow-hidden border-b border-line/60">
              <ImageWithFallback src={meta.image} alt={`${meta.name} visual`} className="h-full w-full object-cover opacity-70" />
              <div className="absolute inset-0 bg-gradient-to-t from-panel via-panel/50 to-transparent" />
              <div className="absolute bottom-3 left-4 flex items-center gap-2">
                <span
                  className="flex h-8 w-8 items-center justify-center rounded-lg border"
                  style={{ color: meta.accent, borderColor: `${meta.accent}40`, backgroundColor: `${meta.accent}18` }}
                >
                  <Icon name={meta.icon} size={15} />
                </span>
                <div>
                  <p className="font-mono text-[8px] uppercase tracking-[0.18em] text-mist">Module {meta.number}</p>
                  <p className="text-[11px] font-medium text-white">{meta.category}</p>
                </div>
              </div>
            </div>
            <div className="p-4">
              <p className="font-mono text-[8px] uppercase tracking-[0.18em] text-slate-600">Safety boundary</p>
              <p className="mt-1.5 text-[10px] leading-relaxed text-mist">{MODULE_SAFETY[meta.id]}</p>
              <div className="mt-3 flex flex-wrap gap-1">
                <span className="chip border-neon/20 text-neon"><CheckCircle2 size={9} /> verified scope</span>
                <span className="chip border-cyan/20 text-cyan">rate limited</span>
                <span className="chip border-violet/20 text-violet">audited</span>
              </div>
            </div>
          </Panel>

          <Panel className="p-4">
            <p className="font-mono text-[8px] uppercase tracking-[0.18em] text-slate-600">Capabilities</p>
            <div className="mt-2.5 space-y-1.5">
              {meta.capabilities.map((capability) => (
                <p key={capability} className="flex items-start gap-2 text-[10px] text-mist">
                  <CheckCircle2 size={11} className="mt-0.5 shrink-0 text-neon/70" /> {capability}
                </p>
              ))}
            </div>
            {meta.techniques?.length ? (
              <>
                <p className="mb-1.5 mt-4 font-mono text-[8px] uppercase tracking-[0.18em] text-slate-600">ATT&CK mapping</p>
                <div className="flex flex-wrap gap-1">
                  {meta.techniques.map((technique) => (
                    <a
                      key={technique}
                      href={`https://attack.mitre.org/techniques/${technique.replace(".", "/")}/`}
                      target="_blank"
                      rel="noreferrer"
                      className="chip border-cyan/15 text-cyan transition hover:bg-cyan/10"
                    >
                      {technique} <ArrowUpRight size={9} />
                    </a>
                  ))}
                </div>
              </>
            ) : null}
          </Panel>

          <Panel className="p-4">
            <p className="font-mono text-[8px] uppercase tracking-[0.18em] text-slate-600">Target requirements</p>
            <div className="mt-2 flex flex-wrap gap-1">
              {meta.target_types.map((type) => (
                <span key={type} className="chip">{TARGET_TYPE_LABELS[type] || type}</span>
              ))}
            </div>
            <p className="mt-2.5 text-[10px] leading-relaxed text-mist">
              The target must be verified and explicitly allow <span className="font-mono text-cyan">{meta.action.replace(/_/g, " ")}</span> before execution.
            </p>
            <Link to="/targets" className="mt-3 flex items-center justify-between rounded-lg border border-line/70 px-2.5 py-2 font-mono text-[8px] uppercase tracking-wider text-mist transition hover:border-cyan/25 hover:text-cyan">
              Review scope register <ChevronRight size={11} />
            </Link>
          </Panel>

          <Panel className="p-4">
            <p className="font-mono text-[8px] uppercase tracking-[0.18em] text-slate-600">Rate discipline</p>
            <div className="mt-2 flex items-center justify-between font-mono text-[9px]">
              <span className="text-mist">Workers</span>
              <span className="text-cyan">bounded</span>
            </div>
            <div className="mt-1 flex items-center justify-between font-mono text-[9px]">
              <span className="text-mist">Timeouts</span>
              <span className="text-cyan">enforced</span>
            </div>
            <div className="mt-1 flex items-center justify-between font-mono text-[9px]">
              <span className="text-mist">Concurrency</span>
              <span className="text-cyan">capped</span>
            </div>
            <div className="mt-3 rounded-lg border border-amber/20 bg-amber/[0.03] p-2.5 text-[9px] leading-relaxed text-mist">
              <span className="flex items-center gap-1 font-mono uppercase tracking-wider text-amber"><Info size={9} /> authorized use</span>
              <p className="mt-1">Only assess systems covered by your written approval. Scope verification does not substitute for authorization.</p>
            </div>
          </Panel>
        </div>
      </div>

      <div className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line/60 bg-abyss/40 px-4 py-3 font-mono text-[8px] uppercase tracking-wider text-slate-600">
        <span className="flex items-center gap-1.5"><ShieldCheck size={11} className="text-neon/70" /> DARKBYTE ARES · one framework, complete red team operations</span>
        <span className="flex items-center gap-1.5"><Lock size={11} /> Evidence chained · demo labels preserved</span>
      </div>
    </div>
  );
}
