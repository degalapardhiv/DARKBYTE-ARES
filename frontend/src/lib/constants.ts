import type { ModuleMeta, Severity } from "./types";

export const APP_NAME = "DARKBYTE ARES";
export const TAGLINE = "ONE FRAMEWORK. COMPLETE RED TEAM OPERATIONS.";

export const DEMO_CREDENTIALS = {
  admin: { email: "admin@ares.example.com", password: "Ares!Admin2026" },
  analyst: { email: "analyst@ares.example.com", password: "Ares!Analyst2026" },
};

export const SEVERITY: Record<Severity, { label: string; color: string; bg: string; border: string; rank: number }> = {
  critical: { label: "Critical", color: "#FF3B5C", bg: "rgba(255,59,92,0.12)", border: "rgba(255,59,92,0.35)", rank: 5 },
  high: { label: "High", color: "#FF7A45", bg: "rgba(255,122,69,0.12)", border: "rgba(255,122,69,0.35)", rank: 4 },
  medium: { label: "Medium", color: "#FFB020", bg: "rgba(255,176,32,0.12)", border: "rgba(255,176,32,0.35)", rank: 3 },
  low: { label: "Low", color: "#38BDF8", bg: "rgba(56,189,248,0.12)", border: "rgba(56,189,248,0.35)", rank: 2 },
  info: { label: "Info", color: "#64748B", bg: "rgba(100,116,139,0.12)", border: "rgba(100,116,139,0.35)", rank: 1 },
};

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const STATUS_STYLES: Record<string, { label: string; color: string; bg: string }> = {
  draft: { label: "Draft", color: "#94A3B8", bg: "rgba(148,163,184,0.10)" },
  queued: { label: "Queued", color: "#00E5FF", bg: "rgba(0,229,255,0.10)" },
  running: { label: "Running", color: "#00E5FF", bg: "rgba(0,229,255,0.12)" },
  completed: { label: "Completed", color: "#00FF88", bg: "rgba(0,255,136,0.10)" },
  failed: { label: "Failed", color: "#FF3B5C", bg: "rgba(255,59,92,0.10)" },
  cancelled: { label: "Cancelled", color: "#FFB020", bg: "rgba(255,176,32,0.10)" },
  pending: { label: "Pending", color: "#FFB020", bg: "rgba(255,176,32,0.10)" },
  verified: { label: "Verified", color: "#00FF88", bg: "rgba(0,255,136,0.10)" },
  rejected: { label: "Rejected", color: "#FF3B5C", bg: "rgba(255,59,92,0.10)" },
  expired: { label: "Expired", color: "#64748B", bg: "rgba(100,116,139,0.10)" },
  open: { label: "Open", color: "#FFB020", bg: "rgba(255,176,32,0.10)" },
  accepted: { label: "Accepted", color: "#38BDF8", bg: "rgba(56,189,248,0.10)" },
  remediated: { label: "Remediated", color: "#00FF88", bg: "rgba(0,255,136,0.10)" },
  false_positive: { label: "False positive", color: "#64748B", bg: "rgba(100,116,139,0.10)" },
};

export const MODULE_META: Record<string, ModuleMeta & { path: string; image: string; number: string }> = {
  recon: {
    id: "recon",
    name: "Reconnaissance",
    short: "External asset discovery and attack-surface mapping.",
    description:
      "DNS inventory, subdomain discovery, WHOIS metadata, TLS certificate review and bounded HTTP fingerprinting. Passive-first and explicitly scoped.",
    category: "Discovery",
    icon: "Radar",
    accent: "#00E5FF",
    action: "recon",
    target_types: ["domain"],
    capabilities: ["DNS records", "Subdomain inventory", "WHOIS", "TLS certificate", "HTTP fingerprint"],
    techniques: ["T1590", "T1592", "T1595", "T1596"],
    path: "/modules/recon",
    image: "/assets/recon-visual.webp",
    number: "01",
  },
  network: {
    id: "network",
    name: "Network Scanner",
    short: "Bounded TCP service inventory for authorized ranges.",
    description:
      "TCP connect scanning with hard host, port and concurrency ceilings. Optional Nmap XML ingestion for lab environments. Risky exposed services are prioritized.",
    category: "Discovery",
    icon: "Network",
    accent: "#00FF88",
    action: "network_scan",
    target_types: ["ip", "cidr"],
    capabilities: ["TCP connect", "Service identification", "Banner metadata", "Topology map", "Nmap XML"],
    techniques: ["T1046", "T1133"],
    path: "/modules/network",
    image: "/assets/network-visual.webp",
    number: "02",
  },
  web: {
    id: "web",
    name: "Web Security",
    short: "OWASP-aligned, non-destructive web baseline.",
    description:
      "Security headers, TLS configuration, cookie flags, exposed sensitive files and safe reflection probes. Injection probes remain lab-gated and disabled by default.",
    category: "Application",
    icon: "Globe",
    accent: "#7C3AED",
    action: "web_scan",
    target_types: ["url", "domain"],
    capabilities: ["OWASP mapping", "Security headers", "TLS review", "Cookie flags", "Sensitive files"],
    techniques: ["T1190", "T1590"],
    path: "/modules/web",
    image: "/assets/cyber-hero.webp",
    number: "03",
  },
  vulnerability: {
    id: "vulnerability",
    name: "Vulnerability Intelligence",
    short: "CVE correlation with CVSS v3 scoring.",
    description:
      "NVD API queries plus a bundled, dated real-data snapshot for offline resilience. Results are scored with CVSS v3 base metrics and mapped to CWE identifiers.",
    category: "Intelligence",
    icon: "ShieldAlert",
    accent: "#FF3B5C",
    action: "vulnerability_lookup",
    target_types: ["domain", "url", "local"],
    capabilities: ["CVE search", "CVSS v3.1", "CWE mapping", "NVD snapshot", "Offline mode"],
    techniques: ["T1190", "T1595"],
    path: "/modules/vulnerability",
    image: "/assets/threat-intelligence.webp",
    number: "04",
  },
  osint: {
    id: "osint",
    name: "OSINT",
    short: "Passive public-source intelligence with evidence hashes.",
    description:
      "DNS, WHOIS, certificate transparency and authorized public-document metadata. Document bytes are never stored; SHA-256 evidence hashes preserve provenance.",
    category: "Intelligence",
    icon: "Fingerprint",
    accent: "#00E5FF",
    action: "osint",
    target_types: ["domain"],
    capabilities: ["Certificate transparency", "DNS intelligence", "WHOIS", "Document metadata", "Evidence hashing"],
    techniques: ["T1590", "T1592", "T1596"],
    path: "/modules/osint",
    image: "/assets/osint-visual.webp",
    number: "05",
  },
  password: {
    id: "password",
    name: "Password Audit",
    short: "Local strength and offline hash hygiene review.",
    description:
      "Runs entirely in memory. Plaintext and hashes are never persisted or returned in results. No credential store, domain controller or authentication endpoint is contacted.",
    category: "Identity",
    icon: "KeyRound",
    accent: "#FFB020",
    action: "password_audit",
    target_types: ["password_policy", "local"],
    capabilities: ["Strength scoring", "Policy review", "Offline dictionary audit", "MFA posture", "No plaintext persistence"],
    techniques: ["T1110"],
    path: "/modules/password",
    image: "/assets/vulnerability-visual.webp",
    number: "06",
  },
  active_directory: {
    id: "active_directory",
    name: "AD Audit",
    short: "Read-only AD configuration posture analysis.",
    description:
      "Accepts an exported AD configuration snapshot and reviews password policy, Kerberos, privileged groups and delegation posture. No LDAP connection is made.",
    category: "Identity",
    icon: "Building2",
    accent: "#8B5CF6",
    action: "config_audit",
    target_types: ["ad_config", "local"],
    capabilities: ["Password policy", "Kerberos posture", "Privileged groups", "Delegation review", "Read-only"],
    techniques: ["T1087", "T1558"],
    path: "/modules/active_directory",
    image: "/assets/threat-intelligence.webp",
    number: "07",
  },
  cloud: {
    id: "cloud",
    name: "Cloud Audit",
    short: "Read-only AWS, Azure and GCP configuration review.",
    description:
      "Reviews exported configuration snapshots for public storage, weak IAM, logging gaps and network exposure. No cloud credentials are requested or stored.",
    category: "Cloud",
    icon: "CloudCog",
    accent: "#22D3EE",
    action: "cloud_audit",
    target_types: ["cloud_account", "local"],
    capabilities: ["Public storage", "IAM review", "Logging coverage", "Network exposure", "Multi-cloud"],
    techniques: ["T1078.004", "T1530"],
    path: "/modules/cloud",
    image: "/assets/cyber-hero.webp",
    number: "08",
  },
  api_security: {
    id: "api_security",
    name: "API Security",
    short: "Safe API exposure, auth and CORS baseline.",
    description:
      "Bounded GET/OPTIONS probes on authorized origins, anonymous exposure observation, security headers, CORS policy and limited rate-limit evidence. No authorization bypass is attempted.",
    category: "Application",
    icon: "Braces",
    accent: "#A855F7",
    action: "api_scan",
    target_types: ["api", "url"],
    capabilities: ["Anonymous exposure", "CORS policy", "Security headers", "Rate-limit evidence", "Endpoint inventory"],
    techniques: ["T1190", "T1078"],
    path: "/modules/api_security",
    image: "/assets/network-visual.webp",
    number: "09",
  },
  red_team: {
    id: "red_team",
    name: "Red Team Simulator",
    short: "Tabletop attack-chain and detection planning.",
    description:
      "ATT&CK-mapped tabletop exercises only. ARES does not execute techniques, deploy malware, steal credentials or generate adversary traffic.",
    category: "Operations",
    icon: "Swords",
    accent: "#FF3B5C",
    action: "simulation",
    target_types: [
      "domain",
      "ip",
      "cidr",
      "url",
      "api",
      "cloud_account",
      "ad_config",
      "password_policy",
      "local",
    ],
    capabilities: ["ATT&CK mapping", "Scenario planning", "Detection requirements", "Tabletop only", "No execution"],
    techniques: ["T1566", "T1204", "T1078", "T1046", "T1087", "T1003", "T1021", "T1562", "T1486"],
    path: "/modules/red_team",
    image: "/assets/mitre-attack.webp",
    number: "10",
  },
};

export type NavItem = {
  label: string;
  path: string;
  icon: string;
  badge?: string;
  adminOnly?: boolean;
  end?: boolean;
};

export const NAV_GROUPS: { label: string; items: NavItem[] }[] = [
  {
    label: "Command",
    items: [
      { label: "Dashboard", path: "/", icon: "LayoutDashboard", end: true },
      { label: "Assessments", path: "/assessments", icon: "Activity" },
      { label: "Targets & Scope", path: "/targets", icon: "Crosshair" },
      { label: "Reports", path: "/reports", icon: "FileText" },
    ],
  },
  {
    label: "Offensive Modules",
    items: [
      { label: "Reconnaissance", path: "/modules/recon", icon: "Radar" },
      { label: "Network Scanner", path: "/modules/network", icon: "Network" },
      { label: "Web Security", path: "/modules/web", icon: "Globe" },
      { label: "Vulnerability Intel", path: "/modules/vulnerability", icon: "ShieldAlert" },
      { label: "OSINT", path: "/modules/osint", icon: "Fingerprint" },
    ],
  },
  {
    label: "Identity & Cloud",
    items: [
      { label: "Password Audit", path: "/modules/password", icon: "KeyRound" },
      { label: "AD Audit", path: "/modules/active_directory", icon: "Building2" },
      { label: "Cloud Audit", path: "/modules/cloud", icon: "CloudCog" },
      { label: "API Security", path: "/modules/api_security", icon: "Braces" },
    ],
  },
  {
    label: "Intelligence",
    items: [
      { label: "MITRE ATT&CK", path: "/mitre", icon: "Grid3X3" },
      { label: "Red Team Simulator", path: "/modules/red_team", icon: "Swords", badge: "TTX" },
    ],
  },
];

export const TARGET_ACTIONS = [
  "recon",
  "network_scan",
  "web_scan",
  "vulnerability_lookup",
  "osint",
  "password_audit",
  "config_audit",
  "cloud_audit",
  "api_scan",
  "simulation",
];

export const TARGET_TYPES = [
  "domain",
  "ip",
  "cidr",
  "url",
  "api",
  "cloud_account",
  "ad_config",
  "password_policy",
  "local",
];

export const ENVIRONMENTS = ["lab", "staging", "production"] as const;

export const SCENARIOS = [
  { id: "initial_access", name: "Initial Access", detail: "Phishing, exploitation and valid-account entry detection." },
  { id: "discovery", name: "Discovery", detail: "Internal network, account and host discovery telemetry." },
  { id: "credential_access", name: "Credential Access", detail: "Spraying, dumping and Kerberos abuse detection." },
  { id: "lateral_movement", name: "Lateral Movement", detail: "RDP, SMB and alternate-authentication paths." },
  { id: "defense_evasion", name: "Defense Evasion", detail: "Log tampering, masquerading and defense impairment." },
  { id: "impact_readiness", name: "Impact Readiness", detail: "Ransomware, recovery inhibition and service disruption." },
];

export const DEMO_AD_SNAPSHOT = {
  domain_name: "areslab.example.com",
  password_policy: {
    minimum_length: 10,
    lockout_threshold: 0,
    lockout_duration_minutes: 0,
    history_count: 5,
    max_age_days: 45,
    complexity_enabled: false,
    reversible_encryption: true,
  },
  kerberos: {
    krbtgt_password_age_days: 840,
    max_ticket_lifetime_hours: 24,
    unconstrained_delegation: ["LEGACY-APP01$"],
    constrained_delegation: ["WEB01$ -> HTTP/DB01.areslab.example.com"],
    aes_encryption: false,
  },
  privileged_groups: {
    domain_admins: ["Administrator", "svc-backup", "Helpdesk-Tier3"],
    enterprise_admins: ["Administrator"],
    schema_admins: ["Administrator", "svc-migration"],
  },
  accounts: [
    { name: "svc-backup", password_never_expires: true, admin_count: true, kerberoastable: true },
    { name: "svc-migration", password_never_expires: true, admin_count: true },
    { name: "guest", enabled: true, admin_count: false },
  ],
  audit: { advanced_auditing_enabled: false, log_retention_days: 14 },
};

export const DEMO_CLOUD_SNAPSHOT = {
  identity: {
    root_access_keys: true,
    root_mfa: false,
    mfa_enforced: false,
    guest_access: true,
    password_policy: { minimum_length: 8 },
  },
  storage: [
    { name: "ares-public-assets", public: true, encrypted: false, https_only: false },
    { name: "ares-backups", public: false, encrypted: true, https_only: true },
  ],
  iam: [
    { name: "AdminPolicy", action: "*", resource: "*", principal: "svc-automation" },
    { name: "CICD-Deploy", action: "s3:*", resource: "*", principal: "ci-runner" },
  ],
  logging: { cloudtrail_enabled: false, flow_logs_enabled: false, retention_days: 7 },
  network: { default_vpc_in_use: true, open_ssh_cidr: "0.0.0.0/0", open_rdp_cidr: "0.0.0.0/0" },
};

export const TERMINAL_LINES = [
  "scope.verify --target demo.example.com --action recon",
  "authorization.record LAB-ARES-2026-001 verified",
  "engine.recon dispatch → bounded workers 02",
  "evidence.sha256 9f1c8d4b6e35a923d7c8eb0a5b1d4f0e",
  "audit.append action=assessment.completed outcome=success",
  "mitre.coverage T1590 T1595 T1190 mapped",
  "queue.health workers=2 depth=0 status=nominal",
  "policy.authorized-testing enforced",
];
