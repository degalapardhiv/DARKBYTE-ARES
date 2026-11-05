export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Role = "admin" | "analyst" | "viewer";

export interface User {
  id: string;
  email: string;
  name: string;
  role: Role;
  is_active: boolean;
  preferences: Record<string, unknown>;
  last_login_at: string | null;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export interface Target {
  id: string;
  name: string;
  target_type: string;
  value: string;
  environment: "production" | "staging" | "lab";
  authorization_ref: string;
  authorized_by: string;
  authorization_expires: string | null;
  allowed_actions: string[];
  status: "pending" | "verified" | "rejected" | "expired";
  verified_by: string | null;
  verified_at: string | null;
  notes: string;
  is_demo: boolean;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface Assessment {
  id: string;
  name: string;
  module: string;
  target_id: string;
  target_name: string | null;
  target_value: string | null;
  config: Record<string, unknown>;
  status: string;
  progress: number;
  summary: Record<string, any>;
  risk_score: number;
  error: string | null;
  is_demo: boolean;
  created_by: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface Finding {
  id: string;
  assessment_id: string;
  target_id: string;
  module: string;
  title: string;
  description: string;
  severity: Severity;
  cvss_score: number | null;
  cvss_vector: string | null;
  cve_id: string | null;
  evidence: Record<string, any>;
  remediation: string;
  references: string[];
  technique_ids: string[];
  status: "open" | "accepted" | "remediated" | "false_positive";
  is_demo: boolean;
  created_at: string;
}

export interface Report {
  id: string;
  assessment_id: string;
  title: string;
  format: "pdf" | "html" | "json";
  size_bytes: number;
  status: string;
  executive_summary: string;
  meta: Record<string, any>;
  is_demo: boolean;
  created_by: string;
  created_at: string;
}

export interface Notification {
  id: string;
  title: string;
  message: string;
  level: "info" | "success" | "warning" | "error" | "critical";
  read: boolean;
  link: string | null;
  created_at: string;
}

export interface Paged<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface DashboardStats {
  total_assessments: number;
  completed_assessments: number;
  active_assessments: number;
  total_findings: number;
  open_findings: number;
  critical_findings: number;
  high_findings: number;
  verified_targets: number;
  pending_targets: number;
  reports: number;
  avg_risk: number;
  assessments_last_7_days: number;
  assessments_prior_7_days: number;
  unread_notifications: number;
}

export interface DashboardData {
  stats: DashboardStats;
  severity: { name: Severity; value: number }[];
  risk_trend: { date: string; assessments: number; risk_score: number | null }[];
  modules: { module: string; assessments: number; findings: number; avg_risk: number }[];
  recent_assessments: Assessment[];
  top_findings: Finding[];
  activity: { id: number; action: string; resource_type: string; resource_id: string | null; outcome: string; actor: string; created_at: string | null }[];
  mitre: {
    covered: number;
    total: number;
    percentage: number;
    tactics: { id: string; name: string; shortname: string; covered: number; total: number; percentage: number }[];
  };
}

export interface ModuleMeta {
  id: string;
  name: string;
  short: string;
  description: string;
  category: string;
  icon: string;
  accent: string;
  action: string;
  target_types: string[];
  capabilities: string[];
  techniques?: string[];
  config_schema?: Record<string, any> | null;
  synchronous_tool?: boolean;
}

export interface MitreTactic {
  id: string;
  name: string;
  shortname: string;
  description: string;
  url: string;
}

export interface MitreTechnique {
  id: string;
  name: string;
  description: string;
  tactics: string[];
  subtechnique?: boolean;
  parent_id?: string;
  url?: string;
  platforms?: string[];
}

export interface MitreCoverage {
  covered: number;
  total: number;
  percentage: number;
  tactics: {
    id: string;
    name: string;
    shortname: string;
    total: number;
    covered: number;
    percentage: number;
    covered_ids: string[];
  }[];
  observed_technique_ids: string[];
  source: Record<string, any>;
}

export interface Plugin {
  id: string;
  name: string;
  version: string;
  description: string;
  author: string;
  permissions: string[];
  enabled: boolean;
  path: string;
  min_ares_version: string | null;
}

export interface AuditEntry {
  id: number;
  created_at: string | null;
  actor_id: string | null;
  actor_email: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  outcome: string;
  details: Record<string, any>;
  ip_address: string | null;
  prev_hash: string;
  entry_hash: string;
}

export interface PlatformInfo {
  name: string;
  version: string;
  tagline: string;
  environment: string;
  demo_mode: boolean;
  role: string;
  modules: string[];
  safety: Record<string, boolean | number | string>;
  policy: Record<string, string>;
}

export interface PasswordAuditResult {
  assessment: Assessment;
  strength: {
    index: number;
    label_name: string;
    score: number;
    label: string;
    length: number;
    character_classes: number;
    entropy_bits: number;
    estimated_offline_time: string;
    feedback: string[];
  }[];
  hash_audit: {
    hashes_audited: number;
    supported_hashes: number;
    unsupported_indices: number[];
    matched_hashes: { index: number; algorithm: string; dictionary_match: boolean }[];
    match_count: number;
    formats: Record<string, number>;
    dictionary_size: number;
    hash_score: number;
    plaintext_returned: boolean;
    notice: string;
  };
  policy_findings: {
    key: string;
    severity: Severity;
    title: string;
    description: string;
    remediation: string;
    cvss_score: number;
    evidence: Record<string, any>;
  }[];
}
