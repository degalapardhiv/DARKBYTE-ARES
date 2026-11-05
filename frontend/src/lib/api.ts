import type {
  Assessment,
  AuditEntry,
  DashboardData,
  Finding,
  MitreCoverage,
  MitreTactic,
  MitreTechnique,
  ModuleMeta,
  Notification,
  Paged,
  PasswordAuditResult,
  PlatformInfo,
  Plugin,
  Report,
  Target,
  TokenResponse,
  User,
} from "./types";

const API_BASE = (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/$/, "") || "/api/v1";
const TOKEN_KEY = "ares.token";

export class ApiError extends Error {
  status: number;
  code: string;
  details: unknown;

  constructor(status: number, message: string, code = "request_failed", details: unknown = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

let unauthorizedHandler: (() => void) | null = null;

export function setUnauthorizedHandler(handler: (() => void) | null) {
  unauthorizedHandler = handler;
}

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string | null) {
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
}

function buildQuery(params?: Record<string, string | number | boolean | null | undefined>): string {
  if (!params) return "";
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") search.set(key, String(value));
  });
  const encoded = search.toString();
  return encoded ? `?${encoded}` : "";
}

async function parseError(response: Response): Promise<ApiError> {
  let message = `Request failed with HTTP ${response.status}.`;
  let code = "request_failed";
  let details: unknown = null;
  try {
    const payload = await response.json();
    if (payload?.error) {
      message = payload.error.message || message;
      code = payload.error.code || code;
      details = payload.error.details ?? null;
    } else if (payload?.detail) {
      if (typeof payload.detail === "string") message = payload.detail;
      else {
        message = payload.detail.message || message;
        code = payload.detail.code || code;
        details = payload.detail.details ?? null;
      }
    }
  } catch {
    // Non-JSON error response.
  }
  return new ApiError(response.status, message, code, details);
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !(init.body instanceof FormData)) headers.set("Content-Type", "application/json");
  headers.set("Accept", "application/json");
  const response = await fetch(`${API_BASE}${path}`, { ...init, headers });
  if (response.status === 401 && token) {
    setToken(null);
    unauthorizedHandler?.();
  }
  if (!response.ok) throw await parseError(response);
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

async function download(path: string): Promise<{ blob: Blob; filename: string }> {
  const token = getToken();
  const response = await fetch(`${API_BASE}${path}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!response.ok) throw await parseError(response);
  const disposition = response.headers.get("content-disposition") || "";
  const match = disposition.match(/filename\*=UTF-8''([^;]+)/i) || disposition.match(/filename="?([^";]+)"?/i);
  const filename = match ? decodeURIComponent(match[1]) : "ares-report";
  return { blob: await response.blob(), filename };
}

function jsonBody(value: unknown): RequestInit {
  return { body: JSON.stringify(value) };
}

export const api = {
  auth: {
    login: (email: string, password: string) =>
      request<TokenResponse>("/auth/login", { method: "POST", ...jsonBody({ email, password }) }),
    register: (email: string, name: string, password: string) =>
      request<TokenResponse>("/auth/register", { method: "POST", ...jsonBody({ email, name, password }) }),
    me: () => request<User>("/auth/me"),
    updateProfile: (name: string, preferences: Record<string, unknown>) =>
      request<User>("/auth/profile", { method: "PATCH", ...jsonBody({ name, preferences }) }),
    changePassword: (current_password: string, new_password: string) =>
      request<{ message: string }>("/auth/change-password", {
        method: "POST",
        ...jsonBody({ current_password, new_password }),
      }),
    logout: () => request<{ message: string }>("/auth/logout", { method: "POST" }),
  },
  targets: {
    list: (params?: Record<string, string | number | boolean | null | undefined>) =>
      request<Paged<Target>>(`/targets${buildQuery(params)}`),
    create: (payload: Record<string, unknown>) =>
      request<Target>("/targets", { method: "POST", ...jsonBody(payload) }),
    get: (id: string) => request<Target>(`/targets/${id}`),
    update: (id: string, payload: Record<string, unknown>) =>
      request<Target>(`/targets/${id}`, { method: "PATCH", ...jsonBody(payload) }),
    verify: (id: string, payload: Record<string, unknown>) =>
      request<Target>(`/targets/${id}/verify`, { method: "POST", ...jsonBody(payload) }),
    reject: (id: string, reason: string) =>
      request<Target>(`/targets/${id}/reject`, { method: "POST", ...jsonBody({ reason }) }),
    remove: (id: string) => request<void>(`/targets/${id}`, { method: "DELETE" }),
  },
  assessments: {
    list: (params?: Record<string, string | number | boolean | null | undefined>) =>
      request<Paged<Assessment>>(`/assessments${buildQuery(params)}`),
    get: (id: string) => request<Assessment>(`/assessments/${id}`),
    create: (payload: Record<string, unknown>) =>
      request<Assessment>("/assessments", { method: "POST", ...jsonBody(payload) }),
    run: (id: string) => request<Assessment>(`/assessments/${id}/run`, { method: "POST" }),
    cancel: (id: string) => request<Assessment>(`/assessments/${id}/cancel`, { method: "POST" }),
    remove: (id: string) => request<void>(`/assessments/${id}`, { method: "DELETE" }),
    findings: (id: string, params?: Record<string, string | number | boolean | null | undefined>) =>
      request<Paged<Finding>>(`/assessments/${id}/findings${buildQuery(params)}`),
  },
  findings: {
    list: (params?: Record<string, string | number | boolean | null | undefined>) =>
      request<Paged<Finding>>(`/findings${buildQuery(params)}`),
    get: (id: string) => request<Finding>(`/findings/${id}`),
    updateStatus: (id: string, status: string) =>
      request<Finding>(`/findings/${id}`, { method: "PATCH", ...jsonBody({ status }) }),
  },
  dashboard: {
    overview: () => request<DashboardData>("/dashboard"),
    activity: (limit = 25) => request<{ items: DashboardData["activity"]; total: number }>(`/dashboard/activity?limit=${limit}`),
  },
  reports: {
    list: (params?: Record<string, string | number | boolean | null | undefined>) =>
      request<Paged<Report>>(`/reports${buildQuery(params)}`),
    create: (payload: Record<string, unknown>) =>
      request<Report>("/reports", { method: "POST", ...jsonBody(payload) }),
    get: (id: string) => request<Report>(`/reports/${id}`),
    download,
    remove: (id: string) => request<void>(`/reports/${id}`, { method: "DELETE" }),
  },
  modules: {
    list: () => request<{ items: ModuleMeta[]; total: number }>("/modules"),
    get: (id: string) => request<ModuleMeta & { id: string }>(`/modules/${id}`),
    cvss: (vector: string) =>
      request<{ vector: string; score: number; severity: string; standard: string; reference: string }>("/tools/cvss", {
        method: "POST",
        ...jsonBody({ vector }),
      }),
    passwordAudit: (payload: Record<string, unknown>) =>
      request<PasswordAuditResult>("/tools/password-audit", { method: "POST", ...jsonBody(payload) }),
  },
  mitre: {
    tactics: () => request<{ items: MitreTactic[]; total: number; source: Record<string, unknown> }>("/mitre/tactics"),
    techniques: (params?: Record<string, string | number | boolean | null | undefined>) =>
      request<{ items: MitreTechnique[]; total: number; limit: number; offset: number; source: Record<string, unknown> }>(
        `/mitre/techniques${buildQuery(params)}`,
      ),
    technique: (id: string) => request<MitreTechnique>(`/mitre/techniques/${id}`),
    coverage: (assessmentId?: string) =>
      request<MitreCoverage>(`/mitre/coverage${buildQuery({ assessment_id: assessmentId })}`),
  },
  plugins: {
    list: () => request<{ items: Plugin[]; total: number; policy: string }>("/plugins"),
    enable: (id: string) => request<{ id: string; enabled: boolean }>(`/plugins/${id}/enable`, { method: "POST" }),
    disable: (id: string) => request<{ id: string; enabled: boolean }>(`/plugins/${id}/disable`, { method: "POST" }),
    run: (id: string, assessmentId: string) =>
      request<{ plugin_id: string; assessment_id: string; result: Record<string, unknown> }>(`/plugins/${id}/run`, {
        method: "POST",
        ...jsonBody({ assessment_id: assessmentId }),
      }),
  },
  notifications: {
    list: (params?: Record<string, string | number | boolean | null | undefined>) =>
      request<{ items: Notification[]; total: number; unread: number; limit: number; offset: number }>(
        `/notifications${buildQuery(params)}`,
      ),
    read: (id: string) => request<Notification>(`/notifications/${id}/read`, { method: "POST" }),
    readAll: () => request<{ updated: number }>("/notifications/read-all", { method: "POST" }),
    remove: (id: string) => request<void>(`/notifications/${id}`, { method: "DELETE" }),
  },
  platform: {
    health: () =>
      request<{
        status: string;
        version: string;
        environment: string;
        demo_mode: boolean;
        database: string;
        redis: string;
        queue_workers: number;
      }>("/health"),
    info: () => request<PlatformInfo>("/platform/info"),
    settings: () =>
      request<{ user: User; preferences: Record<string, unknown>; platform: Record<string, unknown> }>("/settings"),
    updateSettings: (preferences: Record<string, unknown>) =>
      request<{ preferences: Record<string, unknown>; user: User }>("/settings", {
        method: "PATCH",
        ...jsonBody({ preferences }),
      }),
    users: () => request<{ items: User[]; total: number }>("/users"),
    updateUser: (id: string, payload: Record<string, unknown>) =>
      request<User>(`/users/${id}`, { method: "PATCH", ...jsonBody(payload) }),
    audit: (params?: Record<string, string | number | boolean | null | undefined>) =>
      request<{ items: AuditEntry[]; total: number; limit: number; offset: number }>(`/audit${buildQuery(params)}`),
    auditVerify: () => request<{ valid: boolean; checked: number; broken_at: number | null; head: string }>("/audit/verify"),
  },
};

export function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export { API_BASE };
