import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Eye,
  EyeOff,
  History,
  KeyRound,
  Loader2,
  Lock,
  Plug,
  Save,
  Shield,
  ShieldCheck,
  UserCog,
  Users,
} from "lucide-react";
import { PageHeader } from "../components/PageHeader";
import { Panel, SectionTitle, Toggle, InlineSpinner } from "../components/ui";
import { DemoBadge } from "../components/Badges";
import { api } from "../lib/api";
import type { PlatformInfo, User } from "../lib/types";
import { ENVIRONMENTS } from "../lib/constants";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { cn, formatDate, initials } from "../lib/utils";

const PASSWORD_RULES = [
  { key: "length", label: "12+ characters", test: (value: string) => value.length >= 12 },
  { key: "upper", label: "Uppercase", test: (value: string) => /[A-Z]/.test(value) },
  { key: "lower", label: "Lowercase", test: (value: string) => /[a-z]/.test(value) },
  { key: "digit", label: "Number", test: (value: string) => /\d/.test(value) },
  { key: "symbol", label: "Symbol", test: (value: string) => /[^A-Za-z0-9]/.test(value) },
];

export function Settings() {
  const { user, setUser } = useAuth();
  const { notify } = useToast();
  const [name, setName] = useState(user?.name || "");
  const [preferences, setPreferences] = useState<Record<string, any>>(user?.preferences || {});
  const [platform, setPlatform] = useState<Record<string, any>>({});
  const [info, setInfo] = useState<PlatformInfo | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [profileBusy, setProfileBusy] = useState(false);
  const [prefsBusy, setPrefsBusy] = useState(false);
  const [passwordBusy, setPasswordBusy] = useState(false);
  const [userBusy, setUserBusy] = useState<string | null>(null);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPasswords, setShowPasswords] = useState(false);
  const [passwordError, setPasswordError] = useState<string | null>(null);

  const isAdmin = user?.role === "admin";
  const rules = useMemo(() => PASSWORD_RULES.map((rule) => ({ ...rule, passed: rule.test(newPassword) })), [newPassword]);

  const loadUsers = useCallback(async () => {
    if (!isAdmin) return;
    try {
      const response = await api.platform.users();
      setUsers(response.items);
    } catch {
      // The admin section is secondary; report errors through the toast only when an action fails.
    }
  }, [isAdmin]);

  useEffect(() => {
    Promise.all([api.platform.settings(), api.platform.info()])
      .then(([settings, platformInfo]) => {
        setName(settings.user.name);
        setUser(settings.user);
        setPreferences(settings.user.preferences || {});
        setPlatform(settings.platform);
        setInfo(platformInfo);
      })
      .catch((reason) => notify({ title: "Could not load settings", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" }))
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    void loadUsers();
  }, [loadUsers]);

  const saveProfile = async () => {
    if (!user) return;
    setProfileBusy(true);
    try {
      const updated = await api.auth.updateProfile(name.trim(), preferences);
      setUser(updated);
      notify({ title: "Profile updated", message: "Your operator identity has been saved.", tone: "success" });
    } catch (reason) {
      notify({ title: "Profile update failed", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" });
    } finally {
      setProfileBusy(false);
    }
  };

  const savePreferences = async () => {
    setPrefsBusy(true);
    try {
      const updated = await api.platform.updateSettings(preferences);
      setPreferences(updated.preferences);
      setUser(updated.user);
      notify({ title: "Preferences saved", message: "Console behavior updated for this account.", tone: "success" });
    } catch (reason) {
      notify({ title: "Preference update failed", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" });
    } finally {
      setPrefsBusy(false);
    }
  };

  const changePassword = async () => {
    setPasswordError(null);
    if (!rules.every((rule) => rule.passed)) {
      setPasswordError("The new password does not satisfy every policy requirement.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setPasswordError("Password confirmation does not match.");
      return;
    }
    setPasswordBusy(true);
    try {
      await api.auth.changePassword(currentPassword, newPassword);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      notify({ title: "Password changed", message: "Use the new password on your next sign-in.", tone: "success" });
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "Password change failed.";
      setPasswordError(message);
      notify({ title: "Password not changed", message, tone: "error" });
    } finally {
      setPasswordBusy(false);
    }
  };

  const updateUser = async (target: User, payload: Record<string, unknown>) => {
    setUserBusy(target.id);
    try {
      const updated = await api.platform.updateUser(target.id, payload);
      setUsers((current) => current.map((item) => (item.id === updated.id ? updated : item)));
      notify({ title: "Operator updated", message: `${updated.name} · ${updated.role}${updated.is_active ? "" : " · disabled"}`, tone: "success" });
    } catch (reason) {
      notify({ title: "Could not update operator", message: reason instanceof Error ? reason.message : "Request failed.", tone: "error" });
    } finally {
      setUserBusy(null);
    }
  };

  if (!user) return null;

  return (
    <div>
      <PageHeader
        eyebrow="Operator configuration"
        title="Settings"
        description="Manage your profile, console preferences and security posture. Administrators can review operator roles and platform safety limits."
        actions={<DemoBadge compact />}
      />

      <div className="grid gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          <Panel className="p-5">
            <SectionTitle eyebrow="Identity" title="Operator profile" action={loading ? <InlineSpinner /> : null} />
            <div className="mt-5 flex flex-col gap-5 sm:flex-row">
              <div className="flex h-20 w-20 shrink-0 items-center justify-center rounded-2xl border border-cyan/25 bg-gradient-to-br from-cyan/25 to-violet/30 font-mono text-xl font-bold text-white shadow-glow-cyan">
                {initials(user.name)}
              </div>
              <div className="grid flex-1 gap-4 sm:grid-cols-2">
                <div>
                  <label className="label" htmlFor="profile-name">
                    Full name
                  </label>
                  <input id="profile-name" className="input" value={name} onChange={(event) => setName(event.target.value)} />
                </div>
                <div>
                  <label className="label" htmlFor="profile-email">
                    Email
                  </label>
                  <input id="profile-email" className="input opacity-70" value={user.email} readOnly />
                </div>
                <div>
                  <p className="label">Role</p>
                  <div className="flex h-[42px] items-center gap-2 rounded-xl border border-line bg-abyss/80 px-3">
                    <Shield size={14} className="text-cyan" />
                    <span className="font-mono text-xs uppercase tracking-wider text-ice">{user.role}</span>
                  </div>
                </div>
                <div>
                  <p className="label">Last sign-in</p>
                  <div className="flex h-[42px] items-center rounded-xl border border-line bg-abyss/80 px-3 font-mono text-[10px] text-mist">
                    {user.last_login_at ? formatDate(user.last_login_at) : "First session"}
                  </div>
                </div>
              </div>
            </div>
            <div className="mt-4 flex justify-end">
              <button className="btn-primary btn-sm" onClick={() => void saveProfile()} disabled={profileBusy || name.trim().length < 2}>
                {profileBusy ? <Loader2 size={13} className="animate-spin" /> : <Save size={13} />} Save profile
              </button>
            </div>
          </Panel>

          <Panel className="p-5">
            <SectionTitle eyebrow="Console behavior" title="Preferences" />
            <div className="mt-4 grid gap-5 md:grid-cols-2">
              <div className="space-y-3">
                <Toggle
                  checked={Boolean(preferences.notifications)}
                  onChange={(value) => setPreferences({ ...preferences, notifications: value })}
                  label="In-console notifications"
                  description="Receive alerts for assessment completion and platform events."
                />
                <Toggle
                  checked={Boolean(preferences.criticalAlerts)}
                  onChange={(value) => setPreferences({ ...preferences, criticalAlerts: value })}
                  label="Critical alert emphasis"
                  description="Highlight critical findings in notification surfaces."
                />
                <Toggle
                  checked={Boolean(preferences.emailDigest)}
                  onChange={(value) => setPreferences({ ...preferences, emailDigest: value })}
                  label="Weekly email digest"
                  description="Store a digest preference for your notification integration."
                />
              </div>
              <div className="space-y-4">
                <Toggle
                  checked={Boolean(preferences.compactMode)}
                  onChange={(value) => setPreferences({ ...preferences, compactMode: value })}
                  label="Compact data density"
                  description="Prefer denser tables when supported by the console."
                />
                <div>
                  <label className="label" htmlFor="default-environment">
                    Default target environment
                  </label>
                  <select
                    id="default-environment"
                    className="input"
                    value={String(preferences.defaultEnvironment || "lab")}
                    onChange={(event) => setPreferences({ ...preferences, defaultEnvironment: event.target.value })}
                  >
                    {ENVIRONMENTS.map((environment) => (
                      <option key={environment} value={environment}>
                        {environment}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="rounded-lg border border-line/70 bg-abyss/40 p-3 text-[10px] leading-relaxed text-mist">
                  Preferences are converted to a notification and display policy. Scope, rate limits and audit
                  controls cannot be weakened from this screen.
                </div>
              </div>
            </div>
            <div className="mt-4 flex justify-end">
              <button className="btn-primary btn-sm" onClick={() => void savePreferences()} disabled={prefsBusy}>
                {prefsBusy ? <Loader2 size={13} className="animate-spin" /> : <Save size={13} />} Save preferences
              </button>
            </div>
          </Panel>

          <Panel className="p-5">
            <SectionTitle eyebrow="Credential security" title="Change password" />
            <div className="mt-4 grid gap-4 sm:grid-cols-3">
              <div>
                <label className="label" htmlFor="current-password">
                  Current password
                </label>
                <div className="relative">
                  <Lock size={14} className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
                  <input
                    id="current-password"
                    type={showPasswords ? "text" : "password"}
                    className="input pl-10"
                    value={currentPassword}
                    onChange={(event) => setCurrentPassword(event.target.value)}
                    autoComplete="current-password"
                  />
                </div>
              </div>
              <div>
                <label className="label" htmlFor="next-password">
                  New password
                </label>
                <input
                  id="next-password"
                  type={showPasswords ? "text" : "password"}
                  className="input"
                  value={newPassword}
                  onChange={(event) => setNewPassword(event.target.value)}
                  autoComplete="new-password"
                />
              </div>
              <div>
                <label className="label" htmlFor="confirm-new-password">
                  Confirm new password
                </label>
                <input
                  id="confirm-new-password"
                  type={showPasswords ? "text" : "password"}
                  className={cn("input", confirmPassword && confirmPassword !== newPassword && "border-crimson/50")}
                  value={confirmPassword}
                  onChange={(event) => setConfirmPassword(event.target.value)}
                  autoComplete="new-password"
                />
              </div>
            </div>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              {rules.map((rule) => (
                <span
                  key={rule.key}
                  className={cn(
                    "inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[8px] uppercase tracking-wider",
                    rule.passed ? "border-neon/25 bg-neon/5 text-neon" : "border-line text-slate-600",
                  )}
                >
                  <Check size={8} /> {rule.label}
                </span>
              ))}
              <button
                type="button"
                className="ml-auto inline-flex items-center gap-1 font-mono text-[9px] uppercase tracking-wider text-mist transition hover:text-ice"
                onClick={() => setShowPasswords((value) => !value)}
              >
                {showPasswords ? <EyeOff size={12} /> : <Eye size={12} />} {showPasswords ? "Hide" : "Show"}
              </button>
            </div>
            {passwordError ? (
              <div className="mt-3 flex items-start gap-2 rounded-lg border border-crimson/30 bg-crimson/10 px-3 py-2 text-[11px] leading-relaxed text-crimson">
                <AlertTriangle size={13} className="mt-0.5 shrink-0" /> {passwordError}
              </div>
            ) : null}
            <div className="mt-4 flex justify-end">
              <button className="btn-primary btn-sm" onClick={() => void changePassword()} disabled={passwordBusy || !currentPassword}>
                {passwordBusy ? <Loader2 size={13} className="animate-spin" /> : <KeyRound size={13} />} Change password
              </button>
            </div>
          </Panel>
        </div>

        <div className="space-y-4">
          <Panel className="p-5">
            <SectionTitle eyebrow="Deployment" title="Platform posture" />
            <div className="mt-4 space-y-2.5 text-[11px]">
              {[
                { label: "Environment", value: platform.environment || info?.environment || "—" },
                { label: "Version", value: platform.version || info?.version || "—" },
                { label: "Role", value: user.role },
                { label: "Registration", value: platform.registration_enabled ? "enabled" : "closed" },
                { label: "Demo mode", value: platform.demo_mode ? "enabled" : "disabled" },
              ].map((row) => (
                <div key={row.label} className="flex items-center justify-between gap-2 border-b border-line/40 pb-2 last:border-0">
                  <span className="font-mono text-[8px] uppercase tracking-wider text-slate-600">{row.label}</span>
                  <span className="font-mono text-[10px] text-ice">{row.value}</span>
                </div>
              ))}
            </div>
            {platform.demo_mode ? (
              <div className="mt-4 flex items-start gap-2 rounded-lg border border-amber/20 bg-amber/[0.04] p-3 text-[10px] leading-relaxed text-mist">
                <AlertTriangle size={13} className="mt-0.5 shrink-0 text-amber" />
                Demo mode seeds clearly labelled records. Production deployments must set DEMO_MODE=false and use
                unique credentials.
              </div>
            ) : null}
          </Panel>

          <Panel className="p-5">
            <SectionTitle eyebrow="Safety envelope" title="Enforced limits" />
            {info ? (
              <div className="mt-4 space-y-2">
                {[
                  { label: "Verified targets required", value: info.safety.require_verified_targets },
                  { label: "Max scan hosts", value: info.safety.max_scan_hosts },
                  { label: "Max ports / scan", value: info.safety.max_ports_per_scan },
                  { label: "Concurrent assessments", value: info.safety.max_concurrent_assessments },
                  { label: "Assessment timeout (s)", value: info.safety.assessment_timeout_seconds },
                  { label: "API rate limit / min", value: info.safety.rate_limit_per_minute },
                  { label: "Private targets", value: info.safety.allow_private_targets },
                  { label: "Lab mode", value: info.safety.lab_mode },
                  { label: "Immutable audit", value: info.safety.immutable_audit },
                ].map((row) => (
                  <div key={row.label} className="flex items-center justify-between gap-2">
                    <span className="text-[10px] text-mist">{row.label}</span>
                    <span className="font-mono text-[10px] text-cyan">
                      {typeof row.value === "boolean" ? (row.value ? "yes" : "no") : String(row.value)}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-6 text-center"><InlineSpinner /></div>
            )}
            <div className="mt-4 flex items-start gap-2 rounded-lg border border-neon/20 bg-neon/[0.03] p-3 text-[10px] leading-relaxed text-mist">
              <ShieldCheck size={13} className="mt-0.5 shrink-0 text-neon" />
              These ceilings are enforced server-side and cannot be relaxed from the client.
            </div>
          </Panel>

          {isAdmin ? (
            <Panel className="p-5">
              <SectionTitle eyebrow="Administration" title="Controls" />
              <div className="mt-3 space-y-2">
                <Link to="/audit" className="flex items-center justify-between rounded-lg border border-line/70 px-3 py-2.5 text-[11px] text-mist transition hover:border-cyan/25 hover:text-ice">
                  <span className="flex items-center gap-2"><History size={13} className="text-cyan" /> Audit trail</span>
                  <span className="font-mono text-[8px] text-slate-600">hash chain</span>
                </Link>
                <Link to="/plugins" className="flex items-center justify-between rounded-lg border border-line/70 px-3 py-2.5 text-[11px] text-mist transition hover:border-cyan/25 hover:text-ice">
                  <span className="flex items-center gap-2"><Plug size={13} className="text-cyan" /> Extensions</span>
                  <span className="font-mono text-[8px] text-slate-600">trusted local</span>
                </Link>
                <Link to="/targets" className="flex items-center justify-between rounded-lg border border-line/70 px-3 py-2.5 text-[11px] text-mist transition hover:border-cyan/25 hover:text-ice">
                  <span className="flex items-center gap-2"><UserCog size={13} className="text-cyan" /> Scope register</span>
                  <span className="font-mono text-[8px] text-slate-600">verify</span>
                </Link>
              </div>
            </Panel>
          ) : null}
        </div>
      </div>

      {isAdmin ? (
        <Panel className="mt-4 overflow-hidden">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line/70 px-5 py-4">
            <SectionTitle eyebrow="Administration" title="Operator accounts" action={<span className="chip">{users.length} users</span>} />
            <Link to="/audit" className="font-mono text-[9px] uppercase tracking-wider text-cyan hover:text-white">
              Review audit trail
            </Link>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px]">
              <thead className="table-head">
                <tr>
                  <th className="px-5 py-2.5 text-left">Operator</th>
                  <th className="px-3 py-2.5 text-left">Role</th>
                  <th className="px-3 py-2.5 text-left">Status</th>
                  <th className="px-3 py-2.5 text-left">Last sign-in</th>
                  <th className="px-5 py-2.5 text-right">Controls</th>
                </tr>
              </thead>
              <tbody>
                {users.map((operator) => (
                  <tr key={operator.id} className="table-row">
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-2.5">
                        <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-gradient-to-br from-cyan/25 to-violet/30 font-mono text-[9px] text-white">
                          {initials(operator.name)}
                        </span>
                        <div className="min-w-0">
                          <p className="truncate text-[11px] text-ice">
                            {operator.name} {operator.id === user.id ? <span className="font-mono text-[8px] text-cyan">(you)</span> : null}
                          </p>
                          <p className="truncate font-mono text-[9px] text-slate-600">{operator.email}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-3 py-3">
                      <select
                        value={operator.role}
                        disabled={userBusy === operator.id}
                        onChange={(event) => void updateUser(operator, { role: event.target.value })}
                        className="input w-auto py-1.5 text-[10px]"
                        aria-label={`Role for ${operator.name}`}
                      >
                        {["admin", "analyst", "viewer"].map((role) => (
                          <option key={role} value={role}>
                            {role}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td className="px-3 py-3">
                      <span className={cn("chip", operator.is_active ? "border-neon/25 text-neon" : "border-crimson/25 text-crimson")}>
                        {operator.is_active ? "active" : "disabled"}
                      </span>
                    </td>
                    <td className="px-3 py-3 font-mono text-[9px] text-slate-600">
                      {operator.last_login_at ? formatDate(operator.last_login_at) : "never"}
                    </td>
                    <td className="px-5 py-3 text-right">
                      <button
                        className={cn("btn-sm", operator.is_active ? "btn-ghost" : "btn-neon")}
                        disabled={userBusy === operator.id}
                        onClick={() => void updateUser(operator, { is_active: !operator.is_active })}
                      >
                        {userBusy === operator.id ? <Loader2 size={12} className="animate-spin" /> : operator.is_active ? <Users size={12} /> : <CheckCircle2 size={12} />}
                        {operator.is_active ? "Disable" : "Enable"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex items-start gap-2 border-t border-line/60 px-5 py-3 text-[10px] leading-relaxed text-mist">
            <ShieldCheck size={13} className="mt-0.5 shrink-0 text-neon" />
            An administrator cannot remove their own administrator access or deactivate their own account.
          </div>
        </Panel>
      ) : null}

      <div className="mt-4 flex items-center gap-2 font-mono text-[9px] uppercase tracking-wider text-slate-600">
        <ShieldCheck size={12} className="text-neon/70" /> Account changes are audited · JWT session policy enforced
      </div>
    </div>
  );
}
