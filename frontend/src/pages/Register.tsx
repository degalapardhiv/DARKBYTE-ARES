import { useMemo, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Check, Eye, EyeOff, Loader2, Lock, Mail, ShieldAlert, User, UserPlus } from "lucide-react";
import { AuthLayout } from "../components/AuthLayout";
import { useAuth } from "../context/AuthContext";
import { ApiError } from "../lib/api";
import { cn } from "../lib/utils";

const RULES = [
  { key: "length", label: "At least 12 characters", test: (value: string) => value.length >= 12 },
  { key: "upper", label: "One uppercase letter", test: (value: string) => /[A-Z]/.test(value) },
  { key: "lower", label: "One lowercase letter", test: (value: string) => /[a-z]/.test(value) },
  { key: "digit", label: "One number", test: (value: string) => /\d/.test(value) },
  { key: "symbol", label: "One symbol", test: (value: string) => /[^A-Za-z0-9]/.test(value) },
];

export function Register() {
  const { signUp } = useAuth();
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const checks = useMemo(() => RULES.map((rule) => ({ ...rule, passed: rule.test(password) })), [password]);
  const validPassword = checks.every((check) => check.passed);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    if (!validPassword) {
      setError("Choose a password that satisfies every policy requirement.");
      return;
    }
    if (password !== confirm) {
      setError("Password confirmation does not match.");
      return;
    }
    if (!authorized) {
      setError("Confirm the authorized-use statement before requesting an account.");
      return;
    }
    setBusy(true);
    try {
      await signUp(email.trim(), name.trim(), password);
      navigate("/", { replace: true });
    } catch (reason) {
      setError(reason instanceof ApiError ? reason.message : "Registration failed. Verify the form and try again.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthLayout
      eyebrow="Operator onboarding"
      title="Request console access"
      description="Create a named operator identity. New accounts receive analyst permissions; an administrator can adjust roles later."
    >
      <form onSubmit={submit} className="space-y-4">
        <div>
          <label className="label" htmlFor="name">
            Full name
          </label>
          <div className="relative">
            <User size={15} className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              id="name"
              required
              minLength={2}
              autoComplete="name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              className="input pl-10"
              placeholder="Morgan Vale"
            />
          </div>
        </div>

        <div>
          <label className="label" htmlFor="email">
            Work email
          </label>
          <div className="relative">
            <Mail size={15} className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              id="email"
              type="email"
              required
              autoComplete="username"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              className="input pl-10"
              placeholder="you@your-organization.com"
            />
          </div>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label className="label" htmlFor="new-password">
              Password
            </label>
            <div className="relative">
              <Lock size={15} className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                id="new-password"
                type={showPassword ? "text" : "password"}
                required
                autoComplete="new-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                className="input px-10"
                placeholder="12+ characters"
              />
              <button
                type="button"
                onClick={() => setShowPassword((value) => !value)}
                className="absolute right-2 top-1/2 -translate-y-1/2 rounded-md p-1.5 text-mist transition hover:bg-white/5 hover:text-white"
                aria-label={showPassword ? "Hide password" : "Show password"}
              >
                {showPassword ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>
          </div>
          <div>
            <label className="label" htmlFor="confirm-password">
              Confirm password
            </label>
            <input
              id="confirm-password"
              type={showPassword ? "text" : "password"}
              required
              autoComplete="new-password"
              value={confirm}
              onChange={(event) => setConfirm(event.target.value)}
              className={cn(
                "input",
                confirm.length > 0 && confirm !== password && "border-crimson/50 focus:border-crimson/60",
              )}
              placeholder="Repeat password"
            />
          </div>
        </div>

        <div className="rounded-xl border border-line/70 bg-abyss/50 p-3.5">
          <p className="mb-2 font-mono text-[9px] uppercase tracking-[0.18em] text-mist">Password policy</p>
          <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
            {checks.map((check) => (
              <div key={check.key} className="flex items-center gap-2 text-[11px]">
                <span
                  className={cn(
                    "flex h-4 w-4 items-center justify-center rounded-full border transition",
                    check.passed ? "border-neon/40 bg-neon/10 text-neon" : "border-line text-slate-600",
                  )}
                >
                  <Check size={10} />
                </span>
                <span className={check.passed ? "text-ice" : "text-mist"}>{check.label}</span>
              </div>
            ))}
          </div>
        </div>

        <label className="flex cursor-pointer items-start gap-2.5 rounded-xl border border-line/70 bg-abyss/50 p-3">
          <input
            type="checkbox"
            checked={authorized}
            onChange={(event) => setAuthorized(event.target.checked)}
            className="mt-0.5 h-4 w-4 rounded border-line bg-abyss text-cyan focus:ring-cyan/40"
          />
          <span className="text-[11px] leading-relaxed text-mist">
            I will only use ARES against systems for which I hold{" "}
            <span className="text-ice">documented authorization</span>, and I will respect every scope and rate
            limit enforced by the platform.
          </span>
        </label>

        {error ? (
          <div className="flex items-start gap-2.5 rounded-xl border border-crimson/30 bg-crimson/10 px-3.5 py-3 text-xs leading-relaxed text-crimson">
            <ShieldAlert size={15} className="mt-0.5 shrink-0" />
            <span>{error}</span>
          </div>
        ) : null}

        <button type="submit" disabled={busy} className="btn-primary w-full py-3">
          {busy ? <Loader2 size={16} className="animate-spin" /> : <UserPlus size={16} />}
          {busy ? "Creating operator…" : "Create operator account"}
        </button>
      </form>

      <p className="mt-7 text-center text-xs text-mist">
        Already registered?{" "}
        <Link to="/login" className="text-cyan underline-offset-4 transition hover:underline">
          Return to sign in
        </Link>
      </p>
    </AuthLayout>
  );
}
