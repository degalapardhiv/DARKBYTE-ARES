import { useState, type FormEvent } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { Eye, EyeOff, KeyRound, Loader2, Lock, Mail, ShieldCheck, ShieldAlert } from "lucide-react";
import { AuthLayout } from "../components/AuthLayout";
import { useAuth } from "../context/AuthContext";
import { DEMO_CREDENTIALS } from "../lib/constants";
import { ApiError } from "../lib/api";

export function Login() {
  const { signIn } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as { from?: string } | null)?.from;
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    if (!authorized) {
      setError("Confirm that you hold explicit authorization for any system you assess.");
      return;
    }
    setBusy(true);
    try {
      await signIn(email.trim(), password);
      navigate(from && from !== "/login" ? from : "/", { replace: true });
    } catch (reason) {
      setError(reason instanceof ApiError ? reason.message : "Authentication failed. Verify your credentials and connection.");
    } finally {
      setBusy(false);
    }
  };

  const fillDemo = (role: "admin" | "analyst") => {
    const credentials = DEMO_CREDENTIALS[role];
    setEmail(credentials.email);
    setPassword(credentials.password);
    setAuthorized(true);
    setError(null);
  };

  return (
    <AuthLayout
      eyebrow="Operator access"
      title="Authenticate to ARES"
      description="Sign in to the authorized security operations console. All sessions and actions are recorded in the immutable audit chain."
    >
      <form onSubmit={submit} className="space-y-5">
        <div>
          <label className="label" htmlFor="email">
            Operator email
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
              placeholder="analyst@your-organization.com"
            />
          </div>
        </div>

        <div>
          <div className="flex items-center justify-between">
            <label className="label" htmlFor="password">
              Password
            </label>
            <span className="mb-1.5 font-mono text-[9px] uppercase tracking-wider text-slate-600">JWT · 60 min</span>
          </div>
          <div className="relative">
            <Lock size={15} className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              id="password"
              type={showPassword ? "text" : "password"}
              required
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              className="input px-10"
              placeholder="Enter your password"
            />
            <button
              type="button"
              onClick={() => setShowPassword((value) => !value)}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded-md p-1.5 text-mist transition hover:bg-white/5 hover:text-white"
              aria-label={showPassword ? "Hide password" : "Show password"}
            >
              {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
            </button>
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
            I confirm I have <span className="text-ice">explicit written authorization</span> for every system I
            assess through ARES, and I will operate within the approved scope.
          </span>
        </label>

        {error ? (
          <div className="flex items-start gap-2.5 rounded-xl border border-crimson/30 bg-crimson/10 px-3.5 py-3 text-xs leading-relaxed text-crimson">
            <ShieldAlert size={15} className="mt-0.5 shrink-0" />
            <span>{error}</span>
          </div>
        ) : null}

        <button type="submit" disabled={busy} className="btn-primary w-full py-3">
          {busy ? <Loader2 size={16} className="animate-spin" /> : <KeyRound size={16} />}
          {busy ? "Establishing session…" : "Sign in to console"}
        </button>

        <div className="relative py-1">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-line/60" />
          </div>
          <div className="relative flex justify-center">
            <span className="bg-void px-3 font-mono text-[9px] uppercase tracking-[0.2em] text-slate-600">
              demo dataset
            </span>
          </div>
        </div>

        <div className="grid gap-2 sm:grid-cols-2">
          <button type="button" onClick={() => fillDemo("admin")} className="btn-ghost btn-sm justify-start">
            <span className="h-1.5 w-1.5 rounded-full bg-crimson shadow-[0_0_8px_#FF3B5C]" />
            Fill admin demo
          </button>
          <button type="button" onClick={() => fillDemo("analyst")} className="btn-ghost btn-sm justify-start">
            <span className="h-1.5 w-1.5 rounded-full bg-cyan shadow-[0_0_8px_#00E5FF]" />
            Fill analyst demo
          </button>
        </div>

        <p className="flex items-start gap-2 font-mono text-[9px] leading-relaxed text-slate-600">
          <ShieldCheck size={12} className="mt-0.5 shrink-0 text-neon/60" />
          Demo accounts exist only when DEMO_MODE is enabled. Demonstration records are clearly labelled
          and rejected in production.
        </p>
      </form>

      <p className="mt-7 text-center text-xs text-mist">
        Need a new operator account?{" "}
        <Link to="/register" className="text-cyan underline-offset-4 transition hover:underline">
          Request registration
        </Link>
      </p>
    </AuthLayout>
  );
}
