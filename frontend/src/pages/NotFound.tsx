import { Link } from "react-router-dom";
import { ArrowLeft, Radar, ShieldAlert } from "lucide-react";
import { Logo } from "../components/Logo";

export function NotFound() {
  return (
    <div className="relative flex min-h-[70vh] flex-col items-center justify-center overflow-hidden text-center">
      <div className="absolute inset-0 bg-radial-fade" aria-hidden="true" />
      <div className="relative">
        <Logo className="mb-10 justify-center" />
        <p className="font-mono text-[10px] uppercase tracking-[0.32em] text-cyan/70">Signal lost</p>
        <h1 className="mt-4 font-mono text-7xl font-bold tracking-tight text-white md:text-8xl">
          4<span className="text-crimson">0</span>4
        </h1>
        <p className="mx-auto mt-5 max-w-md text-sm leading-relaxed text-mist">
          The requested console route does not exist or has been decommissioned. Verify the
          destination and return to the command dashboard.
        </p>
        <div className="mt-8 flex flex-wrap justify-center gap-3">
          <Link to="/" className="btn-primary">
            <ArrowLeft size={15} /> Return to dashboard
          </Link>
          <Link to="/assessments" className="btn-ghost">
            <Radar size={15} /> Assessments
          </Link>
        </div>
        <div className="mt-12 flex items-center justify-center gap-2 font-mono text-[9px] uppercase tracking-[0.2em] text-slate-600">
          <ShieldAlert size={12} className="text-amber/70" /> Authorized operations console
        </div>
      </div>
    </div>
  );
}
