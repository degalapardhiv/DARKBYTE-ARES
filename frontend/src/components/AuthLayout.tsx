import type { ReactNode } from "react";
import { motion } from "framer-motion";
import { Activity, Fingerprint, ShieldCheck, Terminal } from "lucide-react";
import { ImageWithFallback } from "./ImageWithFallback";
import { Logo } from "./Logo";
import { TAGLINE, TERMINAL_LINES } from "../lib/constants";

export function AuthLayout({
  children,
  eyebrow,
  title,
  description,
}: {
  children: ReactNode;
  eyebrow: string;
  title: string;
  description: string;
}) {
  return (
    <div className="relative min-h-screen overflow-hidden bg-void">
      <div className="grid min-h-screen lg:grid-cols-[1.05fr_0.95fr]">
        <div className="relative hidden overflow-hidden border-r border-line/70 lg:flex lg:flex-col lg:justify-between">
          <ImageWithFallback
            src="/assets/login-background.webp"
            alt="ARES security operations visualization"
            className="absolute inset-0 h-full w-full object-cover opacity-70"
            loading="eager"
          />
          <div className="absolute inset-0 bg-gradient-to-b from-void/70 via-void/40 to-void" />
          <div className="absolute inset-0 bg-grid-faint bg-grid opacity-40" />
          <div className="relative z-10 p-10 xl:p-14">
            <Logo showTagline />
            <div className="mt-16 max-w-lg">
              <motion.p
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                className="font-mono text-[10px] uppercase tracking-[0.3em] text-cyan"
              >
                Authorized operations platform
              </motion.p>
              <motion.h1
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.08 }}
                className="mt-4 text-balance text-4xl font-semibold leading-[1.08] tracking-tight text-white xl:text-5xl"
              >
                ONE FRAMEWORK.
                <br />
                <span className="bg-gradient-to-r from-cyan via-white to-violet bg-clip-text text-transparent">
                  COMPLETE RED TEAM
                </span>
                <br />
                OPERATIONS.
              </motion.h1>
              <motion.p
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.16 }}
                className="mt-5 max-w-md text-sm leading-relaxed text-mist"
              >
                Scoped reconnaissance, network inventory, application review, identity posture,
                vulnerability intelligence and detection engineering — under one immutable audit chain.
              </motion.p>
            </div>
          </div>

          <div className="relative z-10 p-10 xl:p-14">
            <div className="rounded-xl border border-cyan/15 bg-abyss/70 p-4 backdrop-blur-md">
              <div className="mb-2 flex items-center gap-2 font-mono text-[9px] uppercase tracking-[0.2em] text-cyan">
                <Terminal size={12} /> operator console
              </div>
              <div className="space-y-1">
                {TERMINAL_LINES.slice(0, 4).map((line, index) => (
                  <motion.p
                    key={line}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 0.25 + index * 0.12 }}
                    className="truncate font-mono text-[9px] text-mist/80"
                  >
                    <span className="text-neon">$</span> {line}
                  </motion.p>
                ))}
                <p className="font-mono text-[9px] text-cyan">
                  <span className="text-neon">$</span> <span className="animate-blink">▊</span>
                </p>
              </div>
            </div>
            <div className="mt-5 flex flex-wrap items-center gap-4 font-mono text-[8px] uppercase tracking-[0.18em] text-slate-500">
              <span className="flex items-center gap-1.5">
                <ShieldCheck size={11} className="text-neon" /> Authorization first
              </span>
              <span className="flex items-center gap-1.5">
                <Fingerprint size={11} className="text-cyan" /> Evidence hashing
              </span>
              <span className="flex items-center gap-1.5">
                <Activity size={11} className="text-violet" /> 10 modules
              </span>
            </div>
          </div>
        </div>

        <div className="relative flex min-h-screen flex-col">
          <div className="flex items-center justify-between border-b border-line/60 px-5 py-4 lg:hidden">
            <Logo showTagline={false} />
            <span className="chip border-neon/25 text-neon">AUTHORIZED</span>
          </div>
          <div className="flex flex-1 items-center justify-center px-5 py-10 sm:px-8">
            <motion.div
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4 }}
              className="w-full max-w-[420px]"
            >
              <p className="eyebrow mb-2">{eyebrow}</p>
              <h2 className="text-2xl font-semibold tracking-tight text-white">{title}</h2>
              <p className="mt-2 text-sm leading-relaxed text-mist">{description}</p>
              <div className="mt-8">{children}</div>
              <div className="mt-8 flex items-center justify-between border-t border-line/60 pt-4 font-mono text-[8px] uppercase tracking-[0.18em] text-slate-600">
                <span>{TAGLINE}</span>
                <span>v1.0.0</span>
              </div>
            </motion.div>
          </div>
        </div>
      </div>
    </div>
  );
}
