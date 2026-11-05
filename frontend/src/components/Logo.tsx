import { ImageWithFallback } from "./ImageWithFallback";
import { cn } from "../lib/utils";

export function Logo({
  compact = false,
  className,
  showTagline = true,
}: {
  compact?: boolean;
  className?: string;
  showTagline?: boolean;
}) {
  return (
    <div className={cn("flex items-center gap-3", className)}>
      <div className="relative shrink-0">
        <div className="absolute inset-0 rounded-xl bg-cyan/20 blur-md" aria-hidden="true" />
        <ImageWithFallback
          src="/assets/ares-icon.png"
          alt="DARKBYTE ARES icon"
          className="relative h-10 w-10 rounded-xl border border-cyan/30 object-cover shadow-glow-cyan"
          fallbackSrc="/assets/ares-logo.png"
          loading="eager"
        />
      </div>
      {!compact ? (
        <div className="min-w-0 leading-none">
          <div className="flex items-baseline gap-1.5">
            <span className="text-[15px] font-bold tracking-[0.16em] text-white">DARKBYTE</span>
            <span className="text-[15px] font-bold tracking-[0.16em] text-cyan">ARES</span>
          </div>
          {showTagline ? (
            <p className="mt-1 font-mono text-[8px] uppercase tracking-[0.22em] text-mist">Security Operations</p>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
