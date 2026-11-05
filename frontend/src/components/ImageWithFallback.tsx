import { useEffect, useState } from "react";
import { ImageOff } from "lucide-react";
import { cn } from "../lib/utils";

type ImageWithFallbackProps = {
  src: string;
  alt: string;
  className?: string;
  fallbackSrc?: string;
  loading?: "lazy" | "eager";
};

/**
 * Reusable image wrapper: retries with a known-good asset, then renders a
 * branded placeholder instead of a broken image icon.
 */
export function ImageWithFallback({
  src,
  alt,
  className,
  fallbackSrc = "/assets/ares-logo.png",
  loading = "lazy",
}: ImageWithFallbackProps) {
  const [currentSrc, setCurrentSrc] = useState(src);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    setCurrentSrc(src);
    setFailed(false);
  }, [src]);

  if (failed) {
    return (
      <div
        className={cn(
          "flex items-center justify-center overflow-hidden border border-line bg-gradient-to-br from-abyss via-panel to-void",
          className,
        )}
        role="img"
        aria-label={alt}
      >
        <div className="flex flex-col items-center gap-2 p-4 text-center">
          <ImageOff size={24} className="text-cyan/60" />
          <span className="font-mono text-[9px] uppercase tracking-[0.2em] text-mist">{alt}</span>
        </div>
      </div>
    );
  }

  return (
    <img
      src={currentSrc}
      alt={alt}
      loading={loading}
      className={className}
      onError={() => {
        if (currentSrc !== fallbackSrc) setCurrentSrc(fallbackSrc);
        else setFailed(true);
      }}
    />
  );
}
