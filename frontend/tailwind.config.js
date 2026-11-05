/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        void: "#05070B",
        abyss: "#080B12",
        panel: "#0B111B",
        elevated: "#0F1724",
        line: "#162334",
        mist: "#94A3B8",
        ice: "#CBD5E1",
        cyan: { DEFAULT: "#00E5FF", dim: "#0891B2" },
        neon: { DEFAULT: "#00FF88", dim: "#059669" },
        crimson: { DEFAULT: "#FF3B5C", dim: "#BE123C" },
        violet: { DEFAULT: "#7C3AED", dim: "#5B21B6" },
        amber: { DEFAULT: "#FFB020", dim: "#B45309" },
      },
      fontFamily: {
        sans: ["Space Grotesk", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      boxShadow: {
        "glow-cyan": "0 0 0 1px rgba(0,229,255,0.22), 0 0 28px rgba(0,229,255,0.10)",
        "glow-neon": "0 0 0 1px rgba(0,255,136,0.22), 0 0 28px rgba(0,255,136,0.10)",
        "glow-crimson": "0 0 0 1px rgba(255,59,92,0.25), 0 0 30px rgba(255,59,92,0.12)",
        panel: "0 18px 50px rgba(0,0,0,0.35)",
      },
      backgroundImage: {
        "grid-faint":
          "linear-gradient(rgba(0,229,255,0.045) 1px, transparent 1px), linear-gradient(90deg, rgba(0,229,255,0.045) 1px, transparent 1px)",
        "radial-fade":
          "radial-gradient(circle at 50% 0%, rgba(0,229,255,0.10), transparent 55%)",
      },
      backgroundSize: {
        grid: "42px 42px",
      },
      keyframes: {
        scan: {
          "0%": { transform: "translateY(-100%)", opacity: "0" },
          "12%": { opacity: "0.5" },
          "100%": { transform: "translateY(100vh)", opacity: "0" },
        },
        shimmer: {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
        pulseGlow: {
          "0%, 100%": { opacity: "0.55" },
          "50%": { opacity: "1" },
        },
        blink: {
          "0%, 45%": { opacity: "1" },
          "46%, 100%": { opacity: "0" },
        },
        float: {
          "0%, 100%": { transform: "translateY(0)" },
          "50%": { transform: "translateY(-8px)" },
        },
        ticker: {
          "0%": { transform: "translateX(0)" },
          "100%": { transform: "translateX(-50%)" },
        },
      },
      animation: {
        scan: "scan 9s linear infinite",
        shimmer: "shimmer 2.2s linear infinite",
        pulseGlow: "pulseGlow 2.8s ease-in-out infinite",
        blink: "blink 1.1s step-end infinite",
        float: "float 6s ease-in-out infinite",
        ticker: "ticker 26s linear infinite",
      },
    },
  },
  plugins: [],
};
