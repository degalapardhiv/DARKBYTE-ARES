import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { AlertTriangle, CheckCircle2, Info, X, XCircle } from "lucide-react";
import { cn } from "../lib/utils";

type ToastTone = "success" | "error" | "info" | "warning";

type Toast = {
  id: number;
  title: string;
  message?: string;
  tone: ToastTone;
};

type ToastContextValue = {
  notify: (input: { title: string; message?: string; tone?: ToastTone }) => void;
};

const ToastContext = createContext<ToastContextValue | null>(null);

const TONES: Record<ToastTone, { icon: typeof Info; color: string; border: string }> = {
  success: { icon: CheckCircle2, color: "#00FF88", border: "rgba(0,255,136,0.35)" },
  error: { icon: XCircle, color: "#FF3B5C", border: "rgba(255,59,92,0.35)" },
  warning: { icon: AlertTriangle, color: "#FFB020", border: "rgba(255,176,32,0.35)" },
  info: { icon: Info, color: "#00E5FF", border: "rgba(0,229,255,0.35)" },
};

let nextToastId = 1;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const remove = useCallback((id: number) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const notify = useCallback(
    ({ title, message, tone = "info" }: { title: string; message?: string; tone?: ToastTone }) => {
      const id = nextToastId++;
      setToasts((current) => [...current.slice(-3), { id, title, message, tone }]);
      window.setTimeout(() => remove(id), 5200);
    },
    [remove],
  );

  const value = useMemo(() => ({ notify }), [notify]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="pointer-events-none fixed right-4 top-4 z-[100] flex w-[calc(100%-2rem)] max-w-sm flex-col gap-2">
        <AnimatePresence>
          {toasts.map((toast) => {
            const tone = TONES[toast.tone];
            const Icon = tone.icon;
            return (
              <motion.div
                key={toast.id}
                initial={{ opacity: 0, y: -12, scale: 0.97 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, x: 24, scale: 0.97 }}
                className="pointer-events-auto overflow-hidden rounded-xl border bg-panel/95 p-3.5 shadow-panel backdrop-blur-xl"
                style={{ borderColor: tone.border }}
              >
                <div className="flex items-start gap-3">
                  <Icon size={18} style={{ color: tone.color }} className="mt-0.5 shrink-0" />
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium text-white">{toast.title}</p>
                    {toast.message ? <p className="mt-1 text-xs leading-relaxed text-mist">{toast.message}</p> : null}
                  </div>
                  <button
                    onClick={() => remove(toast.id)}
                    className={cn("rounded-md p-1 text-mist transition hover:bg-white/5 hover:text-white")}
                    aria-label="Dismiss notification"
                  >
                    <X size={14} />
                  </button>
                </div>
              </motion.div>
            );
          })}
        </AnimatePresence>
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastContextValue {
  const context = useContext(ToastContext);
  if (!context) throw new Error("useToast must be used inside ToastProvider.");
  return context;
}
