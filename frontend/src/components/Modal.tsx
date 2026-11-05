import { useEffect, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { AnimatePresence, motion } from "framer-motion";
import { X } from "lucide-react";
import { cn } from "../lib/utils";

export function Modal({
  open,
  onClose,
  title,
  eyebrow,
  description,
  children,
  footer,
  size = "md",
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  eyebrow?: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
  size?: "sm" | "md" | "lg" | "xl";
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", onKey);
    return () => {
      document.body.style.overflow = previous;
      window.removeEventListener("keydown", onKey);
    };
  }, [open, onClose]);

  const width = {
    sm: "max-w-md",
    md: "max-w-xl",
    lg: "max-w-3xl",
    xl: "max-w-5xl",
  }[size];

  return createPortal(
    <AnimatePresence>
      {open ? (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-[90] flex items-center justify-center p-4"
        >
          <div className="absolute inset-0 bg-void/80 backdrop-blur-sm" onClick={onClose} aria-hidden="true" />
          <motion.div
            initial={{ opacity: 0, y: 18, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 12, scale: 0.98 }}
            transition={{ duration: 0.22 }}
            className={cn(
              "relative flex max-h-[90vh] w-full flex-col overflow-hidden rounded-2xl border border-line bg-panel shadow-panel",
              width,
            )}
            role="dialog"
            aria-modal="true"
            aria-label={title}
          >
            <div className="glow-line" />
            <div className="flex items-start justify-between gap-4 border-b border-line/70 px-5 py-4">
              <div className="min-w-0">
                {eyebrow ? <p className="eyebrow mb-1">{eyebrow}</p> : null}
                <h2 className="text-base font-semibold tracking-tight text-white">{title}</h2>
                {description ? <p className="mt-1 text-xs leading-relaxed text-mist">{description}</p> : null}
              </div>
              <button
                onClick={onClose}
                className="rounded-lg border border-line p-1.5 text-mist transition hover:border-white/20 hover:text-white"
                aria-label="Close dialog"
              >
                <X size={15} />
              </button>
            </div>
            <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">{children}</div>
            {footer ? <div className="flex items-center justify-end gap-2 border-t border-line/70 px-5 py-3.5">{footer}</div> : null}
          </motion.div>
        </motion.div>
      ) : null}
    </AnimatePresence>,
    document.body,
  );
}

export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel = "Confirm",
  danger = false,
  busy = false,
  onConfirm,
  onClose,
}: {
  open: boolean;
  title: string;
  description: string;
  confirmLabel?: string;
  danger?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  onClose: () => void;
}) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={title}
      size="sm"
      footer={
        <>
          <button className="btn-ghost btn-sm" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className={danger ? "btn-danger btn-sm" : "btn-primary btn-sm"} onClick={onConfirm} disabled={busy}>
            {busy ? "Working…" : confirmLabel}
          </button>
        </>
      }
    >
      <p className="text-sm leading-relaxed text-mist">{description}</p>
    </Modal>
  );
}
