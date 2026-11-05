import { motion } from "framer-motion";
import type { ReactNode } from "react";
import { cn } from "../lib/utils";

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
  className,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: -8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35 }}
      className={cn("mb-6 flex flex-col gap-4 md:flex-row md:items-end md:justify-between", className)}
    >
      <div className="min-w-0">
        {eyebrow ? <p className="eyebrow mb-2">{eyebrow}</p> : null}
        <h1 className="text-balance text-2xl font-semibold tracking-tight text-white md:text-[28px]">{title}</h1>
        {description ? <p className="mt-2 max-w-3xl text-sm leading-relaxed text-mist">{description}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </motion.div>
  );
}
