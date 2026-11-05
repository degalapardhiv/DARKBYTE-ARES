import {
  Area,
  Bar,
  CartesianGrid,
  Cell,
  ComposedChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { SEVERITY } from "../lib/constants";
import type { DashboardData, Severity } from "../lib/types";
import { moduleLabel, riskColor } from "../lib/utils";

function ChartTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-xl border border-line bg-abyss/95 px-3 py-2 shadow-panel backdrop-blur">
      <p className="mb-1 font-mono text-[9px] uppercase tracking-wider text-mist">{label}</p>
      {payload.map((entry: any) => (
        <p key={entry.dataKey} className="font-mono text-[11px]" style={{ color: entry.color || "#CBD5E1" }}>
          {entry.name}: {typeof entry.value === "number" ? entry.value.toFixed(entry.dataKey === "risk_score" ? 1 : 0) : entry.value}
        </p>
      ))}
    </div>
  );
}

export function RiskTrendChart({ data }: { data: DashboardData["risk_trend"] }) {
  const formatted = data.map((item) => ({
    ...item,
    day: item.date.slice(5),
    risk_score: item.risk_score ?? 0,
  }));
  return (
    <div className="h-56 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <ComposedChart data={formatted} margin={{ top: 8, right: 6, bottom: 0, left: -24 }}>
          <defs>
            <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#00E5FF" stopOpacity={0.35} />
              <stop offset="100%" stopColor="#00E5FF" stopOpacity={0.01} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#162334" vertical={false} />
          <XAxis dataKey="day" tick={{ fill: "#64748B", fontSize: 9, fontFamily: "JetBrains Mono" }} axisLine={false} tickLine={false} />
          <YAxis
            yAxisId="risk"
            domain={[0, 100]}
            tick={{ fill: "#64748B", fontSize: 9, fontFamily: "JetBrains Mono" }}
            axisLine={false}
            tickLine={false}
          />
          <YAxis yAxisId="count" orientation="right" hide />
          <Tooltip content={<ChartTooltip />} cursor={{ stroke: "#00E5FF33" }} />
          <Bar yAxisId="count" dataKey="assessments" name="Assessments" fill="#7C3AED" opacity={0.28} radius={[2, 2, 0, 0]} barSize={10} />
          <Area
            yAxisId="risk"
            type="monotone"
            dataKey="risk_score"
            name="Risk score"
            stroke="#00E5FF"
            strokeWidth={1.8}
            fill="url(#riskFill)"
            dot={{ r: 2, fill: "#00E5FF", strokeWidth: 0 }}
            activeDot={{ r: 4, fill: "#00E5FF", stroke: "#05070B", strokeWidth: 2 }}
          />
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  );
}

export function SeverityDonut({ data }: { data: DashboardData["severity"] }) {
  const total = data.reduce((sum, item) => sum + item.value, 0);
  return (
    <div className="relative h-56 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            innerRadius={60}
            outerRadius={82}
            paddingAngle={3}
            stroke="#0B111B"
            strokeWidth={2}
          >
            {data.map((item) => (
              <Cell key={item.name} fill={SEVERITY[item.name as Severity]?.color || "#64748B"} />
            ))}
          </Pie>
          <Tooltip content={<ChartTooltip />} />
        </PieChart>
      </ResponsiveContainer>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-mono text-2xl font-semibold text-white">{total}</span>
        <span className="font-mono text-[8px] uppercase tracking-[0.2em] text-mist">Findings</span>
      </div>
    </div>
  );
}

export function SeverityLegend({ data }: { data: DashboardData["severity"] }) {
  return (
    <div className="grid grid-cols-2 gap-x-3 gap-y-1.5">
      {data.map((item) => (
        <div key={item.name} className="flex items-center justify-between gap-2">
          <span className="flex items-center gap-1.5 text-[10px] capitalize text-mist">
            <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: SEVERITY[item.name as Severity]?.color }} />
            {item.name}
          </span>
          <span className="font-mono text-[10px] text-ice">{item.value}</span>
        </div>
      ))}
    </div>
  );
}

export function ModuleRiskChart({ data }: { data: DashboardData["modules"] }) {
  const rows = data
    .filter((item) => item.assessments > 0)
    .map((item) => ({ ...item, label: moduleLabel(item.module) }))
    .sort((a, b) => b.avg_risk - a.avg_risk)
    .slice(0, 7);
  if (!rows.length) {
    return <p className="py-12 text-center text-xs text-mist">No module activity yet.</p>;
  }
  return (
    <div className="h-56 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <ComposedChart data={rows} layout="vertical" margin={{ top: 4, right: 16, bottom: 0, left: 4 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#162334" horizontal={false} />
          <XAxis
            type="number"
            domain={[0, 100]}
            tick={{ fill: "#64748B", fontSize: 9, fontFamily: "JetBrains Mono" }}
            axisLine={false}
            tickLine={false}
          />
          <YAxis
            type="category"
            dataKey="label"
            width={118}
            tick={{ fill: "#94A3B8", fontSize: 9 }}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip content={<ChartTooltip />} cursor={{ fill: "#00E5FF08" }} />
          <Bar dataKey="avg_risk" name="Avg risk" radius={[0, 4, 4, 0]} barSize={12}>
            {rows.map((row) => (
              <Cell key={row.module} fill={riskColor(row.avg_risk)} />
            ))}
          </Bar>
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  );
}
