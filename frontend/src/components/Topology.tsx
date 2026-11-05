import { motion } from "framer-motion";
import { Network } from "lucide-react";
import { EmptyState } from "./ui";

type TopologyNode = {
  id: string;
  label: string;
  type?: string;
  risk?: string;
  open_ports?: number;
};

type TopologyEdge = { source: string; target: string };

const RISK_COLORS: Record<string, string> = {
  critical: "#FF3B5C",
  high: "#FF7A45",
  medium: "#FFB020",
  low: "#38BDF8",
  info: "#00E5FF",
};

const WIDTH = 840;
const HEIGHT = 330;

export function NetworkTopology({ topology }: { topology?: { nodes?: TopologyNode[]; edges?: TopologyEdge[] } }) {
  const nodes = topology?.nodes || [];
  const edges = topology?.edges || [];
  if (!nodes.length) {
    return (
      <EmptyState
        icon={Network}
        title="No topology recorded"
        description="Network assessments with at least one responsive host render an interactive topology here."
      />
    );
  }

  const byId = new Map(nodes.map((node) => [node.id, node]));
  const roots = nodes.filter((node) => node.type === "root");
  const hosts = nodes.filter((node) => node.type === "host");
  const services = nodes.filter((node) => node.type === "service");
  const other = nodes.filter((node) => !["root", "host", "service"].includes(node.type || ""));

  const positions = new Map<string, { x: number; y: number }>();
  roots.forEach((node, index) => {
    positions.set(node.id, { x: WIDTH / 2 + (index - (roots.length - 1) / 2) * 80, y: 42 });
  });

  const hostY = 155;
  const hostGap = hosts.length > 1 ? Math.min(220, (WIDTH - 160) / (hosts.length - 1)) : 0;
  const hostStart = WIDTH / 2 - ((hosts.length - 1) * hostGap) / 2;
  hosts.forEach((node, index) => {
    positions.set(node.id, { x: hostStart + index * hostGap, y: hostY });
  });

  other.forEach((node, index) => {
    positions.set(node.id, { x: 80 + ((index + 0.5) * (WIDTH - 160)) / Math.max(other.length, 1), y: 236 });
  });

  const childrenOf = new Map<string, TopologyNode[]>();
  edges.forEach((edge) => {
    const source = byId.get(edge.source);
    const target = byId.get(edge.target);
    if (source && target && target.type === "service") {
      const current = childrenOf.get(source.id) || [];
      current.push(target);
      childrenOf.set(source.id, current);
    }
  });

  const assigned = new Set<string>();
  hosts.forEach((host) => {
    const children = childrenOf.get(host.id) || [];
    const base = positions.get(host.id) || { x: WIDTH / 2, y: hostY };
    children.forEach((child, index) => {
      const offset = (index - (children.length - 1) / 2) * 76;
      positions.set(child.id, { x: Math.max(50, Math.min(WIDTH - 50, base.x + offset)), y: 272 });
      assigned.add(child.id);
    });
  });
  services.forEach((service, index) => {
    if (assigned.has(service.id)) return;
    const unassigned = services.filter((item) => !assigned.has(item.id));
    const slot = unassigned.indexOf(service);
    const total = Math.max(unassigned.length, 1);
    positions.set(service.id, {
      x: 60 + ((slot + 0.5) * (WIDTH - 120)) / total,
      y: 272 - Math.floor(index / 10) * 36,
    });
  });

  return (
    <div className="relative">
      <svg
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        className="h-auto w-full"
        role="img"
        aria-label="Assessment network topology"
      >
        <defs>
          <radialGradient id="topoGlow">
            <stop offset="0%" stopColor="#00E5FF" stopOpacity="0.22" />
            <stop offset="100%" stopColor="#00E5FF" stopOpacity="0" />
          </radialGradient>
        </defs>
        <circle cx={WIDTH / 2} cy={150} r={180} fill="url(#topoGlow)" opacity={0.5} />
        {edges.map((edge, index) => {
          const source = positions.get(edge.source);
          const target = positions.get(edge.target);
          if (!source || !target) return null;
          const midY = (source.y + target.y) / 2;
          return (
            <motion.path
              key={`${edge.source}-${edge.target}-${index}`}
              d={`M ${source.x} ${source.y} C ${source.x} ${midY}, ${target.x} ${midY}, ${target.x} ${target.y}`}
              stroke="#1E3A52"
              strokeWidth={1.1}
              fill="none"
              initial={{ pathLength: 0, opacity: 0 }}
              animate={{ pathLength: 1, opacity: 1 }}
              transition={{ duration: 0.7, delay: index * 0.035 }}
            />
          );
        })}
        {nodes.map((node) => {
          const position = positions.get(node.id);
          if (!position) return null;
          const color = RISK_COLORS[node.risk || "info"] || "#00E5FF";
          const isRoot = node.type === "root";
          const isHost = node.type === "host";
          return (
            <motion.g
              key={node.id}
              initial={{ opacity: 0, scale: 0.85 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.35 }}
              style={{ transformOrigin: `${position.x}px ${position.y}px` }}
            >
              <title>{node.label}</title>
              {isRoot ? (
                <circle cx={position.x} cy={position.y} r={19} fill={`${color}1A`} stroke={color} strokeWidth={1.2} />
              ) : isHost ? (
                <rect
                  x={position.x - 8}
                  y={position.y - 8}
                  width={16}
                  height={16}
                  rx={4}
                  fill={`${color}1A`}
                  stroke={color}
                  strokeWidth={1.4}
                />
              ) : (
                <circle cx={position.x} cy={position.y} r={5.5} fill={`${color}1A`} stroke={color} strokeWidth={1.2} />
              )}
              {isRoot ? (
                <>
                  <circle cx={position.x} cy={position.y} r={6} fill={color} />
                  <circle cx={position.x} cy={position.y} r={25} fill="none" stroke={color} strokeOpacity={0.25}>
                    <animate attributeName="r" values="20;32;20" dur="3.5s" repeatCount="indefinite" />
                    <animate attributeName="stroke-opacity" values="0.35;0;0.35" dur="3.5s" repeatCount="indefinite" />
                  </circle>
                </>
              ) : null}
              <text
                x={position.x}
                y={position.y + (isRoot || isHost ? 26 : 18)}
                textAnchor="middle"
                fill={isRoot ? "#FFFFFF" : isHost ? "#CBD5E1" : "#94A3B8"}
                fontSize={isRoot ? 10 : isHost ? 9.5 : 8.5}
                fontFamily="JetBrains Mono, monospace"
              >
                {node.label.length > 24 ? `${node.label.slice(0, 23)}…` : node.label}
              </text>
              {isHost && node.open_ports ? (
                <text
                  x={position.x}
                  y={position.y + 38}
                  textAnchor="middle"
                  fill={color}
                  fontSize={7.5}
                  fontFamily="JetBrains Mono, monospace"
                >
                  {node.open_ports} open
                </text>
              ) : null}
            </motion.g>
          );
        })}
      </svg>
      <div className="absolute bottom-1 right-2 flex items-center gap-3 font-mono text-[8px] uppercase tracking-wider text-mist">
        <span className="flex items-center gap-1">
          <span className="h-2 w-2 rounded-sm border border-cyan bg-cyan/20" /> Host
        </span>
        <span className="flex items-center gap-1">
          <span className="h-1.5 w-1.5 rounded-full border border-cyan bg-cyan/20" /> Service
        </span>
      </div>
    </div>
  );
}
