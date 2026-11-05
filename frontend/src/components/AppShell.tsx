import { useEffect, useRef, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";
import {
  Bell,
  ChevronDown,
  ChevronLeft,
  Command,
  History,
  LogOut,
  Menu,
  Search,
  Settings,
  ShieldCheck,
  UserCog,
  X,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { api } from "../lib/api";
import { APP_NAME, NAV_GROUPS } from "../lib/constants";
import type { Notification } from "../lib/types";
import { cn, initials, timeAgo } from "../lib/utils";
import { Icon } from "./Icon";
import { Logo } from "./Logo";
import { DemoBadge } from "./Badges";

function useClickOutside(onOutside: () => void) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const listener = (event: MouseEvent) => {
      if (ref.current && !ref.current.contains(event.target as Node)) onOutside();
    };
    document.addEventListener("mousedown", listener);
    return () => document.removeEventListener("mousedown", listener);
  }, [onOutside]);
  return ref;
}

function Clock() {
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  return (
    <div className="hidden items-center gap-2 border-l border-line/70 pl-4 lg:flex">
      <div className="text-right leading-none">
        <p className="font-mono text-[11px] tracking-wider text-ice">
          {now.toISOString().slice(11, 19)}
          <span className="ml-1 text-[8px] text-mist">UTC</span>
        </p>
        <p className="mt-1 font-mono text-[8px] uppercase tracking-wider text-mist">
          {now.toISOString().slice(0, 10)}
        </p>
      </div>
      <span className="relative flex h-2 w-2">
        <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-neon opacity-60" />
        <span className="relative inline-flex h-2 w-2 rounded-full bg-neon" />
      </span>
    </div>
  );
}

function SidebarStatus({ collapsed }: { collapsed: boolean }) {
  const [health, setHealth] = useState<{ database: string; redis: string; queue_workers: number; demo_mode: boolean } | null>(null);
  useEffect(() => {
    let active = true;
    const load = () =>
      api.platform
        .health()
        .then((value) => active && setHealth(value))
        .catch(() => active && setHealth(null));
    load();
    const timer = window.setInterval(load, 45000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, []);

  if (collapsed) {
    return (
      <div className="flex justify-center py-3" title={health ? `Database ${health.database} · Queue ${health.queue_workers}` : "Status unavailable"}>
        <span className={cn("h-2 w-2 rounded-full", health?.database === "ok" ? "bg-neon shadow-[0_0_8px_#00FF88]" : "bg-crimson")} />
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-line/70 bg-abyss/60 p-3">
      <div className="mb-2 flex items-center justify-between">
        <span className="font-mono text-[8px] uppercase tracking-[0.2em] text-mist">System status</span>
        <span className="flex items-center gap-1 font-mono text-[8px] text-neon">
          <span className="h-1 w-1 animate-pulse rounded-full bg-neon" /> LIVE
        </span>
      </div>
      <div className="space-y-1.5">
        <div className="flex items-center justify-between font-mono text-[9px]">
          <span className="text-mist">Database</span>
          <span className={health?.database === "ok" ? "text-neon" : "text-crimson"}>{health?.database || "—"}</span>
        </div>
        <div className="flex items-center justify-between font-mono text-[9px]">
          <span className="text-mist">Queue</span>
          <span className="text-cyan">{health?.queue_workers ?? "—"} workers</span>
        </div>
        <div className="flex items-center justify-between font-mono text-[9px]">
          <span className="text-mist">Cache</span>
          <span className="text-ice">{health?.redis || "—"}</span>
        </div>
      </div>
      <div className="mt-2.5 border-t border-line/60 pt-2">
        <p className="font-mono text-[8px] uppercase tracking-[0.16em] text-amber/80">Authorized use only</p>
      </div>
    </div>
  );
}

function Sidebar({
  collapsed,
  setCollapsed,
  mobileOpen,
  setMobileOpen,
}: {
  collapsed: boolean;
  setCollapsed: (value: boolean) => void;
  mobileOpen: boolean;
  setMobileOpen: (value: boolean) => void;
}) {
  const location = useLocation();
  return (
    <>
      <AnimatePresence>
        {mobileOpen ? (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-40 bg-void/80 backdrop-blur-sm lg:hidden"
            onClick={() => setMobileOpen(false)}
          />
        ) : null}
      </AnimatePresence>
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-50 flex w-[264px] flex-col border-r border-line/70 bg-abyss/95 backdrop-blur-xl transition-all duration-300 lg:z-30",
          collapsed ? "lg:w-[82px]" : "lg:w-[264px]",
          mobileOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0",
        )}
      >
        <div className={cn("flex h-16 items-center border-b border-line/60 px-4", collapsed ? "justify-center" : "justify-between")}>
          <NavLink to="/" className="min-w-0" onClick={() => setMobileOpen(false)}>
            <Logo compact={collapsed} showTagline={!collapsed} />
          </NavLink>
          <button
            className="hidden rounded-lg border border-line p-1.5 text-mist transition hover:text-white lg:block"
            onClick={() => setCollapsed(!collapsed)}
            aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
          >
            <ChevronLeft size={14} className={cn("transition-transform", collapsed && "rotate-180")} />
          </button>
          <button className="rounded-lg border border-line p-1.5 text-mist lg:hidden" onClick={() => setMobileOpen(false)}>
            <X size={14} />
          </button>
        </div>

        <nav className="no-scrollbar flex-1 overflow-y-auto px-3 py-4">
          {NAV_GROUPS.map((group) => (
            <div key={group.label} className="mb-5">
              {!collapsed ? (
                <p className="mb-2 px-2 font-mono text-[8px] uppercase tracking-[0.24em] text-slate-600">{group.label}</p>
              ) : (
                <div className="mx-auto mb-3 h-px w-8 bg-line" />
              )}
              <div className="space-y-0.5">
                {group.items.map((item) => {
                  const isActive = item.end
                    ? location.pathname === item.path
                    : location.pathname === item.path || location.pathname.startsWith(`${item.path}/`);
                  return (
                    <NavLink
                      key={item.path}
                      to={item.path}
                      title={collapsed ? item.label : undefined}
                      onClick={() => setMobileOpen(false)}
                      className={cn(
                        "group flex items-center gap-3 rounded-lg border border-transparent px-2.5 py-2 text-[12.5px] text-mist transition-all",
                        collapsed && "justify-center px-2",
                        isActive ? "nav-active text-cyan" : "hover:bg-white/[0.035] hover:text-ice",
                      )}
                    >
                      <span className={cn("shrink-0", isActive ? "text-cyan" : "text-slate-500 group-hover:text-cyan/80")}>
                        <Icon name={item.icon} size={16} />
                      </span>
                      {!collapsed ? (
                        <>
                          <span className="truncate">{item.label}</span>
                          {item.badge ? (
                            <span className="ml-auto rounded border border-crimson/30 bg-crimson/10 px-1 py-0.5 font-mono text-[7px] text-crimson">
                              {item.badge}
                            </span>
                          ) : null}
                        </>
                      ) : null}
                    </NavLink>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        <div className="space-y-3 border-t border-line/60 p-3">
          <SidebarStatus collapsed={collapsed} />
          {!collapsed ? (
            <div className="flex items-center justify-between px-1 font-mono text-[8px] uppercase tracking-wider text-slate-600">
              <span>{APP_NAME}</span>
              <span>v1.0.0</span>
            </div>
          ) : null}
        </div>
      </aside>
    </>
  );
}

function NotificationBell() {
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState<Notification[]>([]);
  const [unread, setUnread] = useState(0);
  const navigate = useNavigate();
  const ref = useClickOutside(() => setOpen(false));

  const load = () =>
    api.notifications
      .list({ limit: 5 })
      .then((response) => {
        setItems(response.items);
        setUnread(response.unread);
      })
      .catch(() => undefined);

  useEffect(() => {
    load();
    const timer = window.setInterval(load, 45000);
    return () => window.clearInterval(timer);
  }, []);

  const onItem = async (item: Notification) => {
    if (!item.read) {
      try {
        await api.notifications.read(item.id);
        setItems((current) => current.map((entry) => (entry.id === item.id ? { ...entry, read: true } : entry)));
        setUnread((value) => Math.max(0, value - 1));
      } catch {
        // Navigation should still work if the read receipt fails.
      }
    }
    setOpen(false);
    navigate(item.link || "/notifications");
  };

  const onReadAll = async () => {
    await api.notifications.readAll();
    setItems((current) => current.map((entry) => ({ ...entry, read: true })));
    setUnread(0);
  };

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => {
          setOpen(!open);
          if (!open) load();
        }}
        className={cn(
          "relative rounded-xl border p-2.5 transition",
          open ? "border-cyan/30 bg-cyan/10 text-cyan" : "border-line bg-white/[0.02] text-mist hover:text-white",
        )}
        aria-label="Notifications"
      >
        <Bell size={16} />
        {unread > 0 ? (
          <span className="absolute -right-1 -top-1 flex h-4 min-w-4 items-center justify-center rounded-full border border-void bg-crimson px-1 font-mono text-[8px] font-bold text-white">
            {unread > 9 ? "9+" : unread}
          </span>
        ) : null}
      </button>
      <AnimatePresence>
        {open ? (
          <motion.div
            initial={{ opacity: 0, y: 8, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 6, scale: 0.98 }}
            className="absolute right-0 z-50 mt-2 w-[min(92vw,380px)] overflow-hidden rounded-xl border border-line bg-panel shadow-panel"
          >
            <div className="flex items-center justify-between border-b border-line/70 px-4 py-3">
              <div>
                <p className="text-xs font-medium text-white">Notifications</p>
                <p className="font-mono text-[9px] text-mist">{unread} unread alerts</p>
              </div>
              <button className="font-mono text-[9px] uppercase tracking-wider text-cyan hover:text-white" onClick={onReadAll}>
                Mark all read
              </button>
            </div>
            <div className="max-h-80 overflow-y-auto">
              {items.length ? (
                items.map((item) => (
                  <button
                    key={item.id}
                    onClick={() => onItem(item)}
                    className={cn(
                      "flex w-full items-start gap-3 border-b border-line/40 px-4 py-3 text-left transition hover:bg-white/[0.03]",
                      !item.read && "bg-cyan/[0.03]",
                    )}
                  >
                    <span
                      className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full"
                      style={{
                        backgroundColor:
                          item.level === "critical"
                            ? "#FF3B5C"
                            : item.level === "error"
                              ? "#FF3B5C"
                              : item.level === "success"
                                ? "#00FF88"
                                : item.level === "warning"
                                  ? "#FFB020"
                                  : "#00E5FF",
                      }}
                    />
                    <span className="min-w-0 flex-1">
                      <span className={cn("block truncate text-[11px]", item.read ? "text-mist" : "font-medium text-white")}>
                        {item.title}
                      </span>
                      <span className="mt-0.5 block line-clamp-2 text-[10px] leading-relaxed text-mist">{item.message}</span>
                      <span className="mt-1 block font-mono text-[8px] text-slate-600">{timeAgo(item.created_at)}</span>
                    </span>
                  </button>
                ))
              ) : (
                <p className="px-4 py-8 text-center text-xs text-mist">No notifications.</p>
              )}
            </div>
            <button
              onClick={() => {
                setOpen(false);
                navigate("/notifications");
              }}
              className="w-full border-t border-line/70 py-2.5 font-mono text-[9px] uppercase tracking-wider text-mist transition hover:bg-white/[0.03] hover:text-cyan"
            >
              View all notifications
            </button>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </div>
  );
}

function UserMenu() {
  const { user, signOut } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const ref = useClickOutside(() => setOpen(false));
  if (!user) return null;

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(!open)}
        className={cn(
          "flex items-center gap-2.5 rounded-xl border p-1.5 pr-2.5 transition",
          open ? "border-cyan/30 bg-cyan/5" : "border-line bg-white/[0.02] hover:border-white/15",
        )}
        aria-label="Account menu"
      >
        <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-gradient-to-br from-cyan/30 to-violet/40 font-mono text-[10px] font-bold text-white">
          {initials(user.name)}
        </span>
        <span className="hidden text-left md:block">
          <span className="block max-w-[120px] truncate text-[11px] font-medium text-white">{user.name}</span>
          <span className="block font-mono text-[8px] uppercase tracking-wider text-cyan/70">{user.role}</span>
        </span>
        <ChevronDown size={12} className={cn("text-mist transition", open && "rotate-180")} />
      </button>
      <AnimatePresence>
        {open ? (
          <motion.div
            initial={{ opacity: 0, y: 8, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 6, scale: 0.98 }}
            className="absolute right-0 z-50 mt-2 w-56 overflow-hidden rounded-xl border border-line bg-panel shadow-panel"
          >
            <div className="border-b border-line/70 px-4 py-3">
              <p className="truncate text-xs font-medium text-white">{user.name}</p>
              <p className="truncate font-mono text-[9px] text-mist">{user.email}</p>
              <div className="mt-2 flex items-center gap-2">
                <span className="chip border-cyan/25 bg-cyan/5 text-cyan">{user.role}</span>
                {user.preferences?.notifications ? <span className="chip text-neon">alerts on</span> : null}
              </div>
            </div>
            <div className="p-1.5">
              {[
                { label: "Account settings", icon: Settings, path: "/settings" },
                { label: "All notifications", icon: Bell, path: "/notifications" },
                ...(user.role === "admin"
                  ? [
                      { label: "Audit trail", icon: History, path: "/audit" },
                      { label: "Extensions", icon: UserCog, path: "/plugins" },
                    ]
                  : []),
              ].map((item) => {
                const IconComponent = item.icon;
                return (
                  <button
                    key={item.path}
                    onClick={() => {
                      setOpen(false);
                      navigate(item.path);
                    }}
                    className="flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left text-[11px] text-mist transition hover:bg-white/[0.04] hover:text-white"
                  >
                    <IconComponent size={14} /> {item.label}
                  </button>
                );
              })}
              <div className="my-1 h-px bg-line/60" />
              <button
                onClick={async () => {
                  setOpen(false);
                  await signOut();
                  navigate("/login");
                }}
                className="flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left text-[11px] text-crimson/80 transition hover:bg-crimson/5 hover:text-crimson"
              >
                <LogOut size={14} /> Sign out
              </button>
            </div>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </div>
  );
}

const EXTRA_COMMANDS = [
  { label: "Findings", path: "/findings", icon: "ShieldAlert", keywords: "vulnerabilities vulns triage" },
  { label: "Notifications", path: "/notifications", icon: "Bell", keywords: "alerts inbox" },
  { label: "Settings", path: "/settings", icon: "Settings", keywords: "profile password preferences account" },
  { label: "Audit trail", path: "/audit", icon: "History", keywords: "logs hash chain admin", admin: true },
  { label: "Extensions", path: "/plugins", icon: "Boxes", keywords: "plugins admin", admin: true },
];

function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [query, setQuery] = useState("");
  const navigate = useNavigate();
  const { user } = useAuth();
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setQuery("");
      window.setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [open]);

  const commands = [
    ...NAV_GROUPS.flatMap((group) =>
      group.items.map((item) => ({ label: item.label, path: item.path, icon: item.icon, keywords: group.label })),
    ),
    ...EXTRA_COMMANDS.filter((item) => !item.admin || user?.role === "admin"),
  ];

  const filtered = commands.filter((item) => {
    const haystack = `${item.label} ${item.keywords}`.toLowerCase();
    return haystack.includes(query.toLowerCase());
  });

  return (
    <AnimatePresence>
      {open ? (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-[95] flex items-start justify-center bg-void/80 p-4 pt-[12vh] backdrop-blur-sm"
          onClick={onClose}
        >
          <motion.div
            initial={{ opacity: 0, y: -12, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -8, scale: 0.98 }}
            className="w-full max-w-xl overflow-hidden rounded-2xl border border-cyan/20 bg-panel shadow-glow-cyan"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="flex items-center gap-3 border-b border-line/70 px-4 py-3.5">
              <Search size={16} className="text-cyan" />
              <input
                ref={inputRef}
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Escape") onClose();
                  if (event.key === "Enter" && filtered[0]) {
                    navigate(filtered[0].path);
                    onClose();
                  }
                }}
                placeholder="Jump to a page, module or tool…"
                className="flex-1 bg-transparent text-sm text-white placeholder:text-slate-600 focus:outline-none"
              />
              <span className="kbd hidden sm:inline">ESC</span>
            </div>
            <div className="max-h-80 overflow-y-auto p-2">
              {filtered.length ? (
                filtered.map((item) => (
                  <button
                    key={item.path}
                    onClick={() => {
                      navigate(item.path);
                      onClose();
                    }}
                    className="flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left transition hover:bg-cyan/[0.06]"
                  >
                    <Icon name={item.icon} size={15} className="text-cyan/70" />
                    <span className="text-xs text-ice">{item.label}</span>
                    <span className="ml-auto font-mono text-[9px] text-slate-600">{item.path}</span>
                  </button>
                ))
              ) : (
                <p className="px-3 py-8 text-center text-xs text-mist">No matching destination.</p>
              )}
            </div>
            <div className="flex items-center justify-between border-t border-line/70 px-4 py-2.5 font-mono text-[9px] text-slate-600">
              <span className="flex items-center gap-1.5">
                <Command size={11} /> K to open
              </span>
              <span>AUTHORIZED OPERATIONS CONSOLE</span>
            </div>
          </motion.div>
        </motion.div>
      ) : null}
    </AnimatePresence>
  );
}

function currentTitle(pathname: string): string {
  if (pathname === "/") return "Command Dashboard";
  const all = NAV_GROUPS.flatMap((group) => group.items);
  const exact = all.find((item) => item.path === pathname);
  if (exact) return exact.label;
  if (pathname.startsWith("/assessments/")) return "Assessment Detail";
  if (pathname === "/findings") return "Findings";
  if (pathname === "/notifications") return "Notifications";
  if (pathname === "/settings") return "Settings";
  if (pathname === "/audit") return "Audit Trail";
  if (pathname === "/plugins") return "Extensions";
  if (pathname.startsWith("/modules/")) return "Module Workspace";
  return "Console";
}

export function AppShell() {
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem("ares.sidebar") === "collapsed");
  const [mobileOpen, setMobileOpen] = useState(false);
  const [commandOpen, setCommandOpen] = useState(false);
  const [demoMode, setDemoMode] = useState(false);
  const location = useLocation();
  const title = currentTitle(location.pathname);

  useEffect(() => {
    localStorage.setItem("ares.sidebar", collapsed ? "collapsed" : "expanded");
  }, [collapsed]);

  useEffect(() => {
    api.platform
      .health()
      .then((health) => setDemoMode(health.demo_mode))
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setCommandOpen((value) => !value);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    setMobileOpen(false);
  }, [location.pathname]);

  return (
    <div className="min-h-screen">
      <Sidebar
        collapsed={collapsed}
        setCollapsed={setCollapsed}
        mobileOpen={mobileOpen}
        setMobileOpen={setMobileOpen}
      />
      <div className={cn("min-h-screen transition-all duration-300", collapsed ? "lg:pl-[82px]" : "lg:pl-[264px]")}>
        <header className="sticky top-0 z-30 flex h-16 items-center gap-3 border-b border-line/60 bg-void/75 px-4 backdrop-blur-xl md:px-6">
          <button
            className="rounded-lg border border-line p-2 text-mist lg:hidden"
            onClick={() => setMobileOpen(true)}
            aria-label="Open navigation"
          >
            <Menu size={16} />
          </button>
          <div className="min-w-0">
            <p className="font-mono text-[8px] uppercase tracking-[0.24em] text-slate-600">
              DARKBYTE ARES / {title}
            </p>
            <h2 className="mt-0.5 truncate text-sm font-medium text-white">{title}</h2>
          </div>
          {demoMode ? (
            <div className="ml-2 hidden sm:block">
              <DemoBadge compact />
            </div>
          ) : null}
          <div className="ml-auto flex items-center gap-2.5">
            <button
              onClick={() => setCommandOpen(true)}
              className="hidden items-center gap-2 rounded-xl border border-line bg-white/[0.02] px-3 py-2 text-mist transition hover:border-cyan/25 hover:text-ice md:flex"
            >
              <Search size={14} />
              <span className="text-[11px]">Search console</span>
              <span className="kbd ml-1">⌘K</span>
            </button>
            <Clock />
            <NotificationBell />
            <UserMenu />
          </div>
        </header>

        <main className="mx-auto w-full max-w-[1540px] px-4 py-6 md:px-6 lg:py-7">
          <motion.div
            key={location.pathname}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.25 }}
          >
            <Outlet />
          </motion.div>
        </main>
        <footer className="mx-auto flex w-full max-w-[1540px] flex-col gap-2 border-t border-line/50 px-4 py-4 font-mono text-[8px] uppercase tracking-wider text-slate-600 md:flex-row md:items-center md:justify-between md:px-6">
          <span>DARKBYTE ARES by DarkByteHunter · One framework. Complete red team operations.</span>
          <span className="flex items-center gap-3">
            <span className="flex items-center gap-1 text-neon">
              <ShieldCheck size={10} /> Authorized testing only
            </span>
            <span>Immutable audit active</span>
          </span>
        </footer>
      </div>

      <CommandPalette open={commandOpen} onClose={() => setCommandOpen(false)} />

      <button
        onClick={() => setCommandOpen(true)}
        className="fixed bottom-5 right-5 z-30 flex h-11 w-11 items-center justify-center rounded-full border border-cyan/30 bg-panel/90 text-cyan shadow-glow-cyan backdrop-blur md:hidden"
        aria-label="Open command palette"
      >
        <Search size={18} />
      </button>

      <div className="pointer-events-none fixed bottom-0 left-0 right-0 z-10 hidden overflow-hidden border-t border-cyan/10 bg-abyss/40 py-1.5 backdrop-blur-sm xl:block">
        <div className="flex w-[200%] animate-ticker gap-8 font-mono text-[8px] uppercase tracking-[0.18em] text-cyan/25">
          {Array.from({ length: 4 }).map((_, index) => (
            <span key={index} className="flex shrink-0 gap-8">
              <span>Scope verified</span>
              <span>Evidence hashed</span>
              <span>Audit chained</span>
              <span>Rate limits enforced</span>
              <span>Tabletop only</span>
              <span>Demo records labelled</span>
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
