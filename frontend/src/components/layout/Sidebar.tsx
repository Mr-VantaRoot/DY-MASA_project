import { Link, useLocation } from "wouter";
import {
  LayoutDashboard,
  UploadCloud,
  ShieldAlert,
  Database,
  BrainCircuit,
  FileText,
  History,
  SquareTerminal,
  HeartPulse,
  ShieldCheck,
  Activity,
  Radar,
  PanelLeftClose,
  PanelLeftOpen,
} from "lucide-react";
import { useJobStateContext } from "../../contexts/JobStateContext";

const NAV_ITEMS = [
  { path: "/", label: "Overview", icon: LayoutDashboard },
  { path: "/scan", label: "Scan", icon: UploadCloud },
  { path: "/findings", label: "Findings", icon: ShieldAlert },
  { path: "/evidence", label: "Evidence", icon: Database },
  { path: "/reasoning", label: "Structured Reasoning", icon: BrainCircuit },
  { path: "/dynamic", label: "DY-MASA", icon: Radar },
  { path: "/reports", label: "Reports", icon: FileText },
  { path: "/jobs", label: "Job History", icon: History },
  { path: "/terminal", label: "Terminal", icon: SquareTerminal },
  { path: "/health", label: "System Health", icon: HeartPulse },
] as const;

export function Sidebar({ collapsed, onToggle }: { collapsed: boolean; onToggle: () => void }) {
  const [location] = useLocation();
  const jobState = useJobStateContext();

  const criticalCount = jobState.findings.filter((f) => f.severity === "critical").length;

  return (
    <aside className={`${collapsed ? "w-[72px]" : "w-[240px]"} relative transition-[width] duration-200 shrink-0 h-full border-r border-border bg-sidebar flex flex-col hidden md:flex`}>
      <div className={`h-[72px] flex items-center ${collapsed ? "justify-center px-2" : "gap-3 px-5"} border-b border-border shrink-0`}>
        <img
          src={collapsed ? "/branding/masa-icon.png" : "/branding/masa-logo.png"}
          alt="MASA"
          className={`${collapsed ? "w-10 h-10" : "w-11 h-11"} object-contain shrink-0`}
        />
        {!collapsed && <div className="flex flex-col overflow-hidden">
          <h1 className="text-2xl font-bold leading-tight truncate">MASA</h1>
        </div>}
        {!collapsed && <button
          onClick={onToggle}
          aria-label="Collapse sidebar"
          title="Collapse sidebar"
          className="ml-auto w-8 h-8 flex items-center justify-center rounded-md text-muted-foreground hover:text-foreground hover:bg-secondary/70"
        >
          <PanelLeftClose size={17} />
        </button>}
        {collapsed && <button
          onClick={onToggle}
          aria-label="Expand sidebar"
          title="Expand sidebar"
          className="absolute left-[52px] top-5 w-8 h-8 flex items-center justify-center rounded-md border border-border bg-sidebar text-muted-foreground hover:text-foreground hover:bg-secondary/70"
        >
          <PanelLeftOpen size={17} />
        </button>}
      </div>

      <nav className={`flex-1 overflow-y-auto py-4 ${collapsed ? "px-2" : "px-3"} flex flex-col gap-1`}>
        {NAV_ITEMS.map(({ path, label, icon: Icon }) => {
          const isActive = location === path;
          const showBadge = path === "/findings" && criticalCount > 0;
          return (
            <Link
              key={path}
              href={path}
              title={collapsed ? label : undefined}
              className={`group relative flex items-center ${collapsed ? "justify-center px-3" : "gap-3 px-3"} py-2.5 rounded-lg text-sm font-semibold transition-all duration-150 ${
                isActive
                  ? "bg-accent/10 text-accent border border-accent/30"
                  : "text-muted-foreground border border-transparent hover:bg-secondary/60 hover:text-foreground"
              }`}
            >
              <Icon size={17} className={isActive ? "text-accent" : "group-hover:text-foreground"} />
              {!collapsed && <span className="truncate">{label}</span>}
              {isActive && <span className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-5 bg-accent rounded-r" />}
              {showBadge && (
                <span className="ml-auto bg-critical text-white text-[10px] font-bold px-1.5 py-0.5 rounded-full">
                  {criticalCount}
                </span>
              )}
            </Link>
          );
        })}
      </nav>

      <div className={`${collapsed ? "p-2" : "p-4"} border-t border-border shrink-0`}>
        <div
          className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-bold border ${
            jobState.isBackendConnected
              ? "bg-[#052e25] text-[#00d4aa] border-[#00d4aa]/40"
              : "bg-critical/10 text-critical border-critical/40"
          }`}
        >
          {jobState.isBackendConnected ? <ShieldCheck size={14} /> : <Activity size={14} />}
          {!collapsed && (jobState.isBackendConnected ? "Backend Connected" : "Backend Offline")}
        </div>
      </div>
    </aside>
  );
}
