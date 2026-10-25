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

export function Sidebar() {
  const [location] = useLocation();
  const jobState = useJobStateContext();

  const criticalCount = jobState.findings.filter((f) => f.severity === "critical").length;

  return (
    <aside className="w-[240px] shrink-0 h-full border-r border-border bg-sidebar flex flex-col hidden md:flex">
      <div className="h-[72px] flex items-center gap-3 px-5 border-b border-border shrink-0">
        <div className="w-9 h-9 bg-accent text-accent-foreground rounded flex items-center justify-center font-bold text-lg shrink-0">
          M
        </div>
        <div className="flex flex-col overflow-hidden">
          <h1 className="text-base font-bold leading-tight truncate">MASA</h1>
          <span className="text-[9px] text-muted-foreground uppercase font-bold tracking-widest truncate">
            Mobile App Security
          </span>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto py-4 px-3 flex flex-col gap-1">
        {NAV_ITEMS.map(({ path, label, icon: Icon }) => {
          const isActive = location === path;
          const showBadge = path === "/findings" && criticalCount > 0;
          return (
            <Link
              key={path}
              href={path}
              className={`group relative flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-semibold transition-all duration-150 ${
                isActive
                  ? "bg-accent/10 text-accent border border-accent/30"
                  : "text-muted-foreground border border-transparent hover:bg-secondary/60 hover:text-foreground"
              }`}
            >
              <Icon size={17} className={isActive ? "text-accent" : "group-hover:text-foreground"} />
              <span className="truncate">{label}</span>
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

      <div className="p-4 border-t border-border shrink-0">
        <div
          className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-bold border ${
            jobState.isBackendConnected
              ? "bg-[#052e25] text-[#00d4aa] border-[#00d4aa]/40"
              : "bg-critical/10 text-critical border-critical/40"
          }`}
        >
          {jobState.isBackendConnected ? <ShieldCheck size={14} /> : <Activity size={14} />}
          {jobState.isBackendConnected ? "Backend Connected" : "Backend Offline"}
        </div>
      </div>
    </aside>
  );
}
