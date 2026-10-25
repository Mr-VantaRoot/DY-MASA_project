import { useState } from "react";
import { Link, useLocation } from "wouter";
import { Menu, X } from "lucide-react";

const NAV_ITEMS = [
  { path: "/", label: "Overview" },
  { path: "/scan", label: "Scan" },
  { path: "/findings", label: "Findings" },
  { path: "/evidence", label: "Evidence" },
  { path: "/reasoning", label: "Structured Reasoning" },
  { path: "/dynamic", label: "DY-MASA" },
  { path: "/reports", label: "Reports" },
  { path: "/jobs", label: "Job History" },
  { path: "/terminal", label: "Terminal" },
  { path: "/health", label: "System Health" },
] as const;

export function MobileNav() {
  const [open, setOpen] = useState(false);
  const [location] = useLocation();

  return (
    <div className="md:hidden relative">
      <button
        onClick={() => setOpen(!open)}
        className="w-9 h-9 flex items-center justify-center rounded-lg border border-border bg-secondary text-foreground"
      >
        {open ? <X size={18} /> : <Menu size={18} />}
      </button>
      {open && (
        <div className="absolute top-11 left-0 z-50 w-56 bg-card border border-border rounded-lg shadow-xl p-2 flex flex-col gap-1">
          {NAV_ITEMS.map((item) => (
            <Link
              key={item.path}
              href={item.path}
              onClick={() => setOpen(false)}
              className={`px-3 py-2 rounded-md text-sm font-semibold ${
                location === item.path ? "bg-accent/10 text-accent" : "text-muted-foreground hover:bg-secondary"
              }`}
            >
              {item.label}
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
