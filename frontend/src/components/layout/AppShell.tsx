import { useEffect, useState, type ReactNode } from "react";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";

export function AppShell({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
}) {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() =>
    typeof window !== "undefined" && window.localStorage.getItem("dy-masa-sidebar-collapsed") === "true",
  );

  useEffect(() => {
    window.localStorage.setItem("dy-masa-sidebar-collapsed", String(sidebarCollapsed));
  }, [sidebarCollapsed]);

  return (
    <div className="min-h-screen bg-background text-foreground flex font-sans">
      <Sidebar collapsed={sidebarCollapsed} onToggle={() => setSidebarCollapsed((value) => !value)} />
      <div className="flex-1 flex flex-col min-w-0 h-screen">
        <TopBar title={title} subtitle={subtitle} />
        <main className="flex-1 overflow-y-auto bg-background p-4 md:p-6 lg:p-8 space-y-6 md:space-y-8">
          {children}
        </main>
      </div>
    </div>
  );
}
