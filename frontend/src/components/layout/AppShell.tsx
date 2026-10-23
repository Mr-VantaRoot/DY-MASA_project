import type { ReactNode } from "react";
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
  return (
    <div className="min-h-screen bg-background text-foreground flex font-sans">
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0 h-screen">
        <TopBar title={title} subtitle={subtitle} />
        <main className="flex-1 overflow-y-auto bg-background p-4 md:p-6 lg:p-8 space-y-6 md:space-y-8">
          {children}
        </main>
      </div>
    </div>
  );
}
