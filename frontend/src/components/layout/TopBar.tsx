import { ChevronDown, FileArchive } from "lucide-react";
import { useState } from "react";
import { useJobStateContext } from "../../contexts/JobStateContext";
import { MobileNav } from "./MobileNav";

export function TopBar({ title, subtitle }: { title: string; subtitle?: string }) {
  const jobState = useJobStateContext();
  const [pickerOpen, setPickerOpen] = useState(false);

  return (
    <header className="h-[72px] border-b border-border bg-card flex items-center justify-between px-4 md:px-6 shrink-0 gap-4">
      <div className="flex items-center gap-3 min-w-0">
        <MobileNav />
        <div className="flex flex-col min-w-0">
          <h2 className="text-base md:text-lg font-bold leading-tight truncate">{title}</h2>
          {subtitle && <span className="text-[11px] text-muted-foreground truncate">{subtitle}</span>}
        </div>
      </div>

      <div className="relative shrink-0">
        <button
          onClick={() => setPickerOpen(!pickerOpen)}
          className="flex items-center gap-2 bg-secondary hover:bg-secondary/70 transition-colors rounded-lg px-3 py-2 text-xs md:text-sm font-semibold max-w-[220px] md:max-w-[280px]"
        >
          <FileArchive size={14} className="text-accent shrink-0" />
          <span className="truncate">
            {jobState.activeJob ? jobState.activeJob.original_filename : "No job selected"}
          </span>
          <ChevronDown size={14} className="shrink-0 text-muted-foreground" />
        </button>
        {pickerOpen && (
          <div className="absolute right-0 top-11 z-50 w-72 max-h-80 overflow-y-auto bg-card border border-border rounded-lg shadow-xl p-2 flex flex-col gap-1">
            {jobState.jobs.length === 0 ? (
              <p className="text-xs text-muted-foreground p-3">No jobs yet. Upload an APK on the Scan tab.</p>
            ) : (
              jobState.jobs.map((job) => (
                <button
                  key={job.id}
                  onClick={() => {
                    jobState.setSelectedJobId(job.id);
                    setPickerOpen(false);
                  }}
                  className={`flex items-center gap-2 px-3 py-2 rounded-md text-left text-xs font-semibold ${
                    jobState.activeJob?.id === job.id
                      ? "bg-accent/10 text-accent"
                      : "text-foreground hover:bg-secondary"
                  }`}
                >
                  <span
                    className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                      job.status === "completed"
                        ? "bg-[#00d4aa]"
                        : job.status === "failed"
                        ? "bg-critical"
                        : job.status === "running"
                        ? "bg-low animate-pulse"
                        : "bg-gray-500"
                    }`}
                  />
                  <span className="truncate">{job.original_filename}</span>
                </button>
              ))
            )}
          </div>
        )}
      </div>
    </header>
  );
}
