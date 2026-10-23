import { CheckCircle2, AlertCircle, Loader2, Clock3 } from "lucide-react";
import type { JobStatus } from "../types";

export function StatusPill({ status }: { status: JobStatus }) {
  let icon = <Clock3 size={14} />;
  let colorClass = "bg-gray-800 text-gray-300 border-gray-600";

  if (status === "completed") {
    icon = <CheckCircle2 size={14} />;
    colorClass = "bg-[#052e25] text-[#00d4aa] border-[#00d4aa]";
  } else if (status === "failed") {
    icon = <AlertCircle size={14} />;
    colorClass = "bg-[#3f1616] text-critical border-critical";
  } else if (status === "running") {
    icon = <Loader2 size={14} className="animate-spin" />;
    colorClass = "bg-[#0d2136] text-low border-low animate-[pulse_2s_infinite]";
  } else if (status === "cancelled") {
    icon = <AlertCircle size={14} />;
    colorClass = "bg-[#3f1616] text-critical border-critical";
  }

  return (
    <div className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold border ${colorClass} uppercase tracking-wide`}>
      {icon}
      {status}
    </div>
  );
}
