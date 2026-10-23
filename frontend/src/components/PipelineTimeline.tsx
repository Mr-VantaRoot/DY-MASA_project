import { PIPELINE_STEPS } from "../lib/api";
import type { TimelineEntry, PipelineEvent, AnalysisJob } from "../types";
import { Check, Minus, X } from "lucide-react";

export function PipelineTimeline({ timeline, pipelineEvents, activeJob }: { timeline: TimelineEntry[], pipelineEvents: PipelineEvent[], activeJob: AnalysisJob | null }) {
  return (
    <div className="bg-card border border-border border-t-[3px] border-t-accent rounded-xl p-6 flex flex-col justify-between overflow-hidden">
      <div className="mb-6">
        <h2 className="text-sm font-bold text-muted-foreground uppercase tracking-wide mb-1">Execution Pipeline</h2>
        <h3 className="text-lg font-bold text-foreground">Live trace</h3>
      </div>

      <div className="flex items-start justify-between w-full relative pt-2 pb-4 overflow-x-auto min-h-[140px] scrollbar-hide">
        {/* Background connector line */}
        <div className="absolute top-[14px] left-[2%] right-[2%] h-[2px] bg-secondary z-0"></div>

        {PIPELINE_STEPS.map((step, index) => {
          const entry = timeline.find(t => t.stage === step.key);
          const liveEvent = [...pipelineEvents].reverse().find((event) => event.stage === step.key);
          const status = liveEvent?.status ?? entry?.status;
          const message = liveEvent?.message ?? entry?.message;
          const isCompleted = status === "completed";
          const isRunning = status === "running";
          const isFailed = status === "failed";
          const isSkipped = status === "skipped";

          let dotClass = "bg-[#1e2a35] border-2 border-card";
          let labelClass = "text-muted-foreground";
          let icon = null;

          if (isCompleted) {
            dotClass = "bg-accent border-2 border-card";
            labelClass = "text-foreground font-semibold";
            icon = <Check size={10} className="text-card font-bold" />;
          } else if (isRunning) {
            dotClass = "bg-accent border-2 border-card pulse-accent";
            labelClass = "text-accent font-semibold";
          } else if (isFailed) {
            dotClass = "bg-critical border-2 border-card";
            labelClass = "text-critical font-semibold";
            icon = <X size={10} className="text-card font-bold" />;
          } else if (isSkipped) {
            dotClass = "bg-secondary border-2 border-card";
            labelClass = "text-muted-foreground font-semibold";
            icon = <Minus size={10} className="text-muted-foreground font-bold" />;
          }

          // Active connecting line
          const prevEntry = index > 0 ? timeline.find(t => t.stage === PIPELINE_STEPS[index-1].key) : null;
          const lineActive = isCompleted || isRunning || isFailed;

          return (
            <div key={step.key} className="relative z-10 flex flex-col items-center flex-1 min-w-[90px]">
              <div className={`w-[20px] h-[20px] rounded-full flex items-center justify-center transition-all duration-300 z-10 relative ${dotClass}`}>
                 {icon}
              </div>
              <div className="mt-3 text-center w-full px-1">
                <p className={`text-[10px] sm:text-xs leading-tight transition-colors duration-300 ${labelClass}`}>
                  {step.label}
                </p>
                {isRunning && message && (
                  <p className="text-[9px] text-muted-foreground mt-1 w-full absolute left-0 text-center px-1 overflow-hidden" style={{display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical'}}>
                    {message}
                  </p>
                )}
              </div>
              {/* Active line fill to the left */}
              {index > 0 && (
                 <div className={`absolute top-[14px] right-[50%] h-[2px] w-full origin-left transition-transform duration-500 ease-in-out z-0 ${lineActive ? 'bg-accent scale-x-100' : 'bg-transparent scale-x-0'}`}></div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
