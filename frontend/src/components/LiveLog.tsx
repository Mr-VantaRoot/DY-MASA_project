import { useEffect, useRef } from "react";
import type { AnalysisJob } from "../types";

export function LiveLog({ liveLog, activeJob }: { liveLog: string[], activeJob: AnalysisJob | null }) {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [liveLog]);

  const isRunning = activeJob?.status === "running";

  return (
    <div className="bg-[#060a0d] border border-border rounded-xl overflow-hidden flex flex-col h-[400px]">
      <div className="flex items-center justify-between p-4 border-b border-[#1e2a35] bg-[#0a0e13]">
        <div className="flex items-center gap-3">
          <h2 className="text-xs font-bold text-muted-foreground uppercase tracking-wider">Live Output</h2>
          <span className={`w-2 h-2 rounded-full ${isRunning ? 'bg-[#00d4aa] blink-dot' : 'bg-gray-600'}`} />
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4 font-mono text-[0.78rem] leading-relaxed scanline" ref={scrollRef}>
        {liveLog.length === 0 ? (
          <p className="text-[#00d4aa]/50 italic">Waiting for tool output...</p>
        ) : (
          <div className="flex flex-col gap-1">
            {liveLog.map((line, i) => {
              const match = line.match(/^(\[\d{2}:\d{2}:\d{2}\])\s(.*)$/);
              const prefix = match ? match[1] : ">";
              const text = match ? match[2] : line;

              return (
                <div key={i} className={`flex gap-3 px-2 py-0.5 rounded ${i % 2 === 0 ? 'bg-transparent' : 'bg-white/[0.02]'}`}>
                  <span className="text-[#8fa2aa] shrink-0">{prefix}</span>
                  <span className="text-[#dbe7ea] break-all">{text}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
