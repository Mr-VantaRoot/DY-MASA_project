import { BrainCircuit, ArrowRight, Info } from "lucide-react";
import { AppShell } from "../components/layout/AppShell";
import { useJobStateContext } from "../contexts/JobStateContext";

type AttackPath = { title: string; steps: string[]; evidence_ids: string[] };

export function ReasoningPage() {
  const jobState = useJobStateContext();
  const { reasoning, reasoningRecords } = jobState;

  let attackPaths: AttackPath[] = [];
  if (reasoning) {
    try {
      attackPaths = JSON.parse(reasoning.attack_paths_json);
    } catch {
      attackPaths = [];
    }
  }

  return (
    <AppShell
      title="Structured Reasoning"
      subtitle={jobState.activeJob ? `Structured risk summary for ${jobState.activeJob.original_filename}` : "No active job"}
    >
      <div className="bg-card border border-border rounded-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-sm font-bold text-muted-foreground uppercase tracking-wide mb-1">
              Structured Risk Summary
            </h2>
            <h3 className="text-xl font-bold text-foreground">
              {reasoning ? reasoning.provider : "Awaiting analysis"}
            </h3>
            {reasoningRecords.length > 0 && (
              <p className="text-xs text-muted-foreground mt-1">
                Showing latest of {reasoningRecords.length} persisted reasoning record{reasoningRecords.length === 1 ? "" : "s"}.
              </p>
            )}
          </div>
          <BrainCircuit className="text-accent" size={28} />
        </div>

        {!reasoning ? (
          <p className="text-muted-foreground italic text-sm py-8 text-center">
            The structured reasoning summary will appear once evidence-backed findings are generated.
          </p>
        ) : (
          <>
            <blockquote className="border-l-4 border-accent pl-4 mb-6">
              <p className="text-sm text-foreground/90 leading-relaxed whitespace-pre-wrap">{reasoning.summary}</p>
            </blockquote>

            {reasoning.limitations && (
              <div className="flex gap-3 bg-secondary/40 border border-border rounded-lg p-4 text-xs text-muted-foreground">
                <Info size={16} className="shrink-0 mt-0.5 text-low" />
                <p>{reasoning.limitations}</p>
              </div>
            )}
          </>
        )}
      </div>

      <div>
        <h3 className="text-sm font-bold text-muted-foreground uppercase tracking-wide mb-4">
          Correlated & Validation Paths ({attackPaths.length})
        </h3>
        {attackPaths.length === 0 ? (
          <div className="bg-card border border-border rounded-xl p-10 flex flex-col items-center justify-center text-muted-foreground">
            <BrainCircuit size={40} className="mb-3 opacity-40" />
            <p className="text-sm">No attack paths generated yet for this job.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            {attackPaths.map((path, idx) => (
              <div key={idx} className="bg-card border border-border rounded-xl p-5">
                <h4 className="font-bold text-foreground text-sm mb-4">{path.title}</h4>
                <div className="flex flex-col gap-0">
                  {path.steps.map((step, stepIdx) => (
                    <div key={stepIdx} className="flex gap-3">
                      <div className="flex flex-col items-center">
                        <div className="w-6 h-6 rounded-full bg-accent/15 border border-accent/40 text-accent text-[10px] font-bold flex items-center justify-center shrink-0">
                          {stepIdx + 1}
                        </div>
                        {stepIdx < path.steps.length - 1 && <div className="w-px flex-1 bg-border my-1" />}
                      </div>
                      <p className="text-xs text-foreground/85 leading-relaxed pb-4">{step}</p>
                    </div>
                  ))}
                </div>
                {path.evidence_ids.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 mt-1 pt-3 border-t border-border">
                    {path.evidence_ids.map((id) => (
                      <span
                        key={id}
                        className="text-[10px] font-mono bg-[#060a0d] border border-border px-1.5 py-0.5 rounded text-accent flex items-center gap-1"
                      >
                        <ArrowRight size={9} /> {id}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </AppShell>
  );
}
