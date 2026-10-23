import { SEVERITY_HEX, SEVERITY_LABELS } from "../../lib/api";

export function SeverityDonut({ counts }: { counts: Record<string, number> }) {
  const total = SEVERITY_LABELS.reduce((sum, s) => sum + (counts[s] || 0), 0);
  const radius = 60;
  const circumference = 2 * Math.PI * radius;
  let offsetAcc = 0;

  return (
    <div className="flex items-center gap-6">
      <div className="relative w-[150px] h-[150px] shrink-0">
        <svg width="150" height="150" viewBox="0 0 150 150" className="-rotate-90">
          <circle cx="75" cy="75" r={radius} fill="none" stroke="#1e2a35" strokeWidth="16" />
          {total > 0 &&
            SEVERITY_LABELS.map((sev) => {
              const value = counts[sev] || 0;
              if (value === 0) return null;
              const fraction = value / total;
              const dash = fraction * circumference;
              const gap = circumference - dash;
              const el = (
                <circle
                  key={sev}
                  cx="75"
                  cy="75"
                  r={radius}
                  fill="none"
                  stroke={SEVERITY_HEX[sev]}
                  strokeWidth="16"
                  strokeDasharray={`${dash} ${gap}`}
                  strokeDashoffset={-offsetAcc}
                  strokeLinecap="butt"
                  className="transition-all duration-500"
                />
              );
              offsetAcc += dash;
              return el;
            })}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold leading-none">{total}</span>
          <span className="text-[10px] text-muted-foreground uppercase font-bold tracking-wide mt-1">Findings</span>
        </div>
      </div>

      <div className="flex flex-col gap-2">
        {SEVERITY_LABELS.map((sev) => (
          <div key={sev} className="flex items-center gap-2 text-sm">
            <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: SEVERITY_HEX[sev] }} />
            <span className="capitalize text-muted-foreground w-16">{sev}</span>
            <span className="font-bold font-mono">{counts[sev] || 0}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
