export function MetricCard({ label, value, accent, className = "" }: { label: string; value: string | number; accent: "neutral" | "critical" | "high" | "medium" | "info"; className?: string }) {
  const accentColors = {
    neutral: "border-t-accent",
    critical: "border-t-critical",
    high: "border-t-high",
    medium: "border-t-medium",
    info: "border-t-low",
  };

  const textColors = {
    neutral: "text-foreground",
    critical: "text-critical",
    high: "text-high",
    medium: "text-medium",
    info: "text-low",
  };

  return (
    <div className={`bg-card border border-border border-t-2 ${accentColors[accent]} rounded-lg p-4 flex flex-col justify-between hover:brightness-110 transition-all duration-150 ${className}`}>
      <span className="text-muted-foreground text-[10px] leading-tight font-bold uppercase tracking-wider">{label}</span>
      <strong className={`text-xl leading-none font-bold mt-1 ${textColors[accent]}`}>{value}</strong>
    </div>
  );
}
