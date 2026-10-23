import { useState, useRef, useEffect } from "react";
import { SquareTerminal, Loader2, TriangleAlert } from "lucide-react";
import { AppShell } from "../components/layout/AppShell";
import { runTerminalCommand } from "../lib/api";

type HistoryEntry = {
  command: string;
  output: string;
  exitCode: number;
  cwd: string;
};

const TERMINAL_HISTORY_KEY = "masa-terminal-history";
const TERMINAL_CWD_KEY = "masa-terminal-cwd";

function loadTerminalHistory(): HistoryEntry[] {
  try { return JSON.parse(localStorage.getItem(TERMINAL_HISTORY_KEY) || "[]") as HistoryEntry[]; } catch { return []; }
}

export function TerminalPage() {
  const [command, setCommand] = useState("");
  const [cwd, setCwd] = useState<string | undefined>(() => localStorage.getItem(TERMINAL_CWD_KEY) || undefined);
  const [previousCwd, setPreviousCwd] = useState<string | undefined>(undefined);
  const [history, setHistory] = useState<HistoryEntry[]>(loadTerminalHistory);
  const [isRunning, setIsRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    localStorage.setItem(TERMINAL_HISTORY_KEY, JSON.stringify(history));
  }, [history]);

  useEffect(() => {
    if (cwd) localStorage.setItem(TERMINAL_CWD_KEY, cwd);
  }, [cwd]);

  useEffect(() => {
    if (!isRunning) inputRef.current?.focus();
  }, [isRunning]);

  async function handleRun(e: React.FormEvent) {
    e.preventDefault();
    if (!command.trim() || isRunning) return;
    setIsRunning(true);
    setError(null);
    const submitted = command;
    setCommand("");
    if (["clear", "cls"].includes(submitted.trim().toLowerCase())) {
      setHistory([]);
      setPreviousCwd(cwd);
      setIsRunning(false);
      return;
    }
    try {
      const result = await runTerminalCommand(submitted, cwd, previousCwd);
      setPreviousCwd(cwd);
      setCwd(result.cwd);
      setHistory((h) => [...h, { command: submitted, output: result.output, exitCode: result.exit_code, cwd: result.cwd }]);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Command failed.";
      if (message.includes("Working directory") || message.includes("external system paths")) {
        localStorage.removeItem(TERMINAL_CWD_KEY);
        setCwd(undefined);
        setPreviousCwd(undefined);
        setError("The previous terminal directory was outside the allowed scope. Reset to the MASA project root; retry the command.");
      } else {
        setError(message);
      }
    } finally {
      setIsRunning(false);
    }
  }

  return (
    <AppShell title="Terminal" subtitle="Scoped local Bash terminal — runs directly on the analysis host">
      <div className="bg-[#3f1616]/40 border border-critical/30 rounded-lg p-4 flex items-start gap-3 text-xs text-critical">
        <TriangleAlert size={16} className="shrink-0 mt-0.5" />
        <p>
          This runs real shell commands on the machine hosting the backend. Use it only for authorized,
          local demo/debug purposes. It is disabled by default; enable it only with a private terminal token.
        </p>
      </div>

      <div className="bg-[#060a0d] border border-border rounded-xl overflow-hidden flex flex-col h-[560px]">
        <div className="flex items-center justify-between p-4 border-b border-[#1e2a35] bg-[#0a0e13]">
          <div className="flex items-center gap-3">
            <SquareTerminal size={16} className="text-accent" />
            <h2 className="text-xs font-bold text-muted-foreground uppercase tracking-wider">
              {cwd || "MASA project root"}
            </h2>
          </div>
          {isRunning && <Loader2 size={14} className="animate-spin text-accent" />}
        </div>

        <div className="flex-1 overflow-y-auto p-4 font-mono text-[0.8rem] leading-relaxed" ref={scrollRef}>
          {history.length === 0 ? (
            <p className="text-[#00d4aa]/50 italic">Type a command below and press Enter.</p>
          ) : (
            <div className="flex flex-col gap-4">
              {history.map((entry, i) => (
                <div key={i}>
                  <div className="flex gap-2 text-[#00d4aa]">
                    <span>&gt;</span>
                    <span>{entry.command}</span>
                  </div>
                  <pre className="text-[#dbe7ea] whitespace-pre-wrap break-all mt-1">{entry.output}</pre>
                  <div className={`text-[10px] mt-1 ${entry.exitCode === 0 ? "text-muted-foreground" : "text-critical"}`}>
                    exit code {entry.exitCode}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <form onSubmit={handleRun} className="flex items-center gap-2 p-4 border-t border-[#1e2a35] bg-[#0a0e13]">
          <span className="text-accent font-mono">&gt;</span>
          <input
            ref={inputRef}
            value={command}
            onChange={(e) => setCommand(e.target.value)}
            placeholder="e.g. curl http://127.0.0.1:8000/api/health"
            className="flex-1 bg-transparent outline-none font-mono text-sm text-foreground placeholder:text-muted-foreground"
            disabled={isRunning}
          />
          <button
            type="submit"
            disabled={isRunning || !command.trim()}
            className="bg-accent text-accent-foreground font-bold text-xs px-3 py-1.5 rounded disabled:opacity-40"
          >
            Run
          </button>
        </form>
      </div>

      {error && <p className="text-critical text-xs font-semibold">{error}</p>}
    </AppShell>
  );
}
