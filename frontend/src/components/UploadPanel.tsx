import { useState, useRef } from "react";
import { UploadCloud, CheckCircle2, Loader2, XCircle, Cpu } from "lucide-react";
import { API_BASE_URL, formatApiError } from "../lib/api";

export function UploadPanel({ onUploadComplete }: { onUploadComplete: (jobId: string) => void }) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ghidraEnabled, setGhidraEnabled] = useState(() =>
    typeof window !== "undefined" && window.localStorage.getItem("dy-masa-ghidra-enabled") === "true",
  );
  const abortRef = useRef<AbortController | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  function resetUpload() {
    abortRef.current?.abort();
    abortRef.current = null;
    setSelectedFile(null);
    setIsUploading(false);
    setError(null);
    if (inputRef.current) inputRef.current.value = "";
  }

  async function handleUpload(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedFile) return;

    const controller = new AbortController();
    abortRef.current = controller;
    setIsUploading(true);
    setError(null);
    const formData = new FormData();
    formData.append("apk", selectedFile);
    formData.append("ghidra_enabled", String(ghidraEnabled));

    try {
      const response = await fetch(`${API_BASE_URL}/jobs`, { method: "POST", body: formData, signal: controller.signal });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload.detail ?? "Upload failed.");
      }
      const created = await response.json();
      resetUpload();
      onUploadComplete(created.id);
    } catch (err) {
      if (controller.signal.aborted) return;
      setError(formatApiError(err, "Upload failed."));
    } finally {
      if (abortRef.current === controller) abortRef.current = null;
      setIsUploading(false);
    }
  }

  const borderClass = isUploading
    ? "border-accent uploading-border"
    : dragActive
      ? "border-accent bg-accent/5"
      : "border-border border-dashed hover:border-muted-foreground";

  return (
    <div className="p-5 flex flex-col">
      <h2 className="text-sm font-bold text-muted-foreground uppercase tracking-wide mb-4">Intake</h2>
      <form onSubmit={handleUpload} className="flex flex-col gap-4">
        <div
          className={`relative flex flex-col items-center justify-center p-6 rounded-lg border-2 transition-all duration-200 cursor-pointer ${borderClass}`}
          onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
          onDragLeave={() => setDragActive(false)}
          onDrop={(e) => { e.preventDefault(); setDragActive(false); setSelectedFile(e.dataTransfer.files?.[0] ?? null); }}
          onClick={() => inputRef.current?.click()}
        >
          {selectedFile ? (
            <>
              <CheckCircle2 size={32} className="text-accent mb-2" />
              <span className="text-sm font-semibold text-center break-all">{selectedFile.name}</span>
              <span className="text-xs text-muted-foreground mt-1">{(selectedFile.size / (1024*1024)).toFixed(2)} MB</span>
            </>
          ) : (
            <>
              <UploadCloud size={32} className={`text-accent mb-2 transition-transform duration-200 ${dragActive ? 'scale-110' : ''}`} />
              <span className="text-sm font-medium text-center">Drop APK here</span>
              <span className="text-xs text-muted-foreground mt-1 text-center">or click to browse</span>
            </>
          )}
          <input
            type="file"
            ref={inputRef}
            className="hidden"
            accept=".apk,application/vnd.android.package-archive"
            onChange={(e) => setSelectedFile(e.target.files?.[0] ?? null)}
          />
        </div>

        <label className="flex items-start gap-3 rounded-lg border border-border bg-secondary/30 px-3 py-3 cursor-pointer hover:border-accent/50 transition-colors">
          <input
            type="checkbox"
            checked={ghidraEnabled}
            onChange={(event) => {
              const enabled = event.target.checked;
              setGhidraEnabled(enabled);
              window.localStorage.setItem("dy-masa-ghidra-enabled", String(enabled));
            }}
            className="mt-1 accent-cyan-400"
          />
          <span className="min-w-0">
            <span className="flex items-center gap-2 text-xs font-bold text-foreground">
              <Cpu size={14} className="text-accent" />
              Ghidra native analysis
              <span className={`ml-auto text-[10px] uppercase tracking-wider ${ghidraEnabled ? "text-accent" : "text-muted-foreground"}`}>
                {ghidraEnabled ? "ON" : "OFF"}
              </span>
            </span>
            <span className="block text-[11px] text-muted-foreground mt-1">
              Optional ELF library analysis. Enabling it increases scan time and CPU/RAM usage.
            </span>
          </span>
        </label>

        <div className="flex gap-2">
          <button
            type="submit"
            disabled={!selectedFile || isUploading}
            className="flex-1 bg-accent text-accent-foreground font-bold py-2.5 rounded hover:brightness-110 active:scale-[0.97] transition-all disabled:opacity-50 disabled:pointer-events-none flex items-center justify-center gap-2"
          >
            {isUploading ? <Loader2 size={18} className="animate-spin" /> : <UploadCloud size={18} />}
            {isUploading ? "Uploading..." : "Start Analysis"}
          </button>
          {(selectedFile || isUploading) && (
            <button
              type="button"
              onClick={resetUpload}
              className="border border-critical/50 text-critical font-bold py-2.5 px-3 rounded hover:bg-critical/10 active:scale-[0.97] transition-all flex items-center justify-center"
              title="Drop this upload"
            >
              <XCircle size={18} />
            </button>
          )}
        </div>
        {error && <p className="text-critical text-xs font-semibold">{error}</p>}
      </form>
    </div>
  );
}
