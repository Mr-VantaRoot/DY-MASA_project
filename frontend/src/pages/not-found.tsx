import { AlertCircle } from "lucide-react";

export default function NotFound() {
  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-background text-foreground">
      <div className="w-full max-w-md mx-4 rounded-lg border border-border bg-card p-6">
        <div className="flex mb-4 gap-2 items-center">
          <AlertCircle className="h-8 w-8 text-critical" />
          <h1 className="text-2xl font-bold">404 Page Not Found</h1>
        </div>
        <p className="mt-2 text-sm text-muted-foreground">
          This page doesn't exist. Head back to the dashboard.
        </p>
      </div>
    </div>
  );
}
