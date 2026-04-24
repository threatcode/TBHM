import { cn } from "@/lib/utils";
import { CheckCircle, XCircle, Clock, Loader, AlertCircle } from "lucide-react";
import type { Scan, ScanStatus } from "@/types";

interface ScanListProps {
  scans: Scan[];
  className?: string;
}

const statusConfig: Record<ScanStatus, { icon: typeof CheckCircle; color: string; label: string }> = {
  pending: { icon: Clock, color: "text-slate-400", label: "Pending" },
  running: { icon: Loader, color: "text-blue-400", label: "Running" },
  completed: { icon: CheckCircle, color: "text-green-400", label: "Completed" },
  failed: { icon: XCircle, color: "text-red-400", label: "Failed" },
  cancelled: { icon: AlertCircle, color: "text-yellow-400", label: "Cancelled" },
};

export function ScanList({ scans, className }: ScanListProps) {
  return (
    <div className={cn("space-y-2", className)}>
      {scans.map((scan) => {
        const config = statusConfig[scan.status];
        const Icon = config.icon;

        return (
          <div
            key={scan.id}
            className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900/30 p-4"
          >
            <div className="flex items-center gap-3">
              <Icon className={cn("h-5 w-5", config.color)} />
              <div>
                <p className="font-medium text-slate-200">
                  {scan.scan_type.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase())}
                </p>
                <p className="text-sm text-slate-400">{config.label}</p>
              </div>
            </div>

            <div className="text-right text-sm text-slate-400">
              {scan.completed_at
                ? new Date(scan.completed_at).toLocaleString()
                : scan.started_at
                ? "In progress..."
                : new Date(scan.created_at).toLocaleString()}
            </div>
          </div>
        );
      })}

      {scans.length === 0 && (
        <p className="py-8 text-center text-slate-500">No scans yet</p>
      )}
    </div>
  );
}

export default ScanList;