import { Shield, Globe, Building, Clock } from "lucide-react";
import Link from "next/link";
import type { Target } from "@/types";

interface TargetCardProps {
  target: Target;
}

export function TargetCard({ target }: TargetCardProps) {
  return (
    <Link
      href={`/targets/${target.id}`}
      className="block rounded-lg border border-slate-800 bg-slate-900/50 p-6 transition-all hover:border-slate-700 hover:bg-slate-800/50"
    >
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-slate-800">
            <Shield className="h-5 w-5 text-slate-400" />
          </div>
          <div>
            <h3 className="font-semibold text-slate-100">{target.name}</h3>
            <div className="mt-1 flex items-center gap-2 text-sm text-slate-400">
              <Globe className="h-3.5 w-3.5" />
              {target.domain}
            </div>
          </div>
        </div>
      </div>

      {target.company && (
        <div className="mt-4 flex items-center gap-2 text-sm text-slate-400">
          <Building className="h-3.5 w-3.5" />
          {target.company}
        </div>
      )}

      <div className="mt-4 flex items-center gap-2 text-xs text-slate-500">
        <Clock className="h-3 w-3" />
        Added {new Date(target.created_at).toLocaleDateString()}
      </div>
    </Link>
  );
}

export default TargetCard;