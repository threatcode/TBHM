import { cn } from "@/lib/utils";
import { ExternalLink } from "lucide-react";
import SeverityBadge from "@/components/ui/SeverityBadge";
import type { Vulnerability } from "@/types";

interface VulnerabilitiesTableProps {
  vulnerabilities: Vulnerability[];
  className?: string;
}

export function VulnerabilitiesTable({
  vulnerabilities,
  className,
}: VulnerabilitiesTableProps) {
  return (
    <div className={cn("overflow-hidden rounded-lg border border-slate-800", className)}>
      <table className="w-full text-left">
        <thead className="bg-slate-900/50 text-xs uppercase text-slate-400">
          <tr>
            <th className="px-4 py-3 font-medium">Severity</th>
            <th className="px-4 py-3 font-medium">Vulnerability</th>
            <th className="px-4 py-3 font-medium">Location</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800">
          {vulnerabilities.map((vuln, index) => (
            <tr key={index} className="hover:bg-slate-800/30">
              <td className="px-4 py-3">
                <SeverityBadge severity={vuln.severity} />
              </td>
              <td className="px-4 py-3">
                <span className="font-medium text-slate-200">{vuln.name}</span>
                {vuln.description && (
                  <p className="mt-0.5 text-sm text-slate-400">{vuln.description}</p>
                )}
              </td>
              <td className="px-4 py-3">
                <div className="flex items-center gap-2">
                  <code className="text-sm text-slate-400">{vuln.matched_at}</code>
                  <ExternalLink className="h-3.5 w-3.5 cursor-pointer text-slate-500 hover:text-slate-300" />
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {vulnerabilities.length === 0 && (
        <p className="py-8 text-center text-slate-500">No vulnerabilities found</p>
      )}
    </div>
  );
}

export default VulnerabilitiesTable;