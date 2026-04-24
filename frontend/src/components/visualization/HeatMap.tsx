"use client";

import { cn } from "@/lib/utils";
import { Flame } from "lucide-react";
import type { HeatMapData, Severity } from "@/types";

interface HeatMapProps {
  data: HeatMapData;
  className?: string;
}

export function HeatMap({ data, className }: HeatMapProps) {
  const severityLevels: Record<Severity, number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
  };

  const getHeatColor = (severity: Severity): string => {
    const level = severityLevels[severity];
    const colors = [
      "bg-blue-500/20",
      "bg-green-500/30",
      "bg-yellow-500/40",
      "bg-orange-500/50",
      "bg-red-500/60",
      "bg-red-600",
    ];
    return colors[level];
  };

  const categories = Object.keys(data.by_category).slice(0, 6);

  return (
    <div
      className={cn(
        "rounded-lg border border-slate-800 bg-slate-900/50 p-6",
        className
      )}
    >
      <div className="mb-4 flex items-center gap-2">
        <Flame className="h-5 w-5 text-orange-400" />
        <h3 className="text-lg font-semibold text-slate-100">Attack Surface Heat Map</h3>
      </div>

      <div className="mb-4 flex items-center gap-4">
        <div className="flex items-center gap-2">
          <div className="h-3 w-3 rounded-full bg-blue-500/40" />
          <span className="text-sm text-slate-400">Info</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="h-3 w-3 rounded-full bg-yellow-500/50" />
          <span className="text-sm text-slate-400">Medium</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="h-3 w-3 rounded-full bg-orange-500/60" />
          <span className="text-sm text-slate-400">High</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="h-3 w-3 rounded-full bg-red-500" />
          <span className="text-sm text-slate-400">Critical</span>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-3">
        {categories.map((category) => {
          const severity = (data.by_category[category] > 0 ? "medium" : "info") as Severity;
          return (
            <div
              key={category}
              className={cn(
                "rounded-lg p-4",
                getHeatColor(severity)
              )}
            >
              <p className="text-sm font-medium text-slate-200">{category}</p>
              <p className="mt-1 text-2xl font-bold text-slate-100">
                {data.by_category[category]}
              </p>
            </div>
          );
        })}
      </div>

      {data.high_risk_areas && data.high_risk_areas.length > 0 && (
        <div className="mt-6">
          <h4 className="mb-3 text-sm font-medium text-slate-300">High Risk Areas</h4>
          <div className="space-y-2">
            {data.high_risk_areas.slice(0, 5).map((area, index) => (
              <div
                key={index}
                className="flex items-center justify-between rounded bg-slate-800/50 px-3 py-2"
              >
                <span className="text-sm text-slate-300">{area.name}</span>
                <span
                  className={cn(
                    "rounded px-2 py-0.5 text-xs font-medium",
                    area.severity === "critical"
                      ? "bg-red-500/20 text-red-400"
                      : area.severity === "high"
                      ? "bg-orange-500/20 text-orange-400"
                      : "bg-yellow-500/20 text-yellow-400"
                  )}
                >
                  {area.severity}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default HeatMap;