"use client";

import { Shield, AlertTriangle, CheckCircle, Activity } from "lucide-react";
import { cn } from "@/lib/utils";

interface RiskScoreProps {
  score: number;
  className?: string;
}

export function RiskScore({ score, className }: RiskScoreProps) {
  const getScoreColor = (score: number): string => {
    if (score >= 8) return "text-red-500";
    if (score >= 6) return "text-orange-500";
    if (score >= 4) return "text-yellow-500";
    return "text-green-500";
  };

  const getScoreLabel = (score: number): string => {
    if (score >= 8) return "Critical Risk";
    if (score >= 6) return "High Risk";
    if (score >= 4) return "Medium Risk";
    if (score >= 2) return "Low Risk";
    return "Minimal Risk";
  };

  const getScoreIcon = (score: number) => {
    if (score >= 8) return AlertTriangle;
    if (score >= 4) return Activity;
    return CheckCircle;
  };

  const Icon = getScoreIcon(score);

  return (
    <div
      className={cn(
        "flex items-center gap-6 rounded-lg border border-slate-800 bg-slate-900/50 p-6",
        className
      )}
    >
      <div
        className={cn(
          "flex h-16 w-16 items-center justify-center rounded-full border-4",
          getScoreColor(score),
          "border-current/20 bg-current/10"
        )}
      >
        <Shield className={cn("h-8 w-8", getScoreColor(score))} />
      </div>

      <div>
        <p className="text-sm text-slate-400">Overall Risk Score</p>
        <div className="mt-1 flex items-baseline gap-2">
          <span className={cn("text-4xl font-bold", getScoreColor(score))}>
            {score.toFixed(1)}
          </span>
          <span className="text-2xl font-bold text-slate-600">/10</span>
        </div>
        <p className={cn("mt-1 flex items-center gap-1 text-sm", getScoreColor(score))}>
          <Icon className="h-4 w-4" />
          {getScoreLabel(score)}
        </p>
      </div>

      <div className="ml-auto h-24 w-24">
        <svg viewBox="0 0 36 36" className="h-full w-full -rotate-90">
          <path
            d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
            fill="none"
            stroke="currentColor"
            strokeWidth="3"
            className="text-slate-800"
          />
          <path
            d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
            fill="none"
            stroke="currentColor"
            strokeWidth="3"
            strokeDasharray={`${(score / 10) * 100}, 100`}
            className={getScoreColor(score)}
          />
        </svg>
      </div>
    </div>
  );
}

export default RiskScore;