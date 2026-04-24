export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Target {
  id: string;
  name: string;
  domain: string;
  description?: string;
  company?: string;
  created_at: string;
  updated_at: string;
}

export interface Scan {
  id: string;
  target_id: string;
  scan_type: string;
  status: ScanStatus;
  task_id?: string;
  started_at?: string;
  completed_at?: string;
  results?: string;
  error_message?: string;
  created_at: string;
  updated_at: string;
}

export type ScanStatus = "pending" | "running" | "completed" | "failed" | "cancelled";

export interface Vulnerability {
  id: string;
  name: string;
  severity: Severity;
  matched_at: string;
  description?: string;
  reference?: string[];
}

export interface Subdomain {
  host: string;
  ip_addresses?: string[];
  http_ports?: number[];
  https_ports?: number[];
  tech_stack?: string[];
  is_live: boolean;
}

export interface Service {
  host: string;
  port: number;
  service: string;
  is_rdp?: boolean;
  is_smb?: boolean;
  is_ssh?: boolean;
  is_http?: boolean;
}

export interface HeatMapData {
  total_vulns: number;
  risk_score: number;
  by_severity: Record<Severity, number>;
  by_category: Record<string, number>;
  high_risk_areas: HighRiskArea[];
}

export interface HighRiskArea {
  name: string;
  severity: Severity;
  url: string;
}