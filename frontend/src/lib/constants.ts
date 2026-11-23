import type {
  AdminCategory,
  AuthObservation,
  AuthorizationStatus,
  FindingCategory,
  FindingStatus,
  RiskLevel,
  ScanStatus,
  Severity,
  VerificationStatus,
} from "./types";

export const SEVERITY_ORDER: Record<RiskLevel, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
  none: 5,
};

/** Hex colors for charts (Recharts needs concrete values). */
export const SEVERITY_HEX: Record<Severity, string> = {
  critical: "#f43f5e",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#38bdf8",
  info: "#64748b",
};

export const SEVERITY_CLASS: Record<RiskLevel, string> = {
  critical: "border-rose-500/40 bg-rose-500/15 text-rose-300",
  high: "border-orange-500/40 bg-orange-500/15 text-orange-300",
  medium: "border-amber-500/40 bg-amber-500/15 text-amber-300",
  low: "border-sky-500/40 bg-sky-500/15 text-sky-300",
  info: "border-slate-500/40 bg-slate-500/15 text-slate-300",
  none: "border-zinc-700 bg-zinc-800/60 text-zinc-400",
};

export const SEVERITY_DOT: Record<RiskLevel, string> = {
  critical: "bg-rose-500",
  high: "bg-orange-500",
  medium: "bg-amber-500",
  low: "bg-sky-400",
  info: "bg-slate-500",
  none: "bg-zinc-600",
};

export const FINDING_STATUS_CLASS: Record<FindingStatus, string> = {
  confirmed: "border-rose-500/40 bg-rose-500/10 text-rose-300",
  potential: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  informational: "border-sky-500/40 bg-sky-500/10 text-sky-300",
  false_positive: "border-zinc-600 bg-zinc-800/60 text-zinc-400 line-through decoration-zinc-500",
  not_tested: "border-dashed border-zinc-600 bg-transparent text-zinc-400",
};

export const FINDING_STATUS_LABEL: Record<FindingStatus, string> = {
  confirmed: "Confirmed",
  potential: "Potential",
  informational: "Informational",
  false_positive: "False positive",
  not_tested: "Not tested",
};

export const VERIFICATION_STATUS_LABEL: Record<VerificationStatus, string> = {
  unverified: "Unverified",
  verified: "Verified",
  false_positive: "False positive",
  accepted_risk: "Accepted risk",
  fixed: "Fixed",
};

export const VERIFICATION_STATUS_CLASS: Record<VerificationStatus, string> = {
  unverified: "border-zinc-700 bg-zinc-800/60 text-zinc-400",
  verified: "border-rose-500/30 bg-rose-500/10 text-rose-300",
  false_positive: "border-zinc-600 bg-zinc-800/60 text-zinc-400",
  accepted_risk: "border-violet-500/30 bg-violet-500/10 text-violet-300",
  fixed: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
};

export const AUTH_OBSERVATION_LABEL: Record<AuthObservation, string> = {
  public_content: "Public content",
  public_shell: "Public SPA shell",
  login_page: "Login page",
  redirect_to_login: "Redirects to login",
  unauthorized: "401 Unauthorized",
  forbidden: "403 Forbidden",
  not_found: "Not found",
  error: "Error",
  redirect_other: "Redirect (other)",
  not_tested: "Not tested",
};

export const AUTH_OBSERVATION_CLASS: Record<AuthObservation, string> = {
  public_content: "border-rose-500/40 bg-rose-500/10 text-rose-300",
  public_shell: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  login_page: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
  redirect_to_login: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
  unauthorized: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
  forbidden: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
  not_found: "border-zinc-700 bg-zinc-800/60 text-zinc-400",
  error: "border-orange-500/30 bg-orange-500/10 text-orange-300",
  redirect_other: "border-sky-500/30 bg-sky-500/10 text-sky-300",
  not_tested: "border-dashed border-zinc-600 bg-transparent text-zinc-400",
};

export const SCAN_STATUS_CLASS: Record<ScanStatus, string> = {
  queued: "border-zinc-600 bg-zinc-800/60 text-zinc-300",
  running: "border-sky-500/40 bg-sky-500/10 text-sky-300",
  completed: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
  failed: "border-rose-500/40 bg-rose-500/10 text-rose-300",
  cancelled: "border-zinc-600 bg-zinc-800/60 text-zinc-400",
  timed_out: "border-orange-500/40 bg-orange-500/10 text-orange-300",
};

export const AUTHZ_STATUS_CLASS: Record<AuthorizationStatus, string> = {
  pending: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  verified: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
  attested: "border-violet-500/40 bg-violet-500/10 text-violet-300",
  expired: "border-orange-500/40 bg-orange-500/10 text-orange-300",
  revoked: "border-rose-500/40 bg-rose-500/10 text-rose-300",
};

export const ADMIN_CATEGORY_LABEL: Record<AdminCategory, string> = {
  authentication: "Authentication",
  admin_interface: "Admin interface",
  user_management: "User management",
  system_configuration: "System configuration",
  workflow_management: "Workflow management",
  backend_management: "Backend management",
  none: "None",
};

export const FINDING_CATEGORY_LABEL: Record<FindingCategory, string> = {
  admin_surface: "Admin surface",
  access_control: "Access control",
  configuration_exposure: "Configuration exposure",
  secret_exposure: "Secret exposure",
  api_security: "API security",
  source_code: "Source code",
  database_policy: "Database policy",
  security_headers: "Security headers",
  information_disclosure: "Information disclosure",
  fingerprint: "Fingerprint",
  pentest_security: "Pentest & hardening",
  sensitive_data: "Sensitive data & PII",
};

export const ACTIVE_SCAN_STATUSES: ScanStatus[] = ["queued", "running"];
export const isScanActive = (s: ScanStatus | undefined) => !!s && ACTIVE_SCAN_STATUSES.includes(s);

export const CONFIG_CATEGORIES: FindingCategory[] = [
  "configuration_exposure",
  "secret_exposure",
  "security_headers",
  "information_disclosure",
  "database_policy",
];

export const PENTEST_CATEGORIES: FindingCategory[] = [
  "pentest_security",
  "access_control",
  "admin_surface",
  "security_headers",
];

export const SENSITIVE_DATA_CATEGORIES: FindingCategory[] = [
  "sensitive_data",
  "secret_exposure",
  "information_disclosure",
];

export const SOURCE_CATEGORIES: FindingCategory[] = ["source_code", "database_policy"];

export function bySeverity<T extends { severity: RiskLevel }>(a: T, b: T) {
  return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
}
