// Types mirroring docs/api-contract.md (VibeScan REST API v1). Keep in sync with the contract.

// ---------- Enumerations ----------
export const OPERATOR_ROLES = ["admin", "operator", "viewer"] as const;
export type OperatorRole = (typeof OPERATOR_ROLES)[number];

export const AUTHORIZATION_STATUSES = ["pending", "verified", "attested", "expired", "revoked"] as const;
export type AuthorizationStatus = (typeof AUTHORIZATION_STATUSES)[number];

export const VERIFICATION_METHODS = ["dns_txt", "well_known", "meta_tag", "attestation"] as const;
export type VerificationMethod = (typeof VERIFICATION_METHODS)[number];
export type VerifiableMethod = Exclude<VerificationMethod, "attestation">;

export const SCAN_STATUSES = ["queued", "running", "completed", "failed", "cancelled", "timed_out"] as const;
export type ScanStatus = (typeof SCAN_STATUSES)[number];

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const FINDING_STATUSES = ["confirmed", "potential", "informational", "false_positive", "not_tested"] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

export const VERIFICATION_STATUSES = ["unverified", "verified", "false_positive", "accepted_risk", "fixed"] as const;
export type VerificationStatus = (typeof VERIFICATION_STATUSES)[number];

export const FINDING_CATEGORIES = [
  "admin_surface",
  "access_control",
  "configuration_exposure",
  "secret_exposure",
  "api_security",
  "source_code",
  "database_policy",
  "security_headers",
  "information_disclosure",
  "fingerprint",
  "pentest_security",
  "sensitive_data",
] as const;
export type FindingCategory = (typeof FINDING_CATEGORIES)[number];

export const ADMIN_CATEGORIES = [
  "authentication",
  "admin_interface",
  "user_management",
  "system_configuration",
  "workflow_management",
  "backend_management",
  "none",
] as const;
export type AdminCategory = (typeof ADMIN_CATEGORIES)[number];

export const AUTH_OBSERVATIONS = [
  "public_content",
  "public_shell",
  "login_page",
  "redirect_to_login",
  "unauthorized",
  "forbidden",
  "not_found",
  "error",
  "redirect_other",
  "not_tested",
] as const;
export type AuthObservation = (typeof AUTH_OBSERVATIONS)[number];

export const RISK_LEVELS = [...SEVERITIES, "none"] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];

export const API_ENDPOINT_CATEGORIES = [
  "authentication",
  "user_management",
  "administration",
  "configuration",
  "database",
  "file_storage",
  "workflow",
  "ai_agents",
  "webhooks",
  "internal",
  "other",
] as const;
export type ApiEndpointCategory = (typeof API_ENDPOINT_CATEGORIES)[number];

export const TECHNOLOGY_KINDS = ["framework", "backend", "baas", "build_tool", "platform"] as const;
export type TechnologyKind = (typeof TECHNOLOGY_KINDS)[number];

export const CREDENTIAL_AUTH_TYPES = ["cookie", "bearer", "header"] as const;
export type CredentialAuthType = (typeof CREDENTIAL_AUTH_TYPES)[number];

export const REPORT_FORMATS = ["html", "json", "pdf"] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];

export type AnalysisStatus = "pending" | "completed" | "failed";
export type AnalysisProvider = "openai" | "deterministic";
export type RemediationPriority = "immediate" | "short_term" | "long_term";
export type AIProviderSetting = "openai" | "disabled";

// ---------- Common ----------
export interface Paginated<T> {
  items: T[];
  total: number;
}

export interface Evidence {
  type: string;
  detail: string;
  location?: string | null;
  snippet?: string | null;
}

// ---------- Auth / Operators ----------
export interface Operator {
  id: string;
  email: string;
  display_name: string;
  role: OperatorRole;
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
}

export interface AuthSession {
  operator: Operator;
  csrf_token: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface OperatorCreate {
  email: string;
  display_name: string;
  password: string;
  role: OperatorRole;
}

export interface OperatorUpdate {
  display_name?: string;
  role?: OperatorRole;
  is_active?: boolean;
  password?: string;
}

// ---------- Targets ----------
export interface ScopeConfig {
  include_paths: string[];
  exclude_paths: string[];
  max_depth: number;
  max_pages: number;
  requests_per_second: number;
  concurrency: number;
  respect_robots: boolean;
  enable_path_probing: boolean;
  render_js: boolean;
  request_timeout_seconds: number;
}

export interface AccessTest {
  url: string;
  owner_role: string;
  description?: string | null;
}

export interface SupabaseIntegration {
  enabled: boolean;
  project_url: string | null;
  anon_key_set: boolean;
}

export interface SupabaseIntegrationInput {
  enabled: boolean;
  project_url: string | null;
  anon_key?: string;
}

export interface Target {
  id: string;
  name: string;
  base_url: string;
  primary_host: string;
  allowed_hosts: string[];
  scope_config: ScopeConfig;
  access_tests: AccessTest[];
  integrations: { supabase: SupabaseIntegration };
  authorization_status: AuthorizationStatus;
  verification_method: VerificationMethod | null;
  verification_token: string;
  verified_at: string | null;
  verification_expires_at: string | null;
  // Contract leaves the attestation shape open; treat as opaque.
  attestation: Record<string, unknown> | null;
  owner_operator_id: string;
  created_at: string;
  last_scan_at: string | null;
  credential_roles: string[];
}

export interface TargetCreate {
  name: string;
  base_url: string;
  allowed_hosts?: string[];
  scope_config?: Partial<ScopeConfig>;
  access_tests?: AccessTest[];
}

export interface TargetUpdate {
  name?: string;
  allowed_hosts?: string[];
  scope_config?: Partial<ScopeConfig>;
  access_tests?: AccessTest[];
  integrations?: { supabase?: SupabaseIntegrationInput };
}

export interface VerificationInstructions {
  token: string;
  instructions: {
    dns_txt: { record_name: string; record_value: string };
    well_known: { url: string; content: string };
    meta_tag: { html: string };
  };
  attestation_allowed: boolean;
}

export interface VerifyResponse {
  verified: boolean;
  detail: string;
  target: Target;
}

export interface AttestRequest {
  statement: string;
  confirm: true;
}

export interface Credential {
  id: string;
  role_name: string;
  auth_type: CredentialAuthType;
  header_name: string | null;
  description: string | null;
  created_at: string;
}

export interface CredentialCreate {
  role_name: string;
  auth_type: CredentialAuthType;
  header_name?: string;
  value: string;
  description?: string;
}

// ---------- Source uploads ----------
export interface SourceUpload {
  id: string;
  target_id: string;
  filename: string;
  sha256: string;
  size_bytes: number;
  file_count: number;
  status: string;
  created_at: string;
}

// ---------- Scans ----------
export type PentestProfile = "standard" | "deep" | "enterprise";

export interface ScanOptions {
  crawl: boolean;
  render_js: boolean;
  path_probing: boolean;
  access_control: boolean;
  config_exposure: boolean;
  api_discovery: boolean;
  pentest_checks: boolean;
  pentest_profile: PentestProfile;
  sensitive_data: boolean;
  source_analysis: boolean;
  ai_analysis: boolean;
  max_pages: number | null;
  timeout_seconds: number;
  source_upload_id: string | null;
}

export const DEFAULT_SCAN_OPTIONS: ScanOptions = {
  crawl: true,
  render_js: false,
  path_probing: true,
  access_control: true,
  config_exposure: true,
  api_discovery: true,
  pentest_checks: true,
  pentest_profile: "standard",
  sensitive_data: true,
  source_analysis: true,
  ai_analysis: false,
  max_pages: null,
  timeout_seconds: 900,
  source_upload_id: null,
};

export interface PhaseLogEntry {
  phase: string;
  status: string;
  started_at: string | null;
  finished_at: string | null;
  message: string | null;
}

export type SeverityCounts = Partial<Record<Severity, number>>;
export type FindingStatusCounts = Partial<Record<FindingStatus, number>>;

export interface ScanStats {
  pages_crawled?: number;
  requests_made?: number;
  routes_discovered?: number;
  admin_surfaces?: number;
  api_endpoints?: number;
  assets_analyzed?: number;
  findings_total?: number;
  findings_by_severity?: SeverityCounts;
  findings_by_status?: FindingStatusCounts;
}

export interface Scan {
  id: string;
  target_id: string;
  target_name: string;
  target_url: string;
  operator_id: string;
  status: ScanStatus;
  options: ScanOptions;
  progress: number;
  current_phase: string | null;
  phase_log: PhaseLogEntry[];
  stats: ScanStats;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  cancel_requested: boolean;
}

export interface ScanCreate {
  target_id: string;
  options?: Partial<ScanOptions>;
  authorization_confirmed: true;
  authorization_statement: string;
}

export interface TechnologyEvidence {
  signal: string;
  detail: string;
  weight: number;
}

export interface Technology {
  id: string;
  name: string;
  kind: TechnologyKind;
  confidence: number;
  evidence: TechnologyEvidence[];
}

export interface RedirectHop {
  url: string;
  status: number;
  location: string | null;
}

export interface Route {
  id: string;
  scan_id: string;
  url: string;
  path: string;
  status_code: number | null;
  title: string | null;
  content_type: string | null;
  auth_observation: AuthObservation;
  redirect_chain: RedirectHop[];
  discovery_methods: string[];
  admin_category: AdminCategory;
  is_admin_surface: boolean;
  confidence: number;
  risk_level: RiskLevel;
  evidence: Evidence[];
  created_at: string;
}

export interface CorsInfo {
  allow_origin: string | null;
  allow_credentials: boolean;
  reflects_origin: boolean;
}

export interface ApiEndpoint {
  id: string;
  scan_id: string;
  url: string;
  path_template: string;
  methods: string[];
  category: ApiEndpointCategory;
  sources: string[];
  status_code: number | null;
  auth_observation: AuthObservation;
  content_type: string | null;
  cors: CorsInfo;
  tested: boolean;
  test_note: string | null;
  evidence: Evidence[];
  created_at: string;
}

export interface Asset {
  id: string;
  url: string;
  kind: string;
  size_bytes: number;
  sha256: string;
  source_map_url: string | null;
  source_map_exposed: boolean;
}

export interface Reference {
  title: string;
  url: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  finding_key: string;
  rule_id: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  status: FindingStatus;
  confidence: number;
  affected: string;
  evidence: Evidence[];
  detection_method: string;
  impact: string;
  reproduction: string[];
  remediation: string;
  references: Reference[];
  cvss_vector: string | null;
  cvss_score: number | null;
  verification_status: VerificationStatus;
  operator_note: string | null;
  created_at: string;
}

export interface FindingUpdate {
  verification_status: VerificationStatus;
  operator_note?: string | null;
}

export interface FindingFilters {
  category?: FindingCategory;
  severity?: Severity;
  status?: FindingStatus;
}

// ---------- AI analysis ----------
export interface Insight {
  summary: string;
  finding_ids: string[];
  severity: Severity;
}

export const ANALYSIS_SECTIONS = [
  "admin_surfaces",
  "exposed_configuration",
  "access_control",
  "api_security",
  "source_code",
] as const;
export type AnalysisSectionKey = (typeof ANALYSIS_SECTIONS)[number];

export interface RiskPrioritizationItem {
  rank: number;
  finding_ids: string[];
  rationale: string;
}

export interface RemediationPlanItem {
  priority: RemediationPriority;
  action: string;
  finding_ids: string[];
}

export interface AIAnalysisOutput {
  executive_summary: string;
  overall_risk: RiskLevel;
  sections: Partial<Record<AnalysisSectionKey, Insight[]>>;
  risk_prioritization: RiskPrioritizationItem[];
  remediation_plan: RemediationPlanItem[];
  limitations: string[];
}

export interface AIAnalysisGrounding {
  valid: boolean;
  dropped_claims: number;
  unknown_ids: string[];
}

export interface AIAnalysis {
  id: string;
  scan_id: string;
  provider: AnalysisProvider;
  model: string | null;
  status: AnalysisStatus;
  error: string | null;
  created_at: string;
  output: AIAnalysisOutput | null;
  grounding: AIAnalysisGrounding | null;
}

// ---------- Reports ----------
export interface Report {
  id: string;
  scan_id: string;
  format: ReportFormat;
  size_bytes: number;
  sha256: string;
  created_at: string;
}

// ---------- Dashboard ----------
export interface SeverityTrendPoint extends SeverityCounts {
  scan_id: string;
  date: string;
  target_name: string;
}

export interface DashboardSummary {
  total_targets: number;
  verified_targets: number;
  total_scans: number;
  running_scans: number;
  total_routes_scanned: number;
  admin_surfaces: number;
  exposed_configurations: number;
  access_control_findings: number;
  critical_high_findings: number;
  findings_by_severity: SeverityCounts;
  findings_by_category: Partial<Record<FindingCategory, number>>;
  severity_trend: SeverityTrendPoint[];
  recent_scans: Scan[];
}

// ---------- Settings / audit ----------
export interface AISettings {
  provider: AIProviderSetting;
  model: string | null;
  base_url: string | null;
  api_key_set: boolean;
  auto_analyze: boolean;
}

export interface AISettingsUpdate {
  provider: AIProviderSetting;
  model: string | null;
  base_url: string | null;
  api_key?: string;
  auto_analyze: boolean;
}

export interface PlatformSettings {
  lab_mode: boolean;
  allow_attestation_only: boolean;
  allow_private_targets: boolean;
  max_scan_timeout_seconds: number;
  semgrep_available: boolean;
  playwright_available: boolean;
  version: string;
}

export interface AuditLogEntry {
  id: string;
  operator_email: string | null;
  action: string;
  target_id: string | null;
  scan_id: string | null;
  ip: string | null;
  details: Record<string, unknown> | string | null;
  created_at: string;
}

export interface HealthResponse {
  status: "ok" | string;
}
