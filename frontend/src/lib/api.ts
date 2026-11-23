import type {
  AIAnalysis,
  AISettings,
  AISettingsUpdate,
  ApiEndpoint,
  Asset,
  AttestRequest,
  AuditLogEntry,
  AuthSession,
  Credential,
  CredentialCreate,
  DashboardSummary,
  Finding,
  FindingFilters,
  FindingUpdate,
  HealthResponse,
  LoginRequest,
  Operator,
  OperatorCreate,
  OperatorUpdate,
  Paginated,
  PlatformSettings,
  Report,
  ReportFormat,
  Route,
  Scan,
  ScanCreate,
  ScanStatus,
  SourceUpload,
  Target,
  TargetCreate,
  TargetUpdate,
  Technology,
  VerifiableMethod,
  VerificationInstructions,
  VerifyResponse,
} from "./types";

export const API_BASE = "/api/v1";
export const CSRF_COOKIE = "vibescan_csrf";
const UNSAFE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export class ApiError extends Error {
  readonly status: number;
  readonly detail: string;
  readonly raw: unknown;

  constructor(status: number, detail: string, raw?: unknown) {
    super(detail);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
    this.raw = raw;
  }

  get isNetworkError() {
    return this.status === 0;
  }
}

export function isApiError(err: unknown): err is ApiError {
  return err instanceof ApiError;
}

export function errorMessage(err: unknown): string {
  if (isApiError(err)) return err.detail;
  if (err instanceof Error) return err.message;
  return "Unexpected error";
}

export function readCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const prefix = `${name}=`;
  for (const part of document.cookie.split(";")) {
    const c = part.trim();
    if (c.startsWith(prefix)) return decodeURIComponent(c.slice(prefix.length));
  }
  return null;
}

// Fallback CSRF token captured from /auth/login and /auth/me in case the cookie is not readable yet.
let csrfFallback: string | null = null;
export function setCsrfToken(token: string | null) {
  csrfFallback = token;
}

/** Turn a FastAPI error payload ({detail: string} or validation list) into a readable message. */
function parseDetail(payload: unknown, fallback: string): string {
  if (payload && typeof payload === "object" && "detail" in payload) {
    const detail = (payload as { detail: unknown }).detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail
        .map((d) => {
          if (d && typeof d === "object") {
            const item = d as { loc?: unknown[]; msg?: string };
            const loc = Array.isArray(item.loc) ? item.loc.filter((l) => l !== "body").join(".") : "";
            return loc ? `${loc}: ${item.msg ?? "invalid"}` : (item.msg ?? "invalid");
          }
          return String(d);
        })
        .join("; ");
    }
  }
  return fallback;
}

let redirectingToLogin = false;
function redirectToLogin() {
  if (typeof window === "undefined" || redirectingToLogin) return;
  if (window.location.pathname.startsWith("/login")) return;
  redirectingToLogin = true;
  const next = encodeURIComponent(window.location.pathname + window.location.search);
  window.location.assign(`/login?next=${next}`);
}

type Query = Record<string, string | number | boolean | null | undefined>;

export interface RequestOptions {
  method?: string;
  body?: unknown;
  query?: Query;
  signal?: AbortSignal;
  /** Skip the automatic redirect to /login on 401 (used by the auth check itself). */
  noAuthRedirect?: boolean;
}

function buildUrl(path: string, query?: Query): string {
  const url = path.startsWith("/health") ? path : `${API_BASE}${path}`;
  if (!query) return url;
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null || v === "") continue;
    params.set(k, String(v));
  }
  const qs = params.toString();
  return qs ? `${url}?${qs}` : url;
}

export async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const method = (opts.method ?? "GET").toUpperCase();
  const headers: Record<string, string> = { Accept: "application/json" };
  let body: BodyInit | undefined;

  if (opts.body instanceof FormData) {
    body = opts.body; // browser sets multipart boundary
  } else if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.body);
  }

  if (UNSAFE_METHODS.has(method)) {
    const token = readCookie(CSRF_COOKIE) ?? csrfFallback;
    if (token) headers["X-CSRF-Token"] = token;
  }

  let res: Response;
  try {
    res = await fetch(buildUrl(path, opts.query), {
      method,
      headers,
      body,
      credentials: "include",
      cache: "no-store",
      signal: opts.signal,
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError(0, "Cannot reach the VibeScan API. Is the backend running?");
  }

  if (res.status === 204) return undefined as T;

  const contentType = res.headers.get("content-type") ?? "";
  let payload: unknown = null;
  if (contentType.includes("application/json")) {
    payload = await res.json().catch(() => null);
  } else {
    const text = await res.text().catch(() => "");
    payload = text ? { detail: text.slice(0, 300) } : null;
  }

  if (!res.ok) {
    if (res.status === 401 && !opts.noAuthRedirect) redirectToLogin();
    const fallback =
      res.status >= 500 && res.status !== 501
        ? `Backend error (${res.status}). The API may be unavailable.`
        : `Request failed (${res.status})`;
    throw new ApiError(res.status, parseDetail(payload, fallback), payload);
  }
  return payload as T;
}

const get = <T>(path: string, query?: Query, opts?: Omit<RequestOptions, "query">) =>
  request<T>(path, { ...opts, query });
const send = <T>(method: string, path: string, body?: unknown) => request<T>(path, { method, body });

export const api = {
  // Auth
  login: (body: LoginRequest) => request<AuthSession>("/auth/login", { method: "POST", body, noAuthRedirect: true }),
  logout: () => request<void>("/auth/logout", { method: "POST", noAuthRedirect: true }),
  me: () => request<AuthSession>("/auth/me", { noAuthRedirect: true }),
  health: () => request<HealthResponse>("/health", { noAuthRedirect: true }),

  // Operators
  listOperators: (q?: Query) => get<Paginated<Operator>>("/operators", q),
  createOperator: (body: OperatorCreate) => send<Operator>("POST", "/operators", body),
  updateOperator: (id: string, body: OperatorUpdate) => send<Operator>("PATCH", `/operators/${id}`, body),

  // Targets
  listTargets: (q?: Query) => get<Paginated<Target>>("/targets", { limit: 500, ...q }),
  getTarget: (id: string) => get<Target>(`/targets/${id}`),
  createTarget: (body: TargetCreate) => send<Target>("POST", "/targets", body),
  updateTarget: (id: string, body: TargetUpdate) => send<Target>("PATCH", `/targets/${id}`, body),
  deleteTarget: (id: string) => send<void>("DELETE", `/targets/${id}`),
  getVerification: (id: string) => get<VerificationInstructions>(`/targets/${id}/verification`),
  verifyTarget: (id: string, method: VerifiableMethod) =>
    send<VerifyResponse>("POST", `/targets/${id}/verify`, { method }),
  attestTarget: (id: string, body: AttestRequest) => send<Target>("POST", `/targets/${id}/attest`, body),
  listCredentials: (id: string) => get<{ items: Credential[] }>(`/targets/${id}/credentials`),
  createCredential: (id: string, body: CredentialCreate) =>
    send<Credential>("POST", `/targets/${id}/credentials`, body),
  deleteCredential: (id: string, credId: string) => send<void>("DELETE", `/targets/${id}/credentials/${credId}`),

  // Source uploads
  listSourceUploads: (targetId?: string) =>
    get<Paginated<SourceUpload>>("/source-uploads", { target_id: targetId, limit: 500 }),
  uploadSource: (targetId: string, file: File) => {
    const form = new FormData();
    form.set("target_id", targetId);
    form.set("file", file);
    return request<SourceUpload>("/source-uploads", { method: "POST", body: form });
  },

  // Scans
  listScans: (q?: { target_id?: string; status?: ScanStatus; limit?: number; offset?: number }) =>
    get<Paginated<Scan>>("/scans", { limit: 100, ...q }),
  getScan: (id: string) => get<Scan>(`/scans/${id}`),
  createScan: (body: ScanCreate) => send<Scan>("POST", "/scans", body),
  cancelScan: (id: string) => send<Scan>("POST", `/scans/${id}/cancel`),
  getTechnologies: (id: string) => get<{ items: Technology[] }>(`/scans/${id}/technologies`),
  listRoutes: (id: string, q?: { admin_only?: boolean; category?: string }) =>
    get<Paginated<Route>>(`/scans/${id}/routes`, { limit: 500, ...q }),
  getRoute: (scanId: string, routeId: string) => get<Route>(`/scans/${scanId}/routes/${routeId}`),
  listEndpoints: (id: string, q?: { category?: string }) =>
    get<Paginated<ApiEndpoint>>(`/scans/${id}/endpoints`, { limit: 500, ...q }),
  listFindings: (id: string, q?: FindingFilters) =>
    get<Paginated<Finding>>(`/scans/${id}/findings`, { limit: 500, ...q }),
  listAssets: (id: string) => get<Paginated<Asset>>(`/scans/${id}/assets`, { limit: 500 }),

  // Findings
  getFinding: (id: string) => get<Finding>(`/findings/${id}`),
  updateFinding: (id: string, body: FindingUpdate) => send<Finding>("PATCH", `/findings/${id}`, body),

  // AI analysis
  getAnalysis: (scanId: string) => get<AIAnalysis>(`/scans/${scanId}/analysis`),
  runAnalysis: (scanId: string) => send<AIAnalysis>("POST", `/scans/${scanId}/analysis`),

  // Reports
  listReports: (scanId: string) => get<Paginated<Report>>(`/scans/${scanId}/reports`),
  createReport: (scanId: string, format: ReportFormat) =>
    send<Report>("POST", `/scans/${scanId}/reports`, { format }),
  reportDownloadUrl: (reportId: string) => `${API_BASE}/reports/${reportId}/download`,

  // Dashboard
  dashboardSummary: () => get<DashboardSummary>("/dashboard/summary"),

  // Settings / audit
  getAISettings: () => get<AISettings>("/settings/ai"),
  updateAISettings: (body: AISettingsUpdate) => send<AISettings>("PUT", "/settings/ai", body),
  getPlatformSettings: () => get<PlatformSettings>("/settings/platform"),
  listAuditLogs: (q: { limit: number; offset: number }) => get<Paginated<AuditLogEntry>>("/audit-logs", q),
};
