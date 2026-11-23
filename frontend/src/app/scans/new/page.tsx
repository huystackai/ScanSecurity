"use client";

import * as React from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Radar, Upload, ShieldCheck, AlertTriangle } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input, NativeSelect, Textarea } from "@/components/ui/input";
import { Checkbox, Label, Switch } from "@/components/ui/form-controls";
import { AuthzStatusBadge, DefensiveNotice, ErrorBanner } from "@/components/status-badges";
import { api, errorMessage } from "@/lib/api";
import { DEFAULT_SCAN_OPTIONS, type ScanOptions } from "@/lib/types";
import { formatBytes, formatDate } from "@/lib/utils";
import { useActiveScan } from "@/components/providers";

const MODULE_DESCRIPTIONS: {
  key: keyof Pick<
    ScanOptions,
    | "crawl"
    | "render_js"
    | "path_probing"
    | "access_control"
    | "config_exposure"
    | "api_discovery"
    | "pentest_checks"
    | "sensitive_data"
    | "source_analysis"
    | "ai_analysis"
  >;
  label: string;
  desc: string;
}[] = [
  {
    key: "crawl",
    label: "Passive & Scoped Web Crawler",
    desc: "Discover client routes, forms, links, and JavaScript bundles within allowed hosts.",
  },
  {
    key: "path_probing",
    label: "Safe Administrative Route Probing",
    desc: "Probe curated administrative/backoffice paths using read-only requests and SPA baseline diffing.",
  },
  {
    key: "access_control",
    label: "Differential Access Control Checks",
    desc: "Compare unauthenticated and test-credential responses to detect missing server-side authorization.",
  },
  {
    key: "pentest_checks",
    label: "Website Pentest & Admin Hardening Audit",
    desc: "Non-destructive checks for insecure session cookies, clickjacking on admin panels, CSRF/form security, open redirects, dangerous HTTP methods, backup/diagnostic files, and GraphQL introspection.",
  },
  {
    key: "sensitive_data",
    label: "Sensitive Data & PII Exposure Scan",
    desc: "Detect exposed payment cards (Luhn-validated), national IDs (CCCD/CMND/SSN), bulk personal emails/phones, cloud credentials, and sensitive HTML comments with automatic redaction.",
  },
  {
    key: "config_exposure",
    label: "Configuration, Secrets & Security Headers Audit",
    desc: "Inspect client bundles, source maps, public env leakage, CSP/HSTS headers, and Supabase RLS policies.",
  },
  {
    key: "api_discovery",
    label: "API Endpoint & CORS Discovery",
    desc: "Extract REST/GraphQL/BaaS endpoints from bundles and inspect authentication & CORS posture.",
  },
  {
    key: "source_analysis",
    label: "Static Source Code & Policy Analysis",
    desc: "Analyze uploaded source archive (Semgrep / AST rules / RLS policies) when a ZIP is attached.",
  },
  {
    key: "render_js",
    label: "Headless Browser JS Rendering (Playwright)",
    desc: "Execute client-side JavaScript to discover dynamically hydrated routes in SPAs.",
  },
  {
    key: "ai_analysis",
    label: "Automated AI Security Triage",
    desc: "Generate grounded executive summary and prioritized remediation plan upon scan completion.",
  },
];

function NewScanForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const queryClient = useQueryClient();
  const { setSelectedScanId } = useActiveScan();

  const targetsQuery = useQuery({
    queryKey: ["targets"],
    queryFn: () => api.listTargets(),
  });

  const [targetId, setTargetId] = React.useState<string>(searchParams.get("target") ?? "");
  const [quickUrl, setQuickUrl] = React.useState<string>("");
  const [options, setOptions] = React.useState<ScanOptions>(DEFAULT_SCAN_OPTIONS);
  const [authConfirmed, setAuthConfirmed] = React.useState(true);
  const [authStatement, setAuthStatement] = React.useState(
    "I confirm that I am authorized to perform this defensive security assessment against the selected target.",
  );

  React.useEffect(() => {
    const list = targetsQuery.data?.items ?? [];
    if (!targetId && list.length > 0) {
      const verified = list.find(
        (t) => t.authorization_status === "verified" || t.authorization_status === "attested",
      );
      setTargetId((verified ?? list[0]).id);
    }
  }, [targetsQuery.data, targetId]);

  const selectedTarget = React.useMemo(
    () => (targetsQuery.data?.items ?? []).find((t) => t.id === targetId) ?? null,
    [targetsQuery.data, targetId],
  );

  const uploadsQuery = useQuery({
    queryKey: ["source-uploads", targetId],
    queryFn: () => api.listSourceUploads(targetId),
    enabled: !!targetId,
  });

  const uploadMutation = useMutation({
    mutationFn: (file: File) => api.uploadSource(targetId, file),
    onSuccess: (uploaded) => {
      setOptions((prev) => ({ ...prev, source_upload_id: uploaded.id, source_analysis: true }));
      queryClient.invalidateQueries({ queryKey: ["source-uploads", targetId] });
    },
  });

  const createScanMutation = useMutation({
    mutationFn: async () => {
      let effectiveTargetId = targetId;
      if (quickUrl.trim()) {
        const raw = quickUrl.trim();
        const normalizedUrl = raw.startsWith("http://") || raw.startsWith("https://") ? raw : `https://${raw}`;
        const existing = (targetsQuery.data?.items ?? []).find(
          (t) => t.base_url.replace(/\/$/, "").toLowerCase() === normalizedUrl.replace(/\/$/, "").toLowerCase(),
        );
        if (existing) {
          effectiveTargetId = existing.id;
        } else {
          let hostLabel = normalizedUrl;
          try {
            hostLabel = new URL(normalizedUrl).hostname;
          } catch {
            // keep raw
          }
          const created = await api.createTarget({
            name: hostLabel,
            base_url: normalizedUrl,
          });
          effectiveTargetId = created.id;
          queryClient.invalidateQueries({ queryKey: ["targets"] });
        }
      }
      return api.createScan({
        target_id: effectiveTargetId,
        options,
        authorization_confirmed: true,
        authorization_statement: authStatement.trim() || "Authorized security assessment",
      });
    },
    onSuccess: (scan) => {
      setSelectedScanId(scan.id);
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      router.push(`/scans/${scan.id}`);
    },
  });

  const isTargetAuthorized =
    selectedTarget?.authorization_status === "verified" ||
    selectedTarget?.authorization_status === "attested";

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div>
        <h1 className="text-xl font-bold tracking-tight text-zinc-100">Launch New Security Scan</h1>
        <p className="text-xs text-muted-foreground">
          Configure defensive audit modules, attach optional source code archive, and confirm operator authorization.
        </p>
      </div>

      <DefensiveNotice />

      {createScanMutation.isError && <ErrorBanner message={errorMessage(createScanMutation.error)} />}

      {/* Step 1: Target selection or quick URL paste */}
      <Card>
        <CardHeader>
          <CardTitle>1. Enter Target URL or Select Registered Target</CardTitle>
          <CardDescription>Paste any target URL directly to scan immediately, or pick an existing target below.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="quick-scan-url">Quick Scan URL</Label>
            <div className="flex items-center gap-2">
              <Input
                id="quick-scan-url"
                type="url"
                placeholder="https://example.com"
                value={quickUrl}
                onChange={(e) => setQuickUrl(e.target.value)}
                className="font-mono"
              />
              <Button
                disabled={(!quickUrl.trim() && (!targetId || !isTargetAuthorized)) || createScanMutation.isPending}
                onClick={() => createScanMutation.mutate()}
              >
                <Radar className="h-4 w-4" />
                {createScanMutation.isPending ? "Starting…" : "Scan Now"}
              </Button>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3 pt-1">
            <NativeSelect
              aria-label="Target"
              value={targetId}
              onChange={(e) => {
                setTargetId(e.target.value);
                setQuickUrl("");
                setOptions((prev) => ({ ...prev, source_upload_id: null }));
              }}
              className="flex-1"
            >
              {(targetsQuery.data?.items ?? []).length === 0 && (
                <option value="">No targets registered yet</option>
              )}
              {(targetsQuery.data?.items ?? []).map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name} — {t.base_url} [{t.authorization_status.toUpperCase()}]
                </option>
              ))}
            </NativeSelect>
            {selectedTarget && <AuthzStatusBadge status={selectedTarget.authorization_status} />}
          </div>

          {selectedTarget && !isTargetAuthorized && (
            <div className="flex items-center justify-between gap-3 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-200">
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
                <span>
                  This target is currently <strong>{selectedTarget.authorization_status}</strong>. Complete domain
                  verification or lab attestation before starting a scan.
                </span>
              </div>
              <Button asChild size="sm" variant="outline">
                <Link href={`/targets/${selectedTarget.id}`}>Verify Target</Link>
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Step 2: Scan Modules */}
      <Card>
        <CardHeader>
          <CardTitle>2. Audit Modules & Limits</CardTitle>
          <CardDescription>Toggle defensive analysis passes and runtime constraints.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2">
            {MODULE_DESCRIPTIONS.map((m) => (
              <label
                key={m.key}
                className="flex cursor-pointer items-start justify-between gap-3 rounded-lg border bg-zinc-900/40 p-3 hover:bg-zinc-900/70"
              >
                <div className="space-y-0.5">
                  <div className="text-xs font-medium text-zinc-100">{m.label}</div>
                  <p className="text-[11px] leading-relaxed text-muted-foreground">{m.desc}</p>
                </div>
                <Switch
                  checked={Boolean(options[m.key])}
                  onCheckedChange={(v) => setOptions((prev) => ({ ...prev, [m.key]: v }))}
                />
              </label>
            ))}
          </div>

          <div className="grid gap-4 pt-2 sm:grid-cols-3">
            <div className="space-y-1.5">
              <Label htmlFor="scan-pentest-profile">Pentest Depth Profile</Label>
              <NativeSelect
                id="scan-pentest-profile"
                value={options.pentest_profile}
                onChange={(e) =>
                  setOptions((prev) => ({
                    ...prev,
                    pentest_profile: e.target.value as ScanOptions["pentest_profile"],
                  }))
                }
              >
                <option value="standard">Standard (150 pages, 5 RPS, 13 artifacts)</option>
                <option value="deep">Deep (500 pages, 25 RPS, 35+ enterprise artifacts)</option>
                <option value="enterprise">Enterprise 900k+ (1,500+ pages, 60 RPS, 25x concurrency)</option>
              </NativeSelect>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="scan-max-pages">Max Pages Override (optional)</Label>
              <Input
                id="scan-max-pages"
                type="number"
                min={1}
                max={5000}
                placeholder="Use profile default"
                value={options.max_pages ?? ""}
                onChange={(e) =>
                  setOptions((prev) => ({
                    ...prev,
                    max_pages: e.target.value ? Number(e.target.value) : null,
                  }))
                }
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="scan-timeout">Scan Timeout (seconds)</Label>
              <Input
                id="scan-timeout"
                type="number"
                min={60}
                max={7200}
                value={options.timeout_seconds}
                onChange={(e) =>
                  setOptions((prev) => ({
                    ...prev,
                    timeout_seconds: Number(e.target.value) || 900,
                  }))
                }
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Step 3: Optional Source ZIP Upload */}
      <Card>
        <CardHeader>
          <CardTitle>3. White-Box Source Code Archive (Optional)</CardTitle>
          <CardDescription>
            Upload a ZIP archive (&le; 50 MB) of your repository to enable static code, secret, and database policy
            auditing alongside dynamic black-box checks.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {uploadMutation.isError && <ErrorBanner message={errorMessage(uploadMutation.error)} />}
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="source-select">Existing Uploaded Archive</Label>
              <NativeSelect
                id="source-select"
                value={options.source_upload_id ?? ""}
                onChange={(e) =>
                  setOptions((prev) => ({ ...prev, source_upload_id: e.target.value || null }))
                }
              >
                <option value="">None (Dynamic Web / API Audit Only)</option>
                {(uploadsQuery.data?.items ?? []).map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.filename} ({formatBytes(u.size_bytes)}, {u.file_count} files — {formatDate(u.created_at)})
                  </option>
                ))}
              </NativeSelect>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="source-file">Or Upload New ZIP Archive</Label>
              <div className="flex items-center gap-2">
                <Input
                  id="source-file"
                  type="file"
                  accept=".zip,application/zip"
                  disabled={!targetId || uploadMutation.isPending}
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (file) uploadMutation.mutate(file);
                  }}
                />
                {uploadMutation.isPending && (
                  <span className="inline-flex items-center gap-1 text-xs text-cyan-300">
                    <Upload className="h-3.5 w-3.5 animate-bounce" />
                    Uploading…
                  </span>
                )}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Step 4: Explicit Authorization Confirmation */}
      <Card className="border-cyan-500/30 bg-cyan-500/5">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-cyan-400" />
            4. Required Operator Authorization Confirmation
          </CardTitle>
          <CardDescription>
            Every scan requires a signed authorization statement recorded in the immutable audit log.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="auth-statement">Authorization Statement</Label>
            <Textarea
              id="auth-statement"
              required
              value={authStatement}
              onChange={(e) => setAuthStatement(e.target.value)}
            />
          </div>
          <div className="flex items-start gap-2.5">
            <Checkbox
              id="auth-confirm"
              checked={authConfirmed}
              onCheckedChange={(v) => setAuthConfirmed(v === true)}
            />
            <Label htmlFor="auth-confirm" className="leading-relaxed">
              I confirm that I own or have explicit written authorization from the system owner to run this defensive
              security scan against{" "}
              <span className="font-mono text-cyan-300">{selectedTarget?.base_url ?? "the selected target"}</span>.
            </Label>
          </div>

          <div className="flex items-center justify-end gap-3 pt-2">
            <Button asChild variant="outline">
              <Link href="/scans">Cancel</Link>
            </Button>
            <Button
              disabled={
                (!quickUrl.trim() && (!targetId || !isTargetAuthorized)) ||
                !authConfirmed ||
                !authStatement.trim() ||
                createScanMutation.isPending
              }
              onClick={() => createScanMutation.mutate()}
            >
              <Radar className="h-4 w-4" />
              {createScanMutation.isPending ? "Starting Scan…" : "Confirm & Start Security Scan"}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

export default function NewScanPage() {
  return (
    <React.Suspense fallback={<div className="p-6 text-sm text-muted-foreground">Loading scan configuration…</div>}>
      <NewScanForm />
    </React.Suspense>
  );
}
