"use client";

import * as React from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ShieldCheck,
  CheckCircle2,
  Plus,
  Trash2,
  KeyRound,
  Sliders,
  Database,
  Radar,
  ArrowLeft,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input, NativeSelect, SecretInput, Textarea } from "@/components/ui/input";
import { Checkbox, Label, Switch } from "@/components/ui/form-controls";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/menus";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { AuthzStatusBadge, CopyButton, ErrorBanner } from "@/components/status-badges";
import { api, errorMessage } from "@/lib/api";
import {
  CREDENTIAL_AUTH_TYPES,
  type AccessTest,
  type CredentialAuthType,
  type ScopeConfig,
  type VerifiableMethod,
} from "@/lib/types";
import { formatDate, humanize } from "@/lib/utils";

export default function TargetDetailPage() {
  const params = useParams<{ id: string }>();
  const targetId = params.id;
  const queryClient = useQueryClient();

  const targetQuery = useQuery({
    queryKey: ["targets", targetId],
    queryFn: () => api.getTarget(targetId),
  });

  const verificationQuery = useQuery({
    queryKey: ["targets", targetId, "verification"],
    queryFn: () => api.getVerification(targetId),
  });

  const credentialsQuery = useQuery({
    queryKey: ["targets", targetId, "credentials"],
    queryFn: () => api.listCredentials(targetId),
  });

  const target = targetQuery.data;
  const verification = verificationQuery.data;

  // Verification feedback state
  const [verifyFeedback, setVerifyFeedback] = React.useState<{ ok: boolean; detail: string } | null>(null);
  const verifyMutation = useMutation({
    mutationFn: (method: VerifiableMethod) => api.verifyTarget(targetId, method),
    onSuccess: (res) => {
      setVerifyFeedback({ ok: res.verified, detail: res.detail });
      queryClient.invalidateQueries({ queryKey: ["targets", targetId] });
      queryClient.invalidateQueries({ queryKey: ["targets"] });
    },
    onError: (err) => {
      setVerifyFeedback({ ok: false, detail: errorMessage(err) });
    },
  });

  // Lab mode attestation
  const [attestStatement, setAttestStatement] = React.useState(
    "I confirm I am the authorized administrator of this local/lab target and approve defensive testing.",
  );
  const [attestConfirm, setAttestConfirm] = React.useState(false);
  const attestMutation = useMutation({
    mutationFn: () => api.attestTarget(targetId, { statement: attestStatement.trim(), confirm: true }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["targets", targetId] });
      queryClient.invalidateQueries({ queryKey: ["targets"] });
    },
  });

  // Scope config state
  const [allowedHostsStr, setAllowedHostsStr] = React.useState("");
  const [scope, setScope] = React.useState<ScopeConfig>({
    include_paths: ["/"],
    exclude_paths: ["/logout"],
    max_depth: 4,
    max_pages: 150,
    requests_per_second: 5,
    concurrency: 4,
    respect_robots: true,
    enable_path_probing: true,
    render_js: false,
    request_timeout_seconds: 15,
  });
  const [includePathsStr, setIncludePathsStr] = React.useState("/");
  const [excludePathsStr, setExcludePathsStr] = React.useState("/logout");
  const [accessTests, setAccessTests] = React.useState<AccessTest[]>([]);

  // Supabase state
  const [supaEnabled, setSupaEnabled] = React.useState(false);
  const [supaUrl, setSupaUrl] = React.useState("");
  const [supaAnonKey, setSupaAnonKey] = React.useState("");
  const [scopeSaved, setScopeSaved] = React.useState(false);

  React.useEffect(() => {
    if (!target) return;
    setAllowedHostsStr(target.allowed_hosts.join(", "));
    setScope(target.scope_config);
    setIncludePathsStr(target.scope_config.include_paths.join(", "));
    setExcludePathsStr(target.scope_config.exclude_paths.join(", "));
    setAccessTests(target.access_tests ?? []);
    setSupaEnabled(target.integrations?.supabase?.enabled ?? false);
    setSupaUrl(target.integrations?.supabase?.project_url ?? "");
  }, [target]);

  const updateTargetMutation = useMutation({
    mutationFn: () =>
      api.updateTarget(targetId, {
        allowed_hosts: allowedHostsStr
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
        scope_config: {
          ...scope,
          include_paths: includePathsStr
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean),
          exclude_paths: excludePathsStr
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean),
        },
        access_tests: accessTests.filter((a) => a.url.trim() && a.owner_role.trim()),
        integrations: {
          supabase: {
            enabled: supaEnabled,
            project_url: supaUrl.trim() || null,
            ...(supaAnonKey.trim() ? { anon_key: supaAnonKey.trim() } : {}),
          },
        },
      }),
    onSuccess: () => {
      setSupaAnonKey("");
      setScopeSaved(true);
      setTimeout(() => setScopeSaved(false), 2500);
      queryClient.invalidateQueries({ queryKey: ["targets", targetId] });
    },
  });

  // New credential form
  const [roleName, setRoleName] = React.useState("");
  const [authType, setAuthType] = React.useState<CredentialAuthType>("cookie");
  const [headerName, setHeaderName] = React.useState("");
  const [secretValue, setSecretValue] = React.useState("");
  const [credDesc, setCredDesc] = React.useState("");

  const createCredMutation = useMutation({
    mutationFn: () =>
      api.createCredential(targetId, {
        role_name: roleName.trim(),
        auth_type: authType,
        ...(authType === "header" && headerName.trim() ? { header_name: headerName.trim() } : {}),
        value: secretValue,
        ...(credDesc.trim() ? { description: credDesc.trim() } : {}),
      }),
    onSuccess: () => {
      setRoleName("");
      setSecretValue("");
      setHeaderName("");
      setCredDesc("");
      queryClient.invalidateQueries({ queryKey: ["targets", targetId, "credentials"] });
      queryClient.invalidateQueries({ queryKey: ["targets", targetId] });
    },
  });

  const deleteCredMutation = useMutation({
    mutationFn: (credId: string) => api.deleteCredential(targetId, credId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["targets", targetId, "credentials"] });
      queryClient.invalidateQueries({ queryKey: ["targets", targetId] });
    },
  });

  if (targetQuery.isLoading) {
    return <div className="p-6 text-sm text-muted-foreground">Loading target configuration…</div>;
  }

  if (targetQuery.isError || !target) {
    return (
      <ErrorBanner
        title="Could not load target"
        message={errorMessage(targetQuery.error)}
        onRetry={() => void targetQuery.refetch()}
      />
    );
  }

  const isAuthorized =
    target.authorization_status === "verified" || target.authorization_status === "attested";

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="space-y-1">
          <Link
            href="/targets"
            className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-zinc-200"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            Back to Target Inventory
          </Link>
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-xl font-bold text-zinc-100">{target.name}</h1>
            <AuthzStatusBadge status={target.authorization_status} />
            {target.verification_method && (
              <span className="rounded bg-zinc-800 px-2 py-0.5 font-mono text-xs text-zinc-300">
                via {humanize(target.verification_method)}
              </span>
            )}
          </div>
          <p className="font-mono text-xs text-muted-foreground">
            {target.base_url} · Verified at: {formatDate(target.verified_at)} · Expires:{" "}
            {formatDate(target.verification_expires_at)}
          </p>
        </div>

        <Button asChild size="sm" disabled={!isAuthorized}>
          <Link href={`/scans/new?target=${target.id}`}>
            <Radar className="h-4 w-4" />
            Launch Scan on Target
          </Link>
        </Button>
      </div>

      <Tabs defaultValue="verification">
        <TabsList>
          <TabsTrigger value="verification">
            <ShieldCheck className="h-3.5 w-3.5" />
            1. Ownership Verification
          </TabsTrigger>
          <TabsTrigger value="scope">
            <Sliders className="h-3.5 w-3.5" />
            2. Scope & Access Tests
          </TabsTrigger>
          <TabsTrigger value="credentials">
            <KeyRound className="h-3.5 w-3.5" />
            3. Test Credentials ({credentialsQuery.data?.items.length ?? 0})
          </TabsTrigger>
          <TabsTrigger value="integrations">
            <Database className="h-3.5 w-3.5" />
            4. Supabase / BaaS Integration
          </TabsTrigger>
        </TabsList>

        {/* TAB 1: Verification */}
        <TabsContent value="verification" className="space-y-4">
          {verifyFeedback && (
            <div
              className={`rounded-lg border p-3 text-xs ${
                verifyFeedback.ok
                  ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-200"
                  : "border-rose-500/40 bg-rose-500/10 text-rose-200"
              }`}
            >
              <strong>{verifyFeedback.ok ? "Verification succeeded:" : "Verification check failed:"}</strong>{" "}
              {verifyFeedback.detail}
            </div>
          )}

          {verification ? (
            <div className="grid gap-4 lg:grid-cols-3">
              {/* DNS TXT */}
              <Card>
                <CardHeader>
                  <CardTitle>Option A: DNS TXT Record</CardTitle>
                  <CardDescription>Recommended for production domains without code deploys</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3 text-xs">
                  <div>
                    <span className="text-muted-foreground">Record Name / Host:</span>
                    <div className="mt-1 flex items-center justify-between gap-2 rounded border bg-zinc-950 p-2 font-mono">
                      <span className="break-all">{verification.instructions.dns_txt.record_name}</span>
                      <CopyButton value={verification.instructions.dns_txt.record_name} />
                    </div>
                  </div>
                  <div>
                    <span className="text-muted-foreground">TXT Value:</span>
                    <div className="mt-1 flex items-center justify-between gap-2 rounded border bg-zinc-950 p-2 font-mono">
                      <span className="break-all">{verification.instructions.dns_txt.record_value}</span>
                      <CopyButton value={verification.instructions.dns_txt.record_value} />
                    </div>
                  </div>
                  <Button
                    size="sm"
                    className="w-full"
                    disabled={verifyMutation.isPending}
                    onClick={() => verifyMutation.mutate("dns_txt")}
                  >
                    Verify DNS TXT
                  </Button>
                </CardContent>
              </Card>

              {/* Well-Known File */}
              <Card>
                <CardHeader>
                  <CardTitle>Option B: Well-Known File</CardTitle>
                  <CardDescription>Serve a plain-text verification token over HTTPS</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3 text-xs">
                  <div>
                    <span className="text-muted-foreground">File URL:</span>
                    <div className="mt-1 flex items-center justify-between gap-2 rounded border bg-zinc-950 p-2 font-mono">
                      <span className="break-all">{verification.instructions.well_known.url}</span>
                      <CopyButton value={verification.instructions.well_known.url} />
                    </div>
                  </div>
                  <div>
                    <span className="text-muted-foreground">File Content:</span>
                    <div className="mt-1 flex items-center justify-between gap-2 rounded border bg-zinc-950 p-2 font-mono">
                      <span className="break-all">{verification.instructions.well_known.content}</span>
                      <CopyButton value={verification.instructions.well_known.content} />
                    </div>
                  </div>
                  <Button
                    size="sm"
                    className="w-full"
                    disabled={verifyMutation.isPending}
                    onClick={() => verifyMutation.mutate("well_known")}
                  >
                    Verify Well-Known File
                  </Button>
                </CardContent>
              </Card>

              {/* HTML Meta Tag */}
              <Card>
                <CardHeader>
                  <CardTitle>Option C: HTML Meta Tag</CardTitle>
                  <CardDescription>Embed inside the &lt;head&gt; of your landing page</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3 text-xs">
                  <div>
                    <span className="text-muted-foreground">Meta Tag Snippet:</span>
                    <div className="mt-1 flex items-center justify-between gap-2 rounded border bg-zinc-950 p-2 font-mono">
                      <span className="break-all">{verification.instructions.meta_tag.html}</span>
                      <CopyButton value={verification.instructions.meta_tag.html} />
                    </div>
                  </div>
                  <Button
                    size="sm"
                    className="w-full"
                    disabled={verifyMutation.isPending}
                    onClick={() => verifyMutation.mutate("meta_tag")}
                  >
                    Verify Meta Tag
                  </Button>
                </CardContent>
              </Card>
            </div>
          ) : (
            <div className="text-xs text-muted-foreground">Loading verification instructions…</div>
          )}

          {/* Lab mode attestation if allowed */}
          {verification?.attestation_allowed && (
            <Card className="border-violet-500/30 bg-violet-500/5">
              <CardHeader>
                <CardTitle>Lab Mode Signed Attestation (Admin Only)</CardTitle>
                <CardDescription>
                  Platform lab mode permits written operator attestation for local or staging environments where public
                  DNS/HTTP challenge verification is not applicable.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {attestMutation.isError && <ErrorBanner message={errorMessage(attestMutation.error)} />}
                <div className="space-y-1.5">
                  <Label htmlFor="attest-statement">Authorization Statement</Label>
                  <Textarea
                    id="attest-statement"
                    value={attestStatement}
                    onChange={(e) => setAttestStatement(e.target.value)}
                  />
                </div>
                <div className="flex items-center gap-2">
                  <Checkbox
                    id="attest-confirm"
                    checked={attestConfirm}
                    onCheckedChange={(v) => setAttestConfirm(v === true)}
                  />
                  <Label htmlFor="attest-confirm">
                    I attest that I have explicit written authorization to audit this target.
                  </Label>
                </div>
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={!attestConfirm || !attestStatement.trim() || attestMutation.isPending}
                  onClick={() => attestMutation.mutate()}
                >
                  {attestMutation.isPending ? "Recording Attestation…" : "Record Lab Attestation"}
                </Button>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* TAB 2: Scope & Access Tests */}
        <TabsContent value="scope" className="space-y-4">
          {updateTargetMutation.isError && <ErrorBanner message={errorMessage(updateTargetMutation.error)} />}
          <Card>
            <CardHeader>
              <CardTitle>Crawl & Rate-Limit Scope</CardTitle>
              <CardDescription>
                Strict boundaries enforced by the scanner so requests never leave allowed hosts or exceed rate limits.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-3">
                <div className="space-y-1.5">
                  <Label>Allowed Hosts (comma-separated)</Label>
                  <Input value={allowedHostsStr} onChange={(e) => setAllowedHostsStr(e.target.value)} />
                </div>
                <div className="space-y-1.5">
                  <Label>Include Paths</Label>
                  <Input value={includePathsStr} onChange={(e) => setIncludePathsStr(e.target.value)} />
                </div>
                <div className="space-y-1.5">
                  <Label>Exclude Paths</Label>
                  <Input value={excludePathsStr} onChange={(e) => setExcludePathsStr(e.target.value)} />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4 sm:grid-cols-5">
                <div className="space-y-1.5">
                  <Label>Max Depth</Label>
                  <Input
                    type="number"
                    min={1}
                    max={12}
                    value={scope.max_depth}
                    onChange={(e) => setScope({ ...scope, max_depth: Number(e.target.value) || 4 })}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label>Max Pages</Label>
                  <Input
                    type="number"
                    min={1}
                    max={2000}
                    value={scope.max_pages}
                    onChange={(e) => setScope({ ...scope, max_pages: Number(e.target.value) || 150 })}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label>Requests / sec</Label>
                  <Input
                    type="number"
                    min={1}
                    max={50}
                    value={scope.requests_per_second}
                    onChange={(e) => setScope({ ...scope, requests_per_second: Number(e.target.value) || 5 })}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label>Concurrency</Label>
                  <Input
                    type="number"
                    min={1}
                    max={16}
                    value={scope.concurrency}
                    onChange={(e) => setScope({ ...scope, concurrency: Number(e.target.value) || 4 })}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label>Timeout (sec)</Label>
                  <Input
                    type="number"
                    min={3}
                    max={60}
                    value={scope.request_timeout_seconds}
                    onChange={(e) =>
                      setScope({ ...scope, request_timeout_seconds: Number(e.target.value) || 15 })
                    }
                  />
                </div>
              </div>

              <div className="grid gap-3 sm:grid-cols-3">
                <label className="flex items-center justify-between rounded-md border bg-zinc-900/50 p-3 text-xs">
                  <span>Respect robots.txt</span>
                  <Switch
                    checked={scope.respect_robots}
                    onCheckedChange={(v) => setScope({ ...scope, respect_robots: v })}
                  />
                </label>
                <label className="flex items-center justify-between rounded-md border bg-zinc-900/50 p-3 text-xs">
                  <span>Safe Admin Path Probing</span>
                  <Switch
                    checked={scope.enable_path_probing}
                    onCheckedChange={(v) => setScope({ ...scope, enable_path_probing: v })}
                  />
                </label>
                <label className="flex items-center justify-between rounded-md border bg-zinc-900/50 p-3 text-xs">
                  <span>Headless JS Rendering (Playwright)</span>
                  <Switch
                    checked={scope.render_js}
                    onCheckedChange={(v) => setScope({ ...scope, render_js: v })}
                  />
                </label>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle>Differential Access Control Test URLs</CardTitle>
                <CardDescription>
                  Specify resource URLs owned by a test credential role to verify horizontal/vertical authorization
                  boundaries (read-only GET comparison).
                </CardDescription>
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={() =>
                  setAccessTests([...accessTests, { url: `${target.base_url}/api/`, owner_role: "user_a", description: "" }])
                }
              >
                <Plus className="h-3.5 w-3.5" />
                Add Test Resource
              </Button>
            </CardHeader>
            <CardContent className="space-y-2.5">
              {accessTests.length === 0 ? (
                <p className="text-xs text-muted-foreground">No differential access test endpoints configured.</p>
              ) : (
                accessTests.map((t, idx) => (
                  <div key={idx} className="grid gap-2 sm:grid-cols-12">
                    <Input
                      className="sm:col-span-5"
                      placeholder="https://app.example.com/api/orders/123"
                      value={t.url}
                      onChange={(e) => {
                        const next = [...accessTests];
                        next[idx] = { ...t, url: e.target.value };
                        setAccessTests(next);
                      }}
                    />
                    <Input
                      className="sm:col-span-3"
                      placeholder="Owner role (e.g. user_a)"
                      value={t.owner_role}
                      onChange={(e) => {
                        const next = [...accessTests];
                        next[idx] = { ...t, owner_role: e.target.value };
                        setAccessTests(next);
                      }}
                    />
                    <Input
                      className="sm:col-span-3"
                      placeholder="Description"
                      value={t.description ?? ""}
                      onChange={(e) => {
                        const next = [...accessTests];
                        next[idx] = { ...t, description: e.target.value };
                        setAccessTests(next);
                      }}
                    />
                    <Button
                      variant="ghost"
                      size="icon"
                      className="sm:col-span-1"
                      onClick={() => setAccessTests(accessTests.filter((_, i) => i !== idx))}
                    >
                      <Trash2 className="h-4 w-4 text-rose-400" />
                    </Button>
                  </div>
                ))
              )}

              <div className="flex items-center justify-end gap-3 pt-2">
                {scopeSaved && (
                  <span className="inline-flex items-center gap-1 text-xs text-emerald-400">
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    Scope & access tests saved
                  </span>
                )}
                <Button
                  size="sm"
                  disabled={updateTargetMutation.isPending}
                  onClick={() => updateTargetMutation.mutate()}
                >
                  {updateTargetMutation.isPending ? "Saving…" : "Save Scope Configuration"}
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* TAB 3: Write-only Credentials */}
        <TabsContent value="credentials" className="space-y-4">
          <div className="grid gap-4 lg:grid-cols-12">
            <Card className="lg:col-span-5">
              <CardHeader>
                <CardTitle>Add Test Role Credential (Write-Only)</CardTitle>
                <CardDescription>
                  Credential secrets are encrypted at rest and never returned by the API.
                </CardDescription>
              </CardHeader>
              <CardContent>
                {createCredMutation.isError && <ErrorBanner message={errorMessage(createCredMutation.error)} />}
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    createCredMutation.mutate();
                  }}
                  className="space-y-3"
                >
                  <div className="space-y-1.5">
                    <Label htmlFor="cred-role">Role Name</Label>
                    <Input
                      id="cred-role"
                      required
                      placeholder="user_a / regular_user / admin_test"
                      value={roleName}
                      onChange={(e) => setRoleName(e.target.value)}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="cred-type">Authentication Type</Label>
                    <NativeSelect
                      id="cred-type"
                      value={authType}
                      onChange={(e) => setAuthType(e.target.value as CredentialAuthType)}
                    >
                      {CREDENTIAL_AUTH_TYPES.map((t) => (
                        <option key={t} value={t}>
                          {t.toUpperCase()}
                        </option>
                      ))}
                    </NativeSelect>
                  </div>
                  {authType === "header" && (
                    <div className="space-y-1.5">
                      <Label htmlFor="cred-header">Custom Header Name</Label>
                      <Input
                        id="cred-header"
                        required
                        placeholder="X-API-Key"
                        value={headerName}
                        onChange={(e) => setHeaderName(e.target.value)}
                      />
                    </div>
                  )}
                  <div className="space-y-1.5">
                    <Label htmlFor="cred-secret">Secret Value (Token / Cookie string)</Label>
                    <SecretInput
                      id="cred-secret"
                      required
                      placeholder="Write-only token or session cookie"
                      value={secretValue}
                      onChange={(e) => setSecretValue(e.target.value)}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="cred-desc">Description (optional)</Label>
                    <Input
                      id="cred-desc"
                      placeholder="Standard tenant user account"
                      value={credDesc}
                      onChange={(e) => setCredDesc(e.target.value)}
                    />
                  </div>
                  <Button type="submit" size="sm" className="w-full" disabled={createCredMutation.isPending}>
                    {createCredMutation.isPending ? "Storing…" : "Store Write-Only Credential"}
                  </Button>
                </form>
              </CardContent>
            </Card>

            <Card className="lg:col-span-7">
              <CardHeader>
                <CardTitle>Configured Test Credentials</CardTitle>
                <CardDescription>Used during differential access control verification</CardDescription>
              </CardHeader>
              <CardContent>
                {(credentialsQuery.data?.items.length ?? 0) === 0 ? (
                  <p className="py-8 text-center text-xs text-muted-foreground">
                    No test credentials stored for this target.
                  </p>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Role</TableHead>
                        <TableHead>Type</TableHead>
                        <TableHead>Description</TableHead>
                        <TableHead>Created</TableHead>
                        <TableHead className="text-right">Action</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {credentialsQuery.data?.items.map((c) => (
                        <TableRow key={c.id}>
                          <TableCell className="font-mono text-xs font-semibold text-cyan-300">
                            {c.role_name}
                          </TableCell>
                          <TableCell className="font-mono text-xs uppercase text-zinc-300">
                            {c.auth_type}
                            {c.header_name ? ` (${c.header_name})` : ""}
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground">
                            {c.description || "—"}
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground">
                            {formatDate(c.created_at)}
                          </TableCell>
                          <TableCell className="text-right">
                            <Button
                              variant="ghost"
                              size="icon-sm"
                              onClick={() => deleteCredMutation.mutate(c.id)}
                            >
                              <Trash2 className="h-3.5 w-3.5 text-rose-400" />
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* TAB 4: Supabase Integration */}
        <TabsContent value="integrations">
          <Card className="max-w-2xl">
            <CardHeader>
              <CardTitle>Supabase Row-Level Security (RLS) & BaaS Audit</CardTitle>
              <CardDescription>
                Optionally configure your Supabase project URL and public anon key so VibeScan can audit exposed PostgREST
                tables and missing RLS policies safely.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <label className="flex items-center justify-between rounded-md border bg-zinc-900/50 p-3 text-xs">
                <span className="font-medium text-zinc-200">Enable Supabase BaaS Policy Audit</span>
                <Switch checked={supaEnabled} onCheckedChange={setSupaEnabled} />
              </label>
              <div className="space-y-1.5">
                <Label htmlFor="supa-url">Supabase Project URL</Label>
                <Input
                  id="supa-url"
                  type="url"
                  placeholder="https://xyzcompany.supabase.co"
                  value={supaUrl}
                  onChange={(e) => setSupaUrl(e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="supa-key">
                  Supabase Public Anon Key{" "}
                  {target.integrations?.supabase?.anon_key_set && (
                    <span className="text-emerald-400">(currently set — leave blank to keep existing)</span>
                  )}
                </Label>
                <SecretInput
                  id="supa-key"
                  placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                  value={supaAnonKey}
                  onChange={(e) => setSupaAnonKey(e.target.value)}
                />
              </div>
              <div className="flex items-center justify-end gap-3">
                {scopeSaved && (
                  <span className="inline-flex items-center gap-1 text-xs text-emerald-400">
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    Integration saved
                  </span>
                )}
                <Button
                  size="sm"
                  disabled={updateTargetMutation.isPending}
                  onClick={() => updateTargetMutation.mutate()}
                >
                  Save Integration
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
