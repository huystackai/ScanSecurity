"use client";

import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Sliders, Sparkles, Users, ScrollText, CheckCircle2, Plus } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input, NativeSelect, SecretInput } from "@/components/ui/input";
import { Label, Switch } from "@/components/ui/form-controls";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/menus";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ErrorBanner } from "@/components/status-badges";
import { useAuth } from "@/components/providers";
import { api, errorMessage } from "@/lib/api";
import {
  OPERATOR_ROLES,
  type AIProviderSetting,
  type OperatorRole,
} from "@/lib/types";
import { formatDate } from "@/lib/utils";

export default function SettingsPage() {
  const { operator } = useAuth();
  const isAdmin = operator?.role === "admin";
  const queryClient = useQueryClient();

  // Platform settings
  const platformQuery = useQuery({
    queryKey: ["settings", "platform"],
    queryFn: () => api.getPlatformSettings(),
  });

  // AI settings (admin)
  const aiQuery = useQuery({
    queryKey: ["settings", "ai"],
    queryFn: () => api.getAISettings(),
    enabled: isAdmin,
  });

  const [aiProvider, setAiProvider] = React.useState<AIProviderSetting>("disabled");
  const [aiModel, setAiModel] = React.useState("gpt-4o-mini");
  const [aiBaseUrl, setAiBaseUrl] = React.useState("");
  const [aiApiKey, setAiApiKey] = React.useState("");
  const [aiAutoAnalyze, setAiAutoAnalyze] = React.useState(false);
  const [aiSaved, setAiSaved] = React.useState(false);

  React.useEffect(() => {
    if (!aiQuery.data) return;
    setAiProvider(aiQuery.data.provider);
    setAiModel(aiQuery.data.model ?? "gpt-4o-mini");
    setAiBaseUrl(aiQuery.data.base_url ?? "");
    setAiAutoAnalyze(aiQuery.data.auto_analyze);
  }, [aiQuery.data]);

  const updateAiMutation = useMutation({
    mutationFn: () =>
      api.updateAISettings({
        provider: aiProvider,
        model: aiModel.trim() || null,
        base_url: aiBaseUrl.trim() || null,
        ...(aiApiKey.trim() ? { api_key: aiApiKey.trim() } : {}),
        auto_analyze: aiAutoAnalyze,
      }),
    onSuccess: () => {
      setAiApiKey("");
      setAiSaved(true);
      setTimeout(() => setAiSaved(false), 2500);
      queryClient.invalidateQueries({ queryKey: ["settings", "ai"] });
    },
  });

  // Operators (admin)
  const operatorsQuery = useQuery({
    queryKey: ["operators"],
    queryFn: () => api.listOperators(),
    enabled: isAdmin,
  });

  const [newEmail, setNewEmail] = React.useState("");
  const [newName, setNewName] = React.useState("");
  const [newPassword, setNewPassword] = React.useState("");
  const [newRole, setNewRole] = React.useState<OperatorRole>("operator");

  const createOperatorMutation = useMutation({
    mutationFn: () =>
      api.createOperator({
        email: newEmail.trim(),
        display_name: newName.trim(),
        password: newPassword,
        role: newRole,
      }),
    onSuccess: () => {
      setNewEmail("");
      setNewName("");
      setNewPassword("");
      queryClient.invalidateQueries({ queryKey: ["operators"] });
    },
  });

  const toggleOperatorMutation = useMutation({
    mutationFn: ({ id, is_active }: { id: string; is_active: boolean }) =>
      api.updateOperator(id, { is_active }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["operators"] });
    },
  });

  // Audit logs (admin)
  const [auditOffset, setAuditOffset] = React.useState(0);
  const auditLimit = 50;
  const auditQuery = useQuery({
    queryKey: ["audit-logs", auditOffset],
    queryFn: () => api.listAuditLogs({ limit: auditLimit, offset: auditOffset }),
    enabled: isAdmin,
  });

  const platform = platformQuery.data;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold tracking-tight text-zinc-100">Platform Settings & Audit Trail</h1>
        <p className="text-xs text-muted-foreground">
          Inspect runtime capabilities, configure AI analysis provider, manage operators, and review immutable audit
          logs.
        </p>
      </div>

      <Tabs defaultValue="platform">
        <TabsList>
          <TabsTrigger value="platform">
            <Sliders className="h-3.5 w-3.5" />
            Platform Environment
          </TabsTrigger>
          {isAdmin && (
            <>
              <TabsTrigger value="ai">
                <Sparkles className="h-3.5 w-3.5" />
                AI Analysis Provider
              </TabsTrigger>
              <TabsTrigger value="operators">
                <Users className="h-3.5 w-3.5" />
                Operators ({operatorsQuery.data?.total ?? 0})
              </TabsTrigger>
              <TabsTrigger value="audit">
                <ScrollText className="h-3.5 w-3.5" />
                Audit Logs ({auditQuery.data?.total ?? 0})
              </TabsTrigger>
            </>
          )}
        </TabsList>

        {/* Platform tab */}
        <TabsContent value="platform">
          {platformQuery.isError && <ErrorBanner message={errorMessage(platformQuery.error)} />}
          <Card className="max-w-3xl">
            <CardHeader>
              <CardTitle>VibeScan Engine Capabilities</CardTitle>
              <CardDescription>Read-only runtime flags and scanner subsystem availability</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-3 sm:grid-cols-2">
              {[
                { label: "Platform Version", value: platform?.version ?? "—" },
                {
                  label: "Max Scan Timeout",
                  value: platform ? `${platform.max_scan_timeout_seconds}s` : "—",
                },
                {
                  label: "Lab Mode Enabled",
                  bool: platform?.lab_mode,
                },
                {
                  label: "Allow Attestation-Only Verification",
                  bool: platform?.allow_attestation_only,
                },
                {
                  label: "Allow Private / RFC1918 Targets",
                  bool: platform?.allow_private_targets,
                },
                {
                  label: "Semgrep Static Engine",
                  bool: platform?.semgrep_available,
                },
                {
                  label: "Playwright Headless Browser",
                  bool: platform?.playwright_available,
                },
              ].map((item) => (
                <div
                  key={item.label}
                  className="flex items-center justify-between rounded-md border bg-zinc-950/70 px-3 py-2.5 text-xs"
                >
                  <span className="text-muted-foreground">{item.label}</span>
                  {"bool" in item ? (
                    <Badge variant={item.bool ? "success" : "secondary"}>
                      {item.bool ? "Enabled / Available" : "Disabled"}
                    </Badge>
                  ) : (
                    <span className="font-mono font-semibold text-zinc-100">{item.value}</span>
                  )}
                </div>
              ))}
            </CardContent>
          </Card>
        </TabsContent>

        {/* AI Settings tab */}
        {isAdmin && (
          <TabsContent value="ai">
            <Card className="max-w-2xl">
              <CardHeader>
                <CardTitle>AI Security Analysis Provider</CardTitle>
                <CardDescription>
                  Configure an OpenAI-compatible LLM endpoint for grounded finding synthesis, or leave disabled to use
                  the built-in deterministic analyzer.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {updateAiMutation.isError && <ErrorBanner message={errorMessage(updateAiMutation.error)} />}
                <div className="space-y-1.5">
                  <Label htmlFor="ai-provider">Provider Mode</Label>
                  <NativeSelect
                    id="ai-provider"
                    value={aiProvider}
                    onChange={(e) => setAiProvider(e.target.value as AIProviderSetting)}
                  >
                    <option value="disabled">Disabled (Use Deterministic Grounded Fallback)</option>
                    <option value="openai">OpenAI / Compatible API</option>
                  </NativeSelect>
                </div>

                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-1.5">
                    <Label htmlFor="ai-model">Model Identifier</Label>
                    <Input
                      id="ai-model"
                      placeholder="gpt-4o-mini"
                      value={aiModel}
                      onChange={(e) => setAiModel(e.target.value)}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="ai-base-url">Custom Base URL (optional)</Label>
                    <Input
                      id="ai-base-url"
                      placeholder="https://api.openai.com/v1"
                      value={aiBaseUrl}
                      onChange={(e) => setAiBaseUrl(e.target.value)}
                    />
                  </div>
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="ai-key">
                    API Key (Write-Only){" "}
                    {aiQuery.data?.api_key_set && (
                      <span className="text-emerald-400">(key is configured — leave blank to keep current)</span>
                    )}
                  </Label>
                  <SecretInput
                    id="ai-key"
                    placeholder="sk-..."
                    value={aiApiKey}
                    onChange={(e) => setAiApiKey(e.target.value)}
                  />
                </div>

                <label className="flex items-center justify-between rounded-md border bg-zinc-900/50 p-3 text-xs">
                  <span>Automatically run AI analysis when a scan completes</span>
                  <Switch checked={aiAutoAnalyze} onCheckedChange={setAiAutoAnalyze} />
                </label>

                <div className="flex items-center justify-end gap-3">
                  {aiSaved && (
                    <span className="inline-flex items-center gap-1 text-xs text-emerald-400">
                      <CheckCircle2 className="h-3.5 w-3.5" />
                      AI settings updated
                    </span>
                  )}
                  <Button
                    size="sm"
                    disabled={updateAiMutation.isPending}
                    onClick={() => updateAiMutation.mutate()}
                  >
                    {updateAiMutation.isPending ? "Saving…" : "Save AI Configuration"}
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        )}

        {/* Operators tab */}
        {isAdmin && (
          <TabsContent value="operators" className="space-y-4">
            <div className="grid gap-4 lg:grid-cols-12">
              <Card className="lg:col-span-4">
                <CardHeader>
                  <CardTitle>Create Operator Account</CardTitle>
                  <CardDescription>Provision admin, operator, or read-only viewer roles</CardDescription>
                </CardHeader>
                <CardContent>
                  {createOperatorMutation.isError && (
                    <ErrorBanner message={errorMessage(createOperatorMutation.error)} />
                  )}
                  <form
                    onSubmit={(e) => {
                      e.preventDefault();
                      createOperatorMutation.mutate();
                    }}
                    className="space-y-3"
                  >
                    <div className="space-y-1.5">
                      <Label htmlFor="op-email">Email</Label>
                      <Input
                        id="op-email"
                        type="email"
                        required
                        value={newEmail}
                        onChange={(e) => setNewEmail(e.target.value)}
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label htmlFor="op-name">Display Name</Label>
                      <Input
                        id="op-name"
                        required
                        value={newName}
                        onChange={(e) => setNewName(e.target.value)}
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label htmlFor="op-role">Role</Label>
                      <NativeSelect
                        id="op-role"
                        value={newRole}
                        onChange={(e) => setNewRole(e.target.value as OperatorRole)}
                      >
                        {OPERATOR_ROLES.map((r) => (
                          <option key={r} value={r}>
                            {r.toUpperCase()}
                          </option>
                        ))}
                      </NativeSelect>
                    </div>
                    <div className="space-y-1.5">
                      <Label htmlFor="op-pass">Initial Password</Label>
                      <SecretInput
                        id="op-pass"
                        required
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                      />
                    </div>
                    <Button
                      type="submit"
                      size="sm"
                      className="w-full"
                      disabled={createOperatorMutation.isPending}
                    >
                      <Plus className="h-4 w-4" />
                      Create Operator
                    </Button>
                  </form>
                </CardContent>
              </Card>

              <Card className="lg:col-span-8">
                <CardHeader>
                  <CardTitle>Registered Operators</CardTitle>
                  <CardDescription>Manage active accounts and access privileges</CardDescription>
                </CardHeader>
                <CardContent>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Display Name</TableHead>
                        <TableHead>Email</TableHead>
                        <TableHead>Role</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Last Login</TableHead>
                        <TableHead className="text-right">Action</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {(operatorsQuery.data?.items ?? []).map((op) => (
                        <TableRow key={op.id}>
                          <TableCell className="font-medium text-zinc-100">{op.display_name}</TableCell>
                          <TableCell className="font-mono text-xs text-zinc-300">{op.email}</TableCell>
                          <TableCell>
                            <Badge variant="outline" className="uppercase">
                              {op.role}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <Badge variant={op.is_active ? "success" : "danger"}>
                              {op.is_active ? "Active" : "Suspended"}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground">
                            {formatDate(op.last_login_at)}
                          </TableCell>
                          <TableCell className="text-right">
                            {op.id !== operator?.id && (
                              <Button
                                variant="outline"
                                size="sm"
                                className="h-7 text-xs"
                                onClick={() =>
                                  toggleOperatorMutation.mutate({
                                    id: op.id,
                                    is_active: !op.is_active,
                                  })
                                }
                              >
                                {op.is_active ? "Suspend" : "Activate"}
                              </Button>
                            )}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        )}

        {/* Audit Logs tab */}
        {isAdmin && (
          <TabsContent value="audit" className="space-y-4">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between">
                <div>
                  <CardTitle>Immutable Security Audit Log</CardTitle>
                  <CardDescription>
                    Chronological record of authentication events, target verifications, and scan authorizations
                  </CardDescription>
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={auditOffset === 0}
                    onClick={() => setAuditOffset((o) => Math.max(0, o - auditLimit))}
                  >
                    Previous
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={(auditQuery.data?.items.length ?? 0) < auditLimit}
                    onClick={() => setAuditOffset((o) => o + auditLimit)}
                  >
                    Next
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Timestamp</TableHead>
                      <TableHead>Operator</TableHead>
                      <TableHead>Action</TableHead>
                      <TableHead>Source IP</TableHead>
                      <TableHead>Details</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(auditQuery.data?.items ?? []).map((log) => (
                      <TableRow key={log.id}>
                        <TableCell className="whitespace-nowrap font-mono text-xs text-muted-foreground">
                          {formatDate(log.created_at)}
                        </TableCell>
                        <TableCell className="font-mono text-xs text-zinc-200">
                          {log.operator_email ?? "system"}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className="font-mono text-[11px]">
                            {log.action}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">
                          {log.ip ?? "—"}
                        </TableCell>
                        <TableCell className="max-w-md truncate font-mono text-xs text-zinc-300">
                          {typeof log.details === "string"
                            ? log.details
                            : log.details
                              ? JSON.stringify(log.details)
                              : "—"}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>
        )}
      </Tabs>
    </div>
  );
}
