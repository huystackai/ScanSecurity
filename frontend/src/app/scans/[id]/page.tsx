"use client";

import * as React from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  CheckCircle2,
  Clock,
  Loader2,
  XCircle,
  ShieldAlert,
  KeyRound,
  Settings2,
  Webhook,
  FileCode2,
  Sparkles,
  FileText,
  Square,
  Cpu,
  ArrowLeft,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/form-controls";
import {
  ErrorBanner,
  FindingStatusBadge,
  ScanStatusBadge,
  SeverityBadge,
} from "@/components/status-badges";
import { api, errorMessage } from "@/lib/api";
import { isScanActive } from "@/lib/constants";
import { FINDING_STATUSES, SEVERITIES } from "@/lib/types";
import { formatDate, formatDuration, formatPercent, humanize } from "@/lib/utils";
import { useActiveScan } from "@/components/providers";

export default function ScanDetailPage() {
  const params = useParams<{ id: string }>();
  const scanId = params.id;
  const queryClient = useQueryClient();
  const { setSelectedScanId } = useActiveScan();

  React.useEffect(() => {
    if (scanId) setSelectedScanId(scanId);
  }, [scanId, setSelectedScanId]);

  const scanQuery = useQuery({
    queryKey: ["scans", scanId],
    queryFn: () => api.getScan(scanId),
    refetchInterval: (query) => (isScanActive(query.state.data?.status) ? 2000 : false),
  });

  const techQuery = useQuery({
    queryKey: ["scans", scanId, "technologies"],
    queryFn: () => api.getTechnologies(scanId),
    enabled: !!scanQuery.data,
    refetchInterval: () => (isScanActive(scanQuery.data?.status) ? 4000 : false),
  });

  const cancelMutation = useMutation({
    mutationFn: () => api.cancelScan(scanId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scans", scanId] });
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
  });

  if (scanQuery.isLoading) {
    return <div className="p-6 text-sm text-muted-foreground">Loading scan telemetry…</div>;
  }

  if (scanQuery.isError || !scanQuery.data) {
    return (
      <ErrorBanner
        title="Could not load scan"
        message={errorMessage(scanQuery.error)}
        onRetry={() => void scanQuery.refetch()}
      />
    );
  }

  const scan = scanQuery.data;
  const active = isScanActive(scan.status);

  const explorerLinks = [
    {
      href: `/admin-surfaces?scan=${scan.id}`,
      label: "Admin Surface Explorer",
      count: scan.stats.admin_surfaces ?? 0,
      icon: ShieldAlert,
    },
    {
      href: `/access-control?scan=${scan.id}`,
      label: "Access Control Findings",
      count: scan.stats.findings_total ?? 0,
      icon: KeyRound,
    },
    {
      href: `/configuration?scan=${scan.id}`,
      label: "Configuration & Headers",
      count: scan.stats.assets_analyzed ?? 0,
      icon: Settings2,
    },
    {
      href: `/api-explorer?scan=${scan.id}`,
      label: "API Explorer",
      count: scan.stats.api_endpoints ?? 0,
      icon: Webhook,
    },
    {
      href: `/source-audit?scan=${scan.id}`,
      label: "Source Code Audit",
      count: null,
      icon: FileCode2,
    },
    {
      href: `/ai-analysis?scan=${scan.id}`,
      label: "AI Security Analysis",
      count: null,
      icon: Sparkles,
    },
    {
      href: `/reports?scan=${scan.id}`,
      label: "Export Reports",
      count: null,
      icon: FileText,
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="space-y-1">
          <Link
            href="/scans"
            className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-zinc-200"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            All Scans
          </Link>
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-xl font-bold text-zinc-100">{scan.target_name}</h1>
            <ScanStatusBadge status={scan.status} />
            <span className="font-mono text-xs text-muted-foreground">{scan.target_url}</span>
          </div>
          <p className="text-xs text-muted-foreground">
            Created {formatDate(scan.created_at)} · Duration:{" "}
            <span className="font-mono text-zinc-300">
              {formatDuration(scan.started_at, scan.finished_at)}
            </span>
          </p>
        </div>

        {active && (
          <Button
            variant="destructive"
            size="sm"
            disabled={scan.cancel_requested || cancelMutation.isPending}
            onClick={() => cancelMutation.mutate()}
          >
            <Square className="h-3.5 w-3.5" />
            {scan.cancel_requested ? "Cancel Requested…" : "Cancel Scan"}
          </Button>
        )}
      </div>

      {scan.error && <ErrorBanner title="Scan Execution Error" message={scan.error} />}

      {/* Live Progress Bar */}
      <Card>
        <CardContent className="space-y-3 p-4">
          <div className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-2">
              {active && <Loader2 className="h-4 w-4 animate-spin text-cyan-400" />}
              <span className="font-semibold text-zinc-200">
                Phase: {scan.current_phase ? humanize(scan.current_phase) : humanize(scan.status)}
              </span>
            </div>
            <span className="font-mono text-sm font-bold text-cyan-300">{scan.progress}%</span>
          </div>
          <Progress value={scan.progress} />

          {/* Live stats counters */}
          <div className="grid grid-cols-2 gap-2.5 pt-2 sm:grid-cols-7">
            {[
              { label: "Pages Crawled", value: scan.stats.pages_crawled ?? 0 },
              { label: "HTTP Requests", value: scan.stats.requests_made ?? 0 },
              { label: "Routes Discovered", value: scan.stats.routes_discovered ?? 0 },
              { label: "Admin Surfaces", value: scan.stats.admin_surfaces ?? 0 },
              { label: "API Endpoints", value: scan.stats.api_endpoints ?? 0 },
              { label: "Assets Analyzed", value: scan.stats.assets_analyzed ?? 0 },
              { label: "Total Findings", value: scan.stats.findings_total ?? 0 },
            ].map((s) => (
              <div key={s.label} className="rounded-md border bg-zinc-950/60 px-3 py-2">
                <div className="text-[11px] text-muted-foreground">{s.label}</div>
                <div className="mt-0.5 font-mono text-lg font-bold text-zinc-100">{s.value}</div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Deep links into Explorer Views */}
      <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4 lg:grid-cols-7">
        {explorerLinks.map((item) => {
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className="flex flex-col justify-between rounded-lg border border-zinc-800 bg-zinc-900/40 p-3 transition hover:border-cyan-500/40 hover:bg-zinc-900"
            >
              <div className="flex items-center justify-between">
                <Icon className="h-4 w-4 text-cyan-400" />
                {item.count !== null && (
                  <span className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-[11px] text-zinc-200">
                    {item.count}
                  </span>
                )}
              </div>
              <span className="mt-2.5 text-xs font-medium text-zinc-200">{item.label}</span>
            </Link>
          );
        })}
      </div>

      {/* Phase timeline + Severity / Status / Tech breakdown */}
      <div className="grid gap-4 lg:grid-cols-12">
        <Card className="lg:col-span-6">
          <CardHeader>
            <CardTitle>Execution Phase Timeline</CardTitle>
            <CardDescription>Step-by-step audit pipeline telemetry</CardDescription>
          </CardHeader>
          <CardContent>
            {scan.phase_log.length === 0 ? (
              <p className="text-xs text-muted-foreground">Waiting for first pipeline phase to start…</p>
            ) : (
              <ol className="space-y-3">
                {scan.phase_log.map((p, idx) => {
                  const icon =
                    p.status === "completed" ? (
                      <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                    ) : p.status === "running" ? (
                      <Loader2 className="h-4 w-4 animate-spin text-sky-400" />
                    ) : p.status === "failed" ? (
                      <XCircle className="h-4 w-4 text-rose-400" />
                    ) : (
                      <Clock className="h-4 w-4 text-zinc-500" />
                    );
                  return (
                    <li
                      key={`${p.phase}-${idx}`}
                      className="flex items-start justify-between gap-3 rounded-md border border-zinc-800/80 bg-zinc-950/60 p-3 text-xs"
                    >
                      <div className="flex items-start gap-2.5">
                        <div className="mt-0.5">{icon}</div>
                        <div>
                          <div className="font-semibold text-zinc-200">{humanize(p.phase)}</div>
                          {p.message && <p className="mt-0.5 text-muted-foreground">{p.message}</p>}
                        </div>
                      </div>
                      <span className="whitespace-nowrap font-mono text-[11px] text-muted-foreground">
                        {formatDuration(p.started_at, p.finished_at)}
                      </span>
                    </li>
                  );
                })}
              </ol>
            )}
          </CardContent>
        </Card>

        <div className="space-y-4 lg:col-span-6">
          <Card>
            <CardHeader>
              <CardTitle>Findings Breakdown</CardTitle>
              <CardDescription>Severity and confirmation status summary</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-5 gap-2">
                {SEVERITIES.map((sev) => (
                  <div key={sev} className="rounded-md border bg-zinc-950/60 p-2.5 text-center">
                    <SeverityBadge severity={sev} />
                    <div className="mt-1.5 font-mono text-lg font-bold text-zinc-100">
                      {scan.stats.findings_by_severity?.[sev] ?? 0}
                    </div>
                  </div>
                ))}
              </div>
              <div className="flex flex-wrap items-center gap-2 pt-1">
                {FINDING_STATUSES.map((st) => (
                  <div
                    key={st}
                    className="flex items-center gap-1.5 rounded border border-zinc-800 bg-zinc-900/50 px-2.5 py-1 text-xs"
                  >
                    <FindingStatusBadge status={st} />
                    <span className="font-mono font-semibold text-zinc-200">
                      {scan.stats.findings_by_status?.[st] ?? 0}
                    </span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Cpu className="h-4 w-4 text-cyan-400" />
                Fingerprinted Stack & Technologies
              </CardTitle>
              <CardDescription>Frameworks, BaaS backends, and build tools detected</CardDescription>
            </CardHeader>
            <CardContent>
              {(techQuery.data?.items.length ?? 0) === 0 ? (
                <p className="text-xs text-muted-foreground">No technologies fingerprinted yet.</p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {techQuery.data?.items.map((tech) => (
                    <div
                      key={tech.id}
                      className="rounded-md border border-zinc-800 bg-zinc-950/70 px-3 py-2 text-xs"
                    >
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-zinc-100">{tech.name}</span>
                        <Badge variant="outline" className="text-[10px] uppercase">
                          {tech.kind}
                        </Badge>
                        <span className="font-mono text-[11px] text-cyan-300">
                          {formatPercent(tech.confidence)}
                        </span>
                      </div>
                      {tech.evidence[0] && (
                        <p className="mt-1 text-[11px] text-muted-foreground">
                          {tech.evidence[0].signal}: {tech.evidence[0].detail}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
