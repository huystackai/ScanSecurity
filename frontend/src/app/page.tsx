"use client";

import * as React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  AreaChart,
  Area,
  CartesianGrid,
  Cell,
} from "recharts";
import {
  Crosshair,
  Radar,
  ShieldAlert,
  KeyRound,
  Settings2,
  AlertOctagon,
  PlusCircle,
  ArrowRight,
  Route as RouteIcon,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/form-controls";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  DefensiveNotice,
  EmptyState,
  ErrorBanner,
  ScanStatusBadge,
  SeverityBadge,
} from "@/components/status-badges";
import { api, errorMessage } from "@/lib/api";
import { FINDING_CATEGORY_LABEL, SEVERITY_HEX } from "@/lib/constants";
import { SEVERITIES, type FindingCategory, type Severity } from "@/lib/types";
import { formatDate, formatRelative } from "@/lib/utils";
import { useActiveScan } from "@/components/providers";

export default function DashboardPage() {
  const { setSelectedScanId } = useActiveScan();
  const summaryQuery = useQuery({
    queryKey: ["dashboard", "summary"],
    queryFn: () => api.dashboardSummary(),
    refetchInterval: 15_000,
  });

  const data = summaryQuery.data;

  const severityChartData = React.useMemo(() => {
    return SEVERITIES.map((sev) => ({
      name: sev.toUpperCase(),
      severity: sev,
      count: data?.findings_by_severity?.[sev] ?? 0,
      fill: SEVERITY_HEX[sev],
    }));
  }, [data]);

  const trendChartData = React.useMemo(() => {
    return (data?.severity_trend ?? []).map((pt) => ({
      label: `${pt.target_name} (${formatDate(pt.date, { withTime: false })})`,
      critical: pt.critical ?? 0,
      high: pt.high ?? 0,
      medium: pt.medium ?? 0,
      low: pt.low ?? 0,
      info: pt.info ?? 0,
    }));
  }, [data]);

  const categoryEntries = React.useMemo(() => {
    const entries = Object.entries(data?.findings_by_category ?? {}) as [FindingCategory, number][];
    return entries.sort((a, b) => b[1] - a[1]);
  }, [data]);

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-zinc-100">Security Posture Dashboard</h1>
          <p className="text-xs text-muted-foreground">
            Aggregate defensive findings, administrative attack surface exposure, and scan telemetry across authorized
            targets.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button asChild variant="outline" size="sm">
            <Link href="/targets">
              <Crosshair className="h-4 w-4" />
              Manage Targets
            </Link>
          </Button>
          <Button asChild size="sm">
            <Link href="/scans/new">
              <PlusCircle className="h-4 w-4" />
              New Security Scan
            </Link>
          </Button>
        </div>
      </div>

      <DefensiveNotice />

      {summaryQuery.isError && (
        <ErrorBanner
          title="Could not load dashboard summary"
          message={errorMessage(summaryQuery.error)}
          onRetry={() => void summaryQuery.refetch()}
        />
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-7">
        {[
          {
            label: "Verified Targets",
            value: data ? `${data.verified_targets} / ${data.total_targets}` : "—",
            sub: "Ownership verified",
            icon: Crosshair,
            color: "text-cyan-400",
          },
          {
            label: "Total Scans",
            value: data?.total_scans ?? "—",
            sub: `${data?.running_scans ?? 0} currently active`,
            icon: Radar,
            color: "text-sky-400",
          },
          {
            label: "Routes Scanned",
            value: data?.total_routes_scanned ?? "—",
            sub: "Frontend & API paths",
            icon: RouteIcon,
            color: "text-zinc-300",
          },
          {
            label: "Admin Surfaces",
            value: data?.admin_surfaces ?? "—",
            sub: "Privileged routes",
            icon: ShieldAlert,
            color: "text-amber-400",
          },
          {
            label: "Exposed Configs",
            value: data?.exposed_configurations ?? "—",
            sub: "Secrets / headers / env",
            icon: Settings2,
            color: "text-orange-400",
          },
          {
            label: "Access Control",
            value: data?.access_control_findings ?? "—",
            sub: "AuthZ / IDOR issues",
            icon: KeyRound,
            color: "text-rose-400",
          },
          {
            label: "Critical & High",
            value: data?.critical_high_findings ?? "—",
            sub: "Priority findings",
            icon: AlertOctagon,
            color: "text-rose-500",
          },
        ].map((kpi) => {
          const Icon = kpi.icon;
          return (
            <Card key={kpi.label} className="border-zinc-800/90 bg-zinc-950/70">
              <CardContent className="p-3.5">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-medium text-muted-foreground">{kpi.label}</span>
                  <Icon className={`h-4 w-4 ${kpi.color}`} />
                </div>
                {summaryQuery.isLoading ? (
                  <Skeleton className="mt-2 h-7 w-16" />
                ) : (
                  <div className="mt-1.5 font-mono text-xl font-bold text-zinc-100">{kpi.value}</div>
                )}
                <p className="mt-0.5 text-[11px] text-muted-foreground">{kpi.sub}</p>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Charts row */}
      <div className="grid gap-4 lg:grid-cols-12">
        <Card className="lg:col-span-5">
          <CardHeader>
            <CardTitle>Findings by Severity</CardTitle>
            <CardDescription>Distribution across all completed and running scans</CardDescription>
          </CardHeader>
          <CardContent className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityChartData} margin={{ top: 8, right: 12, left: -16, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#27272a" vertical={false} />
                <XAxis dataKey="name" tick={{ fill: "#a1a1aa", fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis
                  allowDecimals={false}
                  tick={{ fill: "#a1a1aa", fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                />
                <RechartsTooltip
                  contentStyle={{
                    backgroundColor: "#09090b",
                    borderColor: "#27272a",
                    fontSize: 12,
                    borderRadius: 6,
                  }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {severityChartData.map((entry) => (
                    <Cell key={entry.severity} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card className="lg:col-span-7">
          <CardHeader>
            <CardTitle>Severity Trend Across Scans</CardTitle>
            <CardDescription>Historical finding counts per scan execution</CardDescription>
          </CardHeader>
          <CardContent className="h-64">
            {trendChartData.length === 0 ? (
              <div className="flex h-full items-center justify-center text-xs text-muted-foreground">
                Run scans to populate severity trend telemetry.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trendChartData} margin={{ top: 8, right: 12, left: -16, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#27272a" vertical={false} />
                  <XAxis dataKey="label" tick={{ fill: "#a1a1aa", fontSize: 10 }} axisLine={false} tickLine={false} />
                  <YAxis
                    allowDecimals={false}
                    tick={{ fill: "#a1a1aa", fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <RechartsTooltip
                    contentStyle={{
                      backgroundColor: "#09090b",
                      borderColor: "#27272a",
                      fontSize: 12,
                      borderRadius: 6,
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="critical"
                    stackId="1"
                    stroke={SEVERITY_HEX.critical}
                    fill={SEVERITY_HEX.critical}
                    fillOpacity={0.35}
                  />
                  <Area
                    type="monotone"
                    dataKey="high"
                    stackId="1"
                    stroke={SEVERITY_HEX.high}
                    fill={SEVERITY_HEX.high}
                    fillOpacity={0.35}
                  />
                  <Area
                    type="monotone"
                    dataKey="medium"
                    stackId="1"
                    stroke={SEVERITY_HEX.medium}
                    fill={SEVERITY_HEX.medium}
                    fillOpacity={0.3}
                  />
                  <Area
                    type="monotone"
                    dataKey="low"
                    stackId="1"
                    stroke={SEVERITY_HEX.low}
                    fill={SEVERITY_HEX.low}
                    fillOpacity={0.25}
                  />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Category breakdown + Recent scans */}
      <div className="grid gap-4 lg:grid-cols-12">
        <Card className="lg:col-span-4">
          <CardHeader>
            <CardTitle>Findings by Category</CardTitle>
            <CardDescription>Audit domain distribution</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2.5">
            {categoryEntries.length === 0 ? (
              <p className="py-6 text-center text-xs text-muted-foreground">No findings categorized yet.</p>
            ) : (
              categoryEntries.map(([cat, count]) => (
                <div
                  key={cat}
                  className="flex items-center justify-between rounded-md border border-zinc-800/80 bg-zinc-900/40 px-3 py-2 text-xs"
                >
                  <span className="font-medium text-zinc-200">{FINDING_CATEGORY_LABEL[cat] ?? cat}</span>
                  <span className="rounded bg-zinc-800 px-2 py-0.5 font-mono text-xs font-semibold text-cyan-300">
                    {count}
                  </span>
                </div>
              ))
            )}
          </CardContent>
        </Card>

        <Card className="lg:col-span-8">
          <CardHeader className="flex flex-row items-center justify-between">
            <div>
              <CardTitle>Recent Scans</CardTitle>
              <CardDescription>Latest security assessments and live progress</CardDescription>
            </div>
            <Button asChild variant="ghost" size="sm" className="text-xs text-cyan-400">
              <Link href="/scans">
                View all
                <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </Button>
          </CardHeader>
          <CardContent>
            {!data?.recent_scans?.length ? (
              <EmptyState
                title="No scans have been run yet"
                description="Verify a target in Target Inventory and start an authorized defensive security scan."
                action={
                  <Button asChild size="sm">
                    <Link href="/scans/new">Launch First Scan</Link>
                  </Button>
                }
              />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Target</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Phase / Progress</TableHead>
                    <TableHead>Findings</TableHead>
                    <TableHead>Started</TableHead>
                    <TableHead className="text-right">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.recent_scans.map((scan) => (
                    <TableRow key={scan.id}>
                      <TableCell>
                        <div className="font-medium text-zinc-100">{scan.target_name}</div>
                        <div className="font-mono text-[11px] text-muted-foreground">{scan.target_url}</div>
                      </TableCell>
                      <TableCell>
                        <ScanStatusBadge status={scan.status} />
                      </TableCell>
                      <TableCell className="font-mono text-xs text-zinc-300">
                        {scan.progress}% {scan.current_phase ? `(${scan.current_phase})` : ""}
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap items-center gap-1">
                          {SEVERITIES.map((sev: Severity) => {
                            const n = scan.stats.findings_by_severity?.[sev] ?? 0;
                            if (!n) return null;
                            return (
                              <span key={sev} className="inline-flex items-center gap-1">
                                <SeverityBadge severity={sev} className="px-1.5 py-0 text-[10px]" />
                                <span className="font-mono text-xs text-zinc-300">{n}</span>
                              </span>
                            );
                          })}
                          {(scan.stats.findings_total ?? 0) === 0 && (
                            <span className="text-xs text-muted-foreground">0</span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {formatRelative(scan.created_at)}
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          asChild
                          variant="outline"
                          size="sm"
                          className="h-7 text-xs"
                          onClick={() => setSelectedScanId(scan.id)}
                        >
                          <Link href={`/scans/${scan.id}`}>Inspect</Link>
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
    </div>
  );
}
