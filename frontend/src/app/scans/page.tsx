"use client";

import * as React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { PlusCircle, Radar } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { NativeSelect } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState, ErrorBanner, ScanStatusBadge, SeverityBadge } from "@/components/status-badges";
import { api, errorMessage } from "@/lib/api";
import { SCAN_STATUSES, SEVERITIES, type ScanStatus } from "@/lib/types";
import { formatDate, formatDuration } from "@/lib/utils";
import { useActiveScan } from "@/components/providers";

export default function ScansListPage() {
  const { setSelectedScanId } = useActiveScan();
  const [statusFilter, setStatusFilter] = React.useState<ScanStatus | "">("");
  const [targetFilter, setTargetFilter] = React.useState<string>("");

  const targetsQuery = useQuery({
    queryKey: ["targets"],
    queryFn: () => api.listTargets(),
  });

  const scansQuery = useQuery({
    queryKey: ["scans", { statusFilter, targetFilter }],
    queryFn: () =>
      api.listScans({
        status: statusFilter || undefined,
        target_id: targetFilter || undefined,
      }),
    refetchInterval: 8_000,
  });

  const scans = scansQuery.data?.items ?? [];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-zinc-100">Security Scans</h1>
          <p className="text-xs text-muted-foreground">
            History and live progress of authorized defensive security assessments.
          </p>
        </div>
        <Button asChild size="sm">
          <Link href="/scans/new">
            <PlusCircle className="h-4 w-4" />
            New Security Scan
          </Link>
        </Button>
      </div>

      <Card>
        <CardContent className="flex flex-wrap items-center gap-3 p-3">
          <NativeSelect
            aria-label="Filter by target"
            value={targetFilter}
            onChange={(e) => setTargetFilter(e.target.value)}
            className="w-60"
          >
            <option value="">All targets</option>
            {(targetsQuery.data?.items ?? []).map((t) => (
              <option key={t.id} value={t.id}>
                {t.name} ({t.primary_host})
              </option>
            ))}
          </NativeSelect>

          <NativeSelect
            aria-label="Filter by status"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as ScanStatus | "")}
            className="w-44"
          >
            <option value="">All statuses</option>
            {SCAN_STATUSES.map((s) => (
              <option key={s} value={s}>
                {s.toUpperCase()}
              </option>
            ))}
          </NativeSelect>
        </CardContent>
      </Card>

      {scansQuery.isError && (
        <ErrorBanner message={errorMessage(scansQuery.error)} onRetry={() => void scansQuery.refetch()} />
      )}

      {scans.length === 0 && !scansQuery.isLoading ? (
        <EmptyState
          icon={<Radar className="h-5 w-5" />}
          title="No scans found"
          description="Launch a new scan against a verified target to audit its attack surface."
          action={
            <Button asChild size="sm">
              <Link href="/scans/new">Start New Scan</Link>
            </Button>
          }
        />
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Target</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Progress</TableHead>
                <TableHead>Routes / Endpoints</TableHead>
                <TableHead>Findings Breakdown</TableHead>
                <TableHead>Started</TableHead>
                <TableHead>Duration</TableHead>
                <TableHead className="text-right">Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {scans.map((scan) => (
                <TableRow key={scan.id}>
                  <TableCell>
                    <Link
                      href={`/scans/${scan.id}`}
                      onClick={() => setSelectedScanId(scan.id)}
                      className="font-medium text-zinc-100 hover:text-cyan-400"
                    >
                      {scan.target_name}
                    </Link>
                    <div className="font-mono text-[11px] text-muted-foreground">{scan.target_url}</div>
                  </TableCell>
                  <TableCell>
                    <ScanStatusBadge status={scan.status} />
                  </TableCell>
                  <TableCell className="font-mono text-xs text-zinc-300">
                    {scan.progress}% {scan.current_phase ? `(${scan.current_phase})` : ""}
                  </TableCell>
                  <TableCell className="font-mono text-xs text-zinc-300">
                    {scan.stats.routes_discovered ?? 0} routes · {scan.stats.api_endpoints ?? 0} APIs
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap items-center gap-1">
                      {SEVERITIES.map((sev) => {
                        const n = scan.stats.findings_by_severity?.[sev] ?? 0;
                        if (!n) return null;
                        return (
                          <span key={sev} className="inline-flex items-center gap-0.5">
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
                    {formatDate(scan.created_at)}
                  </TableCell>
                  <TableCell className="font-mono text-xs text-zinc-400">
                    {formatDuration(scan.started_at, scan.finished_at)}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      asChild
                      variant="outline"
                      size="sm"
                      className="h-7 text-xs"
                      onClick={() => setSelectedScanId(scan.id)}
                    >
                      <Link href={`/scans/${scan.id}`}>View Scan</Link>
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}
    </div>
  );
}
