"use client";

import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileText, Download, FileCode, FileSpreadsheet } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState, ErrorBanner } from "@/components/status-badges";
import { ScanSelector } from "@/components/scan-selector";
import { useActiveScan } from "@/components/providers";
import { api, errorMessage } from "@/lib/api";
import type { ReportFormat } from "@/lib/types";
import { formatBytes, formatDate, shortHash } from "@/lib/utils";

const FORMAT_CARDS: {
  format: ReportFormat;
  title: string;
  desc: string;
  icon: React.ComponentType<{ className?: string }>;
}[] = [
  {
    format: "html",
    title: "Standalone HTML Audit Report",
    desc: "Self-contained interactive security report suitable for engineering and stakeholder review.",
    icon: FileText,
  },
  {
    format: "pdf",
    title: "Executive & Compliance PDF",
    desc: "Formatted printable assessment document with executive summary, CVSS scores, and remediation roadmap.",
    icon: FileSpreadsheet,
  },
  {
    format: "json",
    title: "Machine-Readable JSON Export",
    desc: "Complete structured telemetry (routes, endpoints, findings, evidence, and AI analysis) for CI/SIEM ingestion.",
    icon: FileCode,
  },
];

export default function ReportsPage() {
  const { selectedScanId } = useActiveScan();
  const queryClient = useQueryClient();

  const reportsQuery = useQuery({
    queryKey: ["scans", selectedScanId, "reports"],
    queryFn: () => api.listReports(selectedScanId),
    enabled: !!selectedScanId,
  });

  const generateMutation = useMutation({
    mutationFn: (format: ReportFormat) => api.createReport(selectedScanId, format),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scans", selectedScanId, "reports"] });
    },
  });

  const reports = reportsQuery.data?.items ?? [];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-zinc-100">Audit Reports & Exports</h1>
          <p className="text-xs text-muted-foreground">
            Generate and download verifiable HTML, PDF, and JSON security reports for the active scan.
          </p>
        </div>
        <ScanSelector />
      </div>

      {generateMutation.isError && <ErrorBanner message={errorMessage(generateMutation.error)} />}
      {reportsQuery.isError && (
        <ErrorBanner
          message={errorMessage(reportsQuery.error)}
          onRetry={() => void reportsQuery.refetch()}
        />
      )}

      {!selectedScanId ? (
        <EmptyState
          icon={<FileText className="h-5 w-5" />}
          title="No scan selected"
          description="Select a scan to generate or download audit reports."
        />
      ) : (
        <>
          <div className="grid gap-4 sm:grid-cols-3">
            {FORMAT_CARDS.map((card) => {
              const Icon = card.icon;
              return (
                <Card key={card.format} className="flex flex-col justify-between">
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle>{card.title}</CardTitle>
                      <Icon className="h-4 w-4 text-cyan-400" />
                    </div>
                    <CardDescription>{card.desc}</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <Button
                      size="sm"
                      className="w-full"
                      disabled={generateMutation.isPending}
                      onClick={() => generateMutation.mutate(card.format)}
                    >
                      Generate {card.format.toUpperCase()} Report
                    </Button>
                  </CardContent>
                </Card>
              );
            })}
          </div>

          {reports.length === 0 ? (
            <EmptyState
              icon={<FileText className="h-5 w-5" />}
              title="No reports generated for this scan yet"
              description="Choose HTML, PDF, or JSON above to generate a downloadable report artifact."
            />
          ) : (
            <Card>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Format</TableHead>
                    <TableHead>File Size</TableHead>
                    <TableHead>SHA-256 Checksum</TableHead>
                    <TableHead>Generated At</TableHead>
                    <TableHead className="text-right">Download</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {reports.map((r) => (
                    <TableRow key={r.id}>
                      <TableCell>
                        <Badge variant="default" className="font-mono uppercase">
                          {r.format}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-zinc-300">
                        {formatBytes(r.size_bytes)}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground" title={r.sha256}>
                        {shortHash(r.sha256, 20)}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {formatDate(r.created_at)}
                      </TableCell>
                      <TableCell className="text-right">
                        <Button asChild variant="outline" size="sm" className="h-7 text-xs">
                          <a href={api.reportDownloadUrl(r.id)} download>
                            <Download className="h-3.5 w-3.5" />
                            Download
                          </a>
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
