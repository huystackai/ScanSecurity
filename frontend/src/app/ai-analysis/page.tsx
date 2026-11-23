"use client";

import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Sparkles,
  ShieldCheck,
  AlertTriangle,
  Loader2,
  ListOrdered,
  Wrench,
  Info,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState, ErrorBanner, SeverityBadge } from "@/components/status-badges";
import { ScanSelector } from "@/components/scan-selector";
import { FindingSheet } from "@/components/finding-sheet";
import { useActiveScan } from "@/components/providers";
import { api, errorMessage, isApiError } from "@/lib/api";
import {
  ANALYSIS_SECTIONS,
  type AnalysisSectionKey,
  type Finding,
  type RemediationPriority,
} from "@/lib/types";
import { formatDate } from "@/lib/utils";

const SECTION_LABELS: Record<AnalysisSectionKey, string> = {
  admin_surfaces: "Administrative Surfaces",
  exposed_configuration: "Exposed Configuration & Secrets",
  access_control: "Access Control & Authorization",
  api_security: "API Security Posture",
  source_code: "Source Code & Database Policies",
};

const PRIORITY_BADGE: Record<RemediationPriority, { label: string; variant: "danger" | "warning" | "default" }> = {
  immediate: { label: "Immediate (0–48h)", variant: "danger" },
  short_term: { label: "Short-Term (1–2 Weeks)", variant: "warning" },
  long_term: { label: "Long-Term Hardening", variant: "default" },
};

export default function AIAnalysisPage() {
  const { selectedScanId } = useActiveScan();
  const queryClient = useQueryClient();
  const [selectedFinding, setSelectedFinding] = React.useState<Finding | null>(null);

  const analysisQuery = useQuery({
    queryKey: ["scans", selectedScanId, "analysis"],
    queryFn: async () => {
      try {
        return await api.getAnalysis(selectedScanId);
      } catch (err) {
        if (isApiError(err) && err.status === 404) return null;
        throw err;
      }
    },
    enabled: !!selectedScanId,
    refetchInterval: (query) => (query.state.data?.status === "pending" ? 2500 : false),
  });

  const findingsQuery = useQuery({
    queryKey: ["findings", selectedScanId, "for-ai"],
    queryFn: () => api.listFindings(selectedScanId),
    enabled: !!selectedScanId,
  });

  const findingByKey = React.useMemo(() => {
    const map = new Map<string, Finding>();
    for (const f of findingsQuery.data?.items ?? []) {
      map.set(f.finding_key, f);
    }
    return map;
  }, [findingsQuery.data]);

  const runMutation = useMutation({
    mutationFn: () => api.runAnalysis(selectedScanId),
    onSuccess: (res) => {
      queryClient.setQueryData(["scans", selectedScanId, "analysis"], res);
    },
  });

  const analysis = analysisQuery.data;
  const output = analysis?.output;

  const renderFindingChips = (keys: string[]) => (
    <div className="flex flex-wrap gap-1">
      {keys.map((key) => {
        const match = findingByKey.get(key);
        return (
          <button
            key={key}
            type="button"
            disabled={!match}
            onClick={() => match && setSelectedFinding(match)}
            className="rounded border border-cyan-500/30 bg-cyan-500/10 px-1.5 py-0.5 font-mono text-[11px] text-cyan-300 transition hover:bg-cyan-500/20 disabled:cursor-default disabled:opacity-60"
          >
            {key}
          </button>
        );
      })}
    </div>
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-zinc-100">AI Security Analysis & Risk Prioritization</h1>
          <p className="text-xs text-muted-foreground">
            Hallucination-guarded synthesis grounded strictly on verified scan findings (`finding_key` citations).
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <ScanSelector />
          {selectedScanId && (
            <Button
              size="sm"
              disabled={runMutation.isPending || analysis?.status === "pending"}
              onClick={() => runMutation.mutate()}
            >
              {runMutation.isPending || analysis?.status === "pending" ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Analyzing…
                </>
              ) : (
                <>
                  <Sparkles className="h-4 w-4" />
                  {analysis ? "Re-run Analysis" : "Run Analysis"}
                </>
              )}
            </Button>
          )}
        </div>
      </div>

      {runMutation.isError && <ErrorBanner message={errorMessage(runMutation.error)} />}
      {analysisQuery.isError && (
        <ErrorBanner
          message={errorMessage(analysisQuery.error)}
          onRetry={() => void analysisQuery.refetch()}
        />
      )}

      {!selectedScanId ? (
        <EmptyState
          icon={<Sparkles className="h-5 w-5" />}
          title="No scan selected"
          description="Select a scan to view or trigger grounded AI security analysis."
        />
      ) : !analysis && !analysisQuery.isLoading ? (
        <EmptyState
          icon={<Sparkles className="h-5 w-5" />}
          title="No AI analysis generated for this scan yet"
          description="Click 'Run Analysis' to synthesize findings into an executive summary, domain insights, and a prioritized remediation plan."
          action={
            <Button size="sm" onClick={() => runMutation.mutate()} disabled={runMutation.isPending}>
              <Sparkles className="h-4 w-4" />
              Run AI Security Analysis
            </Button>
          }
        />
      ) : analysis?.status === "pending" ? (
        <Card>
          <CardContent className="flex items-center gap-3 p-6 text-sm text-zinc-200">
            <Loader2 className="h-5 w-5 animate-spin text-cyan-400" />
            <span>Generating grounded security analysis and verifying finding ID citations…</span>
          </CardContent>
        </Card>
      ) : analysis?.status === "failed" ? (
        <ErrorBanner
          title="AI Analysis Failed"
          message={analysis.error ?? "Analysis job encountered an error."}
          onRetry={() => runMutation.mutate()}
        />
      ) : output ? (
        <div className="space-y-6">
          {/* Executive Summary + Metadata Bar */}
          <Card className="border-cyan-500/30 bg-zinc-950/80">
            <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2">
              <div className="space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <CardTitle className="text-base">Executive Security Assessment</CardTitle>
                  <SeverityBadge severity={output.overall_risk} />
                  <Badge variant="outline" className="font-mono text-[11px]">
                    Provider: {analysis.provider} {analysis.model ? `(${analysis.model})` : ""}
                  </Badge>
                  {analysis.grounding && (
                    <Badge
                      variant={analysis.grounding.valid ? "success" : "warning"}
                      title={
                        analysis.grounding.unknown_ids.length
                          ? `Unknown IDs stripped: ${analysis.grounding.unknown_ids.join(", ")}`
                          : "All cited finding keys verified against scan database"
                      }
                    >
                      {analysis.grounding.valid ? (
                        <ShieldCheck className="h-3 w-3" />
                      ) : (
                        <AlertTriangle className="h-3 w-3" />
                      )}
                      Grounding: {analysis.grounding.valid ? "Verified" : "Filtered"} (
                      {analysis.grounding.dropped_claims} dropped)
                    </Badge>
                  )}
                </div>
                <CardDescription>Generated {formatDate(analysis.created_at)}</CardDescription>
              </div>
            </CardHeader>
            <CardContent>
              <p className="whitespace-pre-line text-sm leading-relaxed text-zinc-200">
                {output.executive_summary}
              </p>
            </CardContent>
          </Card>

          {/* 5 Domain Sections */}
          <div className="grid gap-4 lg:grid-cols-2">
            {ANALYSIS_SECTIONS.map((sectionKey) => {
              const insights = output.sections?.[sectionKey] ?? [];
              return (
                <Card key={sectionKey}>
                  <CardHeader>
                    <CardTitle>{SECTION_LABELS[sectionKey]}</CardTitle>
                    <CardDescription>{insights.length} synthesized insight(s)</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {insights.length === 0 ? (
                      <p className="text-xs text-muted-foreground">No critical insights noted for this domain.</p>
                    ) : (
                      insights.map((ins, idx) => (
                        <div key={idx} className="space-y-2 rounded-md border bg-zinc-950/70 p-3">
                          <div className="flex items-center justify-between gap-2">
                            <SeverityBadge severity={ins.severity} />
                            {renderFindingChips(ins.finding_ids)}
                          </div>
                          <p className="text-xs leading-relaxed text-zinc-200">{ins.summary}</p>
                        </div>
                      ))
                    )}
                  </CardContent>
                </Card>
              );
            })}
          </div>

          {/* Risk Prioritization + Remediation Plan */}
          <div className="grid gap-4 lg:grid-cols-12">
            <Card className="lg:col-span-6">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <ListOrdered className="h-4 w-4 text-cyan-400" />
                  Risk Prioritization Ranking
                </CardTitle>
                <CardDescription>Ordered by exploitability and business impact</CardDescription>
              </CardHeader>
              <CardContent>
                {output.risk_prioritization.length === 0 ? (
                  <p className="text-xs text-muted-foreground">No prioritized items.</p>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-14">Rank</TableHead>
                        <TableHead>Findings</TableHead>
                        <TableHead>Rationale</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {output.risk_prioritization.map((item) => (
                        <TableRow key={item.rank}>
                          <TableCell className="font-mono text-xs font-bold text-cyan-300">
                            #{item.rank}
                          </TableCell>
                          <TableCell>{renderFindingChips(item.finding_ids)}</TableCell>
                          <TableCell className="text-xs text-zinc-300">{item.rationale}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>

            <Card className="lg:col-span-6">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Wrench className="h-4 w-4 text-emerald-400" />
                  Phased Remediation Plan
                </CardTitle>
                <CardDescription>Actionable engineering tasks tied to finding keys</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {output.remediation_plan.length === 0 ? (
                  <p className="text-xs text-muted-foreground">No remediation actions required.</p>
                ) : (
                  output.remediation_plan.map((plan, idx) => {
                    const meta = PRIORITY_BADGE[plan.priority] ?? PRIORITY_BADGE.short_term;
                    return (
                      <div key={idx} className="space-y-2 rounded-md border bg-zinc-950/70 p-3">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <Badge variant={meta.variant}>{meta.label}</Badge>
                          {renderFindingChips(plan.finding_ids)}
                        </div>
                        <p className="text-xs leading-relaxed text-zinc-200">{plan.action}</p>
                      </div>
                    );
                  })
                )}
              </CardContent>
            </Card>
          </div>

          {/* Limitations */}
          {output.limitations.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-xs uppercase tracking-wider text-muted-foreground">
                  <Info className="h-3.5 w-3.5 text-cyan-400" />
                  Assessment Scope & Limitations
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ul className="list-disc space-y-1 pl-5 text-xs text-muted-foreground">
                  {output.limitations.map((lim, i) => (
                    <li key={i}>{lim}</li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          )}
        </div>
      ) : null}

      <FindingSheet
        finding={selectedFinding}
        open={!!selectedFinding}
        onOpenChange={(o) => !o && setSelectedFinding(null)}
      />
    </div>
  );
}
