"use client";

import * as React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { FileCode2, FolderGit2, Upload } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/menus";
import {
  CategoryBadge,
  EmptyState,
  ErrorBanner,
  FindingStatusBadge,
  SeverityBadge,
  VerificationStatusBadge,
} from "@/components/status-badges";
import { ScanSelector } from "@/components/scan-selector";
import { FindingSheet } from "@/components/finding-sheet";
import { FindingsTableView } from "@/components/findings-view";
import { useActiveScan } from "@/components/providers";
import { api, errorMessage } from "@/lib/api";
import { bySeverity, SOURCE_CATEGORIES } from "@/lib/constants";
import type { Finding } from "@/lib/types";

export default function SourceAuditPage() {
  const { selectedScanId } = useActiveScan();
  const [selectedFinding, setSelectedFinding] = React.useState<Finding | null>(null);

  const findingsQuery = useQuery({
    queryKey: ["findings", selectedScanId, "source-audit"],
    queryFn: () => api.listFindings(selectedScanId),
    enabled: !!selectedScanId,
  });

  const sourceFindings = React.useMemo(() => {
    const set = new Set(SOURCE_CATEGORIES);
    return (findingsQuery.data?.items ?? []).filter((f) => set.has(f.category)).sort(bySeverity);
  }, [findingsQuery.data]);

  const groupedByFile = React.useMemo(() => {
    const map = new Map<string, Finding[]>();
    for (const f of sourceFindings) {
      const fileKey = f.evidence.find((e) => e.location)?.location || f.affected || "General / Project Root";
      const group = map.get(fileKey) ?? [];
      group.push(f);
      map.set(fileKey, group);
    }
    return Array.from(map.entries());
  }, [sourceFindings]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-zinc-100">Source Code & Database Policy Audit</h1>
          <p className="text-xs text-muted-foreground">
            Static analysis findings (`source_code`) and BaaS/Supabase RLS policy flaws (`database_policy`) grouped by
            source file with redacted code snippets.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <ScanSelector />
          <Button asChild variant="outline" size="sm">
            <Link href="/scans/new">
              <Upload className="h-3.5 w-3.5" />
              Upload Source ZIP
            </Link>
          </Button>
        </div>
      </div>

      {findingsQuery.isError && (
        <ErrorBanner
          message={errorMessage(findingsQuery.error)}
          onRetry={() => void findingsQuery.refetch()}
        />
      )}

      {!selectedScanId ? (
        <EmptyState
          icon={<FileCode2 className="h-5 w-5" />}
          title="No scan selected"
          description="Select a scan or launch a scan with a white-box source ZIP archive attached."
        />
      ) : sourceFindings.length === 0 && !findingsQuery.isLoading ? (
        <EmptyState
          icon={<FileCode2 className="h-5 w-5" />}
          title="No source code or database policy findings in this scan"
          description="Upload a repository ZIP archive on the New Scan page or enable Supabase RLS policy checks to populate source audit results."
          action={
            <Button asChild size="sm">
              <Link href="/scans/new">Run Scan with Source ZIP</Link>
            </Button>
          }
        />
      ) : (
        <Tabs defaultValue="grouped">
          <TabsList>
            <TabsTrigger value="grouped">
              <FolderGit2 className="h-3.5 w-3.5" />
              Grouped by File ({groupedByFile.length} files)
            </TabsTrigger>
            <TabsTrigger value="table">
              <FileCode2 className="h-3.5 w-3.5" />
              All Source & Policy Findings ({sourceFindings.length})
            </TabsTrigger>
          </TabsList>

          <TabsContent value="grouped" className="space-y-4">
            {groupedByFile.map(([filePath, list]) => (
              <Card key={filePath} className="overflow-hidden">
                <CardHeader className="border-b border-zinc-800/80 bg-zinc-900/50 py-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <CardTitle className="font-mono text-xs text-cyan-300">{filePath}</CardTitle>
                    <CardDescription className="text-xs">
                      {list.length} finding{list.length > 1 ? "s" : ""}
                    </CardDescription>
                  </div>
                </CardHeader>
                <CardContent className="divide-y divide-zinc-800/70 p-0">
                  {list.map((f) => {
                    const snippet = f.evidence.find((e) => e.snippet)?.snippet;
                    return (
                      <div
                        key={f.id}
                        onClick={() => setSelectedFinding(f)}
                        className="cursor-pointer space-y-2 p-4 transition hover:bg-zinc-900/50"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-mono text-xs text-cyan-300">{f.finding_key}</span>
                            <SeverityBadge severity={f.severity} />
                            <FindingStatusBadge status={f.status} />
                            <VerificationStatusBadge status={f.verification_status} />
                            <CategoryBadge category={f.category} />
                            <span className="font-mono text-xs text-muted-foreground">{f.rule_id}</span>
                          </div>
                        </div>
                        <p className="text-sm font-medium text-zinc-100">{f.title}</p>
                        <p className="text-xs text-muted-foreground">{f.remediation}</p>
                        {snippet && (
                          <pre className="max-h-48 overflow-auto rounded border border-zinc-800 bg-black/80 p-3 font-mono text-xs leading-relaxed text-zinc-200">
                            <code>{snippet}</code>
                          </pre>
                        )}
                      </div>
                    );
                  })}
                </CardContent>
              </Card>
            ))}
          </TabsContent>

          <TabsContent value="table">
            <FindingsTableView
              findings={findingsQuery.data?.items ?? []}
              allowedCategories={SOURCE_CATEGORIES}
            />
          </TabsContent>
        </Tabs>
      )}

      <FindingSheet
        finding={selectedFinding}
        open={!!selectedFinding}
        onOpenChange={(o) => !o && setSelectedFinding(null)}
        onUpdated={(u) => setSelectedFinding(u)}
      />
    </div>
  );
}
