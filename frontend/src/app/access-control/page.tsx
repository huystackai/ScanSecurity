"use client";

import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { KeyRound } from "lucide-react";
import { ScanSelector } from "@/components/scan-selector";
import { FindingsTableView } from "@/components/findings-view";
import { EmptyState, ErrorBanner } from "@/components/status-badges";
import { useActiveScan } from "@/components/providers";
import { api, errorMessage } from "@/lib/api";

export default function AccessControlPage() {
  const { selectedScanId } = useActiveScan();

  const findingsQuery = useQuery({
    queryKey: ["findings", selectedScanId, "access-control"],
    queryFn: () => api.listFindings(selectedScanId),
    enabled: !!selectedScanId,
  });

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-zinc-100">Access Control & Authorization Findings</h1>
          <p className="text-xs text-muted-foreground">
            Unauthenticated admin access, missing server-side role verification, horizontal privilege escalation, and
            exposed privileged surfaces.
          </p>
        </div>
        <ScanSelector />
      </div>

      {findingsQuery.isError && (
        <ErrorBanner
          message={errorMessage(findingsQuery.error)}
          onRetry={() => void findingsQuery.refetch()}
        />
      )}

      {!selectedScanId ? (
        <EmptyState
          icon={<KeyRound className="h-5 w-5" />}
          title="No scan selected"
          description="Select a scan to inspect access control and administrative surface findings."
        />
      ) : (
        <FindingsTableView
          findings={findingsQuery.data?.items ?? []}
          allowedCategories={["access_control", "admin_surface"]}
          emptyTitle="No access control findings in this scan"
          emptyDescription="No unauthenticated admin endpoints or differential access control violations were observed."
        />
      )}
    </div>
  );
}
