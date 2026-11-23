"use client";

import * as React from "react";
import Link from "next/link";
import { ExternalLink, Radar } from "lucide-react";
import { useActiveScan } from "@/components/providers";
import { NativeSelect } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { ScanStatusBadge } from "@/components/status-badges";
import { formatDate } from "@/lib/utils";

export function ScanSelector({ className }: { className?: string }) {
  const { scans, selectedScanId, setSelectedScanId, selectedScan, isLoadingScans } = useActiveScan();

  if (isLoadingScans) {
    return <div className="h-9 w-64 animate-pulse rounded-md bg-zinc-800/70" />;
  }

  if (!scans.length) {
    return (
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <span>No scans recorded yet.</span>
        <Button asChild size="sm" variant="outline">
          <Link href="/scans/new">Launch New Scan</Link>
        </Button>
      </div>
    );
  }

  return (
    <div className={`flex flex-wrap items-center gap-2 ${className ?? ""}`}>
      <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
        <Radar className="h-3.5 w-3.5 text-cyan-400" />
        <span className="font-medium text-zinc-300">Active Scan:</span>
      </div>
      <NativeSelect
        aria-label="Select scan"
        value={selectedScanId}
        onChange={(e) => setSelectedScanId(e.target.value)}
        className="h-8 w-auto min-w-[260px] text-xs"
      >
        {scans.map((s) => (
          <option key={s.id} value={s.id}>
            {s.target_name} — {s.status.toUpperCase()} ({formatDate(s.created_at)}) [{s.stats.findings_total ?? 0}{" "}
            findings]
          </option>
        ))}
      </NativeSelect>
      {selectedScan && (
        <>
          <ScanStatusBadge status={selectedScan.status} />
          <Button asChild variant="ghost" size="sm" className="h-8 px-2 text-xs text-cyan-400">
            <Link href={`/scans/${selectedScan.id}`}>
              Scan details
              <ExternalLink className="h-3 w-3" />
            </Link>
          </Button>
        </>
      )}
    </div>
  );
}
