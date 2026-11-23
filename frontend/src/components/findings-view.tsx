"use client";

import * as React from "react";
import { Search, ShieldAlert } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Input, NativeSelect } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  CategoryBadge,
  EmptyState,
  FindingStatusBadge,
  SeverityBadge,
  VerificationStatusBadge,
} from "@/components/status-badges";
import { FindingSheet } from "@/components/finding-sheet";
import {
  bySeverity,
  FINDING_CATEGORY_LABEL,
  FINDING_STATUS_LABEL,
  VERIFICATION_STATUS_LABEL,
} from "@/lib/constants";
import {
  FINDING_STATUSES,
  SEVERITIES,
  VERIFICATION_STATUSES,
  type Finding,
  type FindingCategory,
  type FindingStatus,
  type Severity,
  type VerificationStatus,
} from "@/lib/types";
import { formatPercent } from "@/lib/utils";

export function FindingsTableView({
  findings,
  allowedCategories,
  emptyTitle = "No findings matched your filters",
  emptyDescription = "Adjust the severity, status, or search filter, or select another scan.",
}: {
  findings: Finding[];
  allowedCategories?: FindingCategory[];
  emptyTitle?: string;
  emptyDescription?: string;
}) {
  const [search, setSearch] = React.useState("");
  const [severityFilter, setSeverityFilter] = React.useState<Severity | "all">("all");
  const [statusFilter, setStatusFilter] = React.useState<FindingStatus | "all">("all");
  const [triageFilter, setTriageFilter] = React.useState<VerificationStatus | "all">("all");
  const [categoryFilter, setCategoryFilter] = React.useState<FindingCategory | "all">("all");
  const [selected, setSelected] = React.useState<Finding | null>(null);

  const scoped = React.useMemo(() => {
    if (!allowedCategories || allowedCategories.length === 0) return findings;
    const set = new Set(allowedCategories);
    return findings.filter((f) => set.has(f.category));
  }, [findings, allowedCategories]);

  const filtered = React.useMemo(() => {
    const q = search.trim().toLowerCase();
    return scoped
      .filter((f) => {
        if (severityFilter !== "all" && f.severity !== severityFilter) return false;
        if (statusFilter !== "all" && f.status !== statusFilter) return false;
        if (triageFilter !== "all" && f.verification_status !== triageFilter) return false;
        if (categoryFilter !== "all" && f.category !== categoryFilter) return false;
        if (q) {
          const hay = `${f.finding_key} ${f.rule_id} ${f.title} ${f.affected}`.toLowerCase();
          if (!hay.includes(q)) return false;
        }
        return true;
      })
      .sort(bySeverity);
  }, [scoped, severityFilter, statusFilter, triageFilter, categoryFilter, search]);

  const counts = React.useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of scoped) {
      c[f.severity] = (c[f.severity] ?? 0) + 1;
    }
    return c;
  }, [scoped]);

  return (
    <div className="space-y-4">
      {/* Severity summary pills */}
      <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-5">
        {SEVERITIES.map((sev) => (
          <button
            key={sev}
            type="button"
            onClick={() => setSeverityFilter((prev) => (prev === sev ? "all" : sev))}
            className={`flex items-center justify-between rounded-lg border px-3 py-2 text-left transition ${
              severityFilter === sev
                ? "border-cyan-500/60 bg-cyan-500/10"
                : "border-border bg-card hover:bg-zinc-900/70"
            }`}
          >
            <SeverityBadge severity={sev} />
            <span className="font-mono text-base font-semibold text-zinc-100">{counts[sev]}</span>
          </button>
        ))}
      </div>

      {/* Filter bar */}
      <Card>
        <CardContent className="flex flex-wrap items-center gap-2.5 p-3">
          <div className="relative min-w-[220px] flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Filter by key, rule ID, title, or URL…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-8"
            />
          </div>
          {(!allowedCategories || allowedCategories.length > 1) && (
            <NativeSelect
              aria-label="Filter by category"
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value as FindingCategory | "all")}
              className="w-44"
            >
              <option value="all">All categories</option>
              {(allowedCategories ?? (Object.keys(FINDING_CATEGORY_LABEL) as FindingCategory[])).map((cat) => (
                <option key={cat} value={cat}>
                  {FINDING_CATEGORY_LABEL[cat]}
                </option>
              ))}
            </NativeSelect>
          )}
          <NativeSelect
            aria-label="Filter by severity"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value as Severity | "all")}
            className="w-36"
          >
            <option value="all">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s.toUpperCase()}
              </option>
            ))}
          </NativeSelect>
          <NativeSelect
            aria-label="Filter by finding status"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as FindingStatus | "all")}
            className="w-40"
          >
            <option value="all">All statuses</option>
            {FINDING_STATUSES.map((s) => (
              <option key={s} value={s}>
                {FINDING_STATUS_LABEL[s]}
              </option>
            ))}
          </NativeSelect>
          <NativeSelect
            aria-label="Filter by triage status"
            value={triageFilter}
            onChange={(e) => setTriageFilter(e.target.value as VerificationStatus | "all")}
            className="w-40"
          >
            <option value="all">All triage states</option>
            {VERIFICATION_STATUSES.map((s) => (
              <option key={s} value={s}>
                {VERIFICATION_STATUS_LABEL[s]}
              </option>
            ))}
          </NativeSelect>
        </CardContent>
      </Card>

      {/* Table */}
      {filtered.length === 0 ? (
        <EmptyState
          icon={<ShieldAlert className="h-5 w-5" />}
          title={emptyTitle}
          description={emptyDescription}
        />
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Key</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Title & Rule</TableHead>
                <TableHead>Category</TableHead>
                <TableHead>Affected Resource</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Triage</TableHead>
                <TableHead className="text-right">CVSS / Conf.</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((f) => (
                <TableRow
                  key={f.id}
                  onClick={() => setSelected(f)}
                  className="cursor-pointer"
                >
                  <TableCell className="font-mono text-xs text-cyan-300">{f.finding_key}</TableCell>
                  <TableCell>
                    <SeverityBadge severity={f.severity} />
                  </TableCell>
                  <TableCell className="max-w-xs">
                    <div className="font-medium text-zinc-100">{f.title}</div>
                    <div className="font-mono text-[11px] text-muted-foreground">{f.rule_id}</div>
                  </TableCell>
                  <TableCell>
                    <CategoryBadge category={f.category} />
                  </TableCell>
                  <TableCell className="max-w-[240px] truncate font-mono text-xs text-zinc-300">
                    {f.affected}
                  </TableCell>
                  <TableCell>
                    <FindingStatusBadge status={f.status} />
                  </TableCell>
                  <TableCell>
                    <VerificationStatusBadge status={f.verification_status} />
                  </TableCell>
                  <TableCell className="whitespace-nowrap text-right font-mono text-xs text-zinc-300">
                    {f.cvss_score != null ? `${f.cvss_score.toFixed(1)} · ` : ""}
                    {formatPercent(f.confidence)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      <FindingSheet
        finding={selected}
        open={!!selected}
        onOpenChange={(o) => !o && setSelected(null)}
        onUpdated={(updated) => setSelected(updated)}
      />
    </div>
  );
}
