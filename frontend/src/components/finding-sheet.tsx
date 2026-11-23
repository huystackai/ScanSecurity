"use client";

import * as React from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ExternalLink, ShieldCheck, FileCode, Terminal, BookOpen, CheckCircle2 } from "lucide-react";
import {
  Sheet,
  SheetBody,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/form-controls";
import { NativeSelect, Textarea } from "@/components/ui/input";
import {
  CategoryBadge,
  CopyButton,
  ErrorBanner,
  FindingStatusBadge,
  SeverityBadge,
  VerificationStatusBadge,
} from "@/components/status-badges";
import { api, errorMessage } from "@/lib/api";
import { VERIFICATION_STATUS_LABEL } from "@/lib/constants";
import { VERIFICATION_STATUSES, type Finding, type VerificationStatus } from "@/lib/types";
import { formatDate, formatPercent, safeHref } from "@/lib/utils";

export function FindingSheet({
  finding,
  open,
  onOpenChange,
  onUpdated,
}: {
  finding: Finding | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onUpdated?: (updated: Finding) => void;
}) {
  const queryClient = useQueryClient();
  const [verificationStatus, setVerificationStatus] = React.useState<VerificationStatus>("unverified");
  const [operatorNote, setOperatorNote] = React.useState("");
  const [savedToast, setSavedToast] = React.useState(false);

  React.useEffect(() => {
    if (finding) {
      setVerificationStatus(finding.verification_status);
      setOperatorNote(finding.operator_note ?? "");
      setSavedToast(false);
    }
  }, [finding]);

  const mutation = useMutation({
    mutationFn: (id: string) =>
      api.updateFinding(id, {
        verification_status: verificationStatus,
        operator_note: operatorNote.trim() ? operatorNote.trim() : null,
      }),
    onSuccess: (updated) => {
      setSavedToast(true);
      setTimeout(() => setSavedToast(false), 2000);
      queryClient.invalidateQueries({ queryKey: ["findings"] });
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      onUpdated?.(updated);
    },
  });

  if (!finding) return null;

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="sm:max-w-2xl">
        <SheetHeader>
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded bg-zinc-800 px-2 py-0.5 font-mono text-xs text-cyan-300">
              {finding.finding_key}
            </span>
            <SeverityBadge severity={finding.severity} />
            <FindingStatusBadge status={finding.status} />
            <VerificationStatusBadge status={finding.verification_status} />
            <CategoryBadge category={finding.category} />
          </div>
          <SheetTitle className="mt-1 text-base leading-snug">{finding.title}</SheetTitle>
          <SheetDescription className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
            <span>
              Rule: <code className="font-mono text-zinc-300">{finding.rule_id}</code>
            </span>
            <span>Confidence: {formatPercent(finding.confidence)}</span>
            {finding.cvss_score != null && (
              <span>
                CVSS:{" "}
                <strong className="font-mono text-zinc-200">{finding.cvss_score.toFixed(1)}</strong>
              </span>
            )}
            <span>Detected: {formatDate(finding.created_at)}</span>
          </SheetDescription>
        </SheetHeader>

        <SheetBody className="space-y-5 text-sm">
          {/* Affected resource */}
          <div className="rounded-md border bg-zinc-950/70 p-3">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                Affected Resource
              </span>
              <CopyButton value={finding.affected} label="Copy target" />
            </div>
            <p className="mt-1 break-all font-mono text-xs text-zinc-200">{finding.affected}</p>
            {finding.cvss_vector && (
              <p className="mt-1.5 break-all font-mono text-[11px] text-muted-foreground">
                {finding.cvss_vector}
              </p>
            )}
          </div>

          {/* Detection & Impact */}
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-md border bg-zinc-900/40 p-3">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Detection Method
              </h4>
              <p className="mt-1 text-xs leading-relaxed text-zinc-300">
                {finding.detection_method || "Automated passive/defensive heuristic inspection."}
              </p>
            </div>
            <div className="rounded-md border bg-zinc-900/40 p-3">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Security Impact
              </h4>
              <p className="mt-1 text-xs leading-relaxed text-zinc-300">
                {finding.impact || "Potential exposure of privileged functionality or sensitive configuration."}
              </p>
            </div>
          </div>

          {/* Evidence list */}
          <div className="space-y-2">
            <h4 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              <FileCode className="h-3.5 w-3.5 text-cyan-400" />
              Evidence ({finding.evidence.length})
            </h4>
            {finding.evidence.length === 0 ? (
              <p className="text-xs text-muted-foreground">No structured evidence attached.</p>
            ) : (
              <div className="space-y-2.5">
                {finding.evidence.map((ev, idx) => (
                  <div key={idx} className="rounded-md border bg-zinc-950/80 p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                      <span className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-[11px] text-cyan-300">
                        {ev.type}
                      </span>
                      {ev.location && (
                        <span className="truncate font-mono text-[11px] text-muted-foreground">
                          {ev.location}
                        </span>
                      )}
                    </div>
                    <p className="mt-1.5 text-xs text-zinc-200">{ev.detail}</p>
                    {ev.snippet && (
                      <pre className="mt-2 max-h-56 overflow-auto rounded border border-zinc-800 bg-black/70 p-2.5 font-mono text-[11px] leading-relaxed text-zinc-300">
                        <code>{ev.snippet}</code>
                      </pre>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Safe Reproduction Steps */}
          {finding.reproduction.length > 0 && (
            <div className="space-y-2">
              <h4 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                <Terminal className="h-3.5 w-3.5 text-cyan-400" />
                Safe Verification / Reproduction Steps
              </h4>
              <p className="text-[11px] text-muted-foreground">
                Read-only verification commands for authorized operators. Run only against verified targets.
              </p>
              <div className="space-y-2">
                {finding.reproduction.map((step, i) => (
                  <div
                    key={i}
                    className="flex items-start justify-between gap-2 rounded-md border border-zinc-800 bg-black/60 p-2.5"
                  >
                    <pre className="overflow-x-auto whitespace-pre-wrap break-all font-mono text-xs text-zinc-200">
                      <code>{step}</code>
                    </pre>
                    <CopyButton value={step} label="Copy" />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Remediation */}
          <div className="rounded-md border border-emerald-500/30 bg-emerald-500/5 p-3.5">
            <h4 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-emerald-300">
              <ShieldCheck className="h-4 w-4 text-emerald-400" />
              Recommended Remediation
            </h4>
            <p className="mt-1.5 whitespace-pre-line text-xs leading-relaxed text-zinc-200">
              {finding.remediation || "Enforce server-side authentication and role checks on this resource."}
            </p>
          </div>

          {/* References */}
          {finding.references.length > 0 && (
            <div className="space-y-1.5">
              <h4 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                <BookOpen className="h-3.5 w-3.5 text-cyan-400" />
                References
              </h4>
              <ul className="space-y-1 text-xs">
                {finding.references.map((ref, idx) => {
                  const href = safeHref(ref.url);
                  return (
                    <li key={idx}>
                      {href ? (
                        <a
                          href={href}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-cyan-400 hover:underline"
                        >
                          {ref.title || ref.url}
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      ) : (
                        <span className="text-zinc-300">{ref.title}</span>
                      )}
                    </li>
                  );
                })}
              </ul>
            </div>
          )}

          {/* Operator Triage (PATCH /findings/{id}) */}
          <div className="rounded-lg border bg-zinc-900/60 p-4">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-200">
              Operator Triage & Verification
            </h4>
            <p className="mt-0.5 text-xs text-muted-foreground">
              Record manual verification status and triage notes for audit tracking.
            </p>

            {mutation.isError && (
              <div className="mt-3">
                <ErrorBanner message={errorMessage(mutation.error)} />
              </div>
            )}

            <div className="mt-3 grid gap-3">
              <div className="space-y-1.5">
                <Label htmlFor="finding-verification-status">Verification Status</Label>
                <NativeSelect
                  id="finding-verification-status"
                  value={verificationStatus}
                  onChange={(e) => setVerificationStatus(e.target.value as VerificationStatus)}
                >
                  {VERIFICATION_STATUSES.map((s) => (
                    <option key={s} value={s}>
                      {VERIFICATION_STATUS_LABEL[s]}
                    </option>
                  ))}
                </NativeSelect>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="finding-operator-note">Operator Note</Label>
                <Textarea
                  id="finding-operator-note"
                  placeholder="Add verification details, ticket ID, or compensating control notes…"
                  value={operatorNote}
                  onChange={(e) => setOperatorNote(e.target.value)}
                />
              </div>
              <div className="flex items-center justify-between">
                {savedToast ? (
                  <span className="inline-flex items-center gap-1 text-xs text-emerald-400">
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    Triage status saved
                  </span>
                ) : (
                  <span />
                )}
                <Button
                  size="sm"
                  disabled={mutation.isPending}
                  onClick={() => mutation.mutate(finding.id)}
                >
                  {mutation.isPending ? "Saving…" : "Save Triage"}
                </Button>
              </div>
            </div>
          </div>
        </SheetBody>
      </SheetContent>
    </Sheet>
  );
}
