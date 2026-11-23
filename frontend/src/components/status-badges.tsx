"use client";

import * as React from "react";
import { Check, Copy, AlertTriangle, ShieldAlert, Info } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  AUTH_OBSERVATION_CLASS,
  AUTH_OBSERVATION_LABEL,
  AUTHZ_STATUS_CLASS,
  FINDING_CATEGORY_LABEL,
  FINDING_STATUS_CLASS,
  FINDING_STATUS_LABEL,
  SCAN_STATUS_CLASS,
  SEVERITY_CLASS,
  SEVERITY_DOT,
  VERIFICATION_STATUS_CLASS,
  VERIFICATION_STATUS_LABEL,
} from "@/lib/constants";
import type {
  AuthObservation,
  AuthorizationStatus,
  FindingCategory,
  FindingStatus,
  RiskLevel,
  ScanStatus,
  VerificationStatus,
} from "@/lib/types";
import { cn, humanize } from "@/lib/utils";

export function SeverityBadge({ severity, className }: { severity: RiskLevel; className?: string }) {
  return (
    <Badge className={cn("uppercase tracking-wider", SEVERITY_CLASS[severity] ?? SEVERITY_CLASS.none, className)}>
      <span className={cn("h-1.5 w-1.5 rounded-full", SEVERITY_DOT[severity] ?? SEVERITY_DOT.none)} />
      {severity}
    </Badge>
  );
}

export function FindingStatusBadge({ status, className }: { status: FindingStatus; className?: string }) {
  return (
    <Badge className={cn(FINDING_STATUS_CLASS[status], className)}>
      {FINDING_STATUS_LABEL[status] ?? humanize(status)}
    </Badge>
  );
}

export function VerificationStatusBadge({
  status,
  className,
}: {
  status: VerificationStatus;
  className?: string;
}) {
  return (
    <Badge className={cn(VERIFICATION_STATUS_CLASS[status], className)}>
      {VERIFICATION_STATUS_LABEL[status] ?? humanize(status)}
    </Badge>
  );
}

export function AuthObservationBadge({
  observation,
  className,
}: {
  observation: AuthObservation;
  className?: string;
}) {
  return (
    <Badge className={cn(AUTH_OBSERVATION_CLASS[observation], className)}>
      {AUTH_OBSERVATION_LABEL[observation] ?? humanize(observation)}
    </Badge>
  );
}

export function ScanStatusBadge({ status, className }: { status: ScanStatus; className?: string }) {
  return (
    <Badge className={cn("capitalize", SCAN_STATUS_CLASS[status], className)}>
      {status === "running" && <span className="h-1.5 w-1.5 animate-ping rounded-full bg-sky-400" />}
      {humanize(status)}
    </Badge>
  );
}

export function AuthzStatusBadge({
  status,
  className,
}: {
  status: AuthorizationStatus;
  className?: string;
}) {
  return (
    <Badge className={cn("capitalize", AUTHZ_STATUS_CLASS[status], className)}>
      {humanize(status)}
    </Badge>
  );
}

export function CategoryBadge({ category, className }: { category: FindingCategory; className?: string }) {
  return (
    <Badge variant="secondary" className={cn("font-normal text-zinc-300", className)}>
      {FINDING_CATEGORY_LABEL[category] ?? humanize(category)}
    </Badge>
  );
}

export function HttpStatusBadge({ code }: { code: number | null | undefined }) {
  if (code == null) {
    return <span className="font-mono text-xs text-muted-foreground">—</span>;
  }
  const color =
    code >= 500
      ? "border-rose-500/40 bg-rose-500/10 text-rose-300"
      : code >= 400
        ? "border-amber-500/40 bg-amber-500/10 text-amber-300"
        : code >= 300
          ? "border-sky-500/40 bg-sky-500/10 text-sky-300"
          : "border-emerald-500/40 bg-emerald-500/10 text-emerald-300";
  return <Badge className={cn("font-mono", color)}>{code}</Badge>;
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = React.useState(false);

  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      // Clipboard API unavailable
    }
  };

  return (
    <Button variant="outline" size="sm" onClick={onCopy} className="h-7 gap-1.5 px-2 text-xs">
      {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
      {copied ? "Copied" : label}
    </Button>
  );
}

export function ErrorBanner({
  title = "Error",
  message,
  onRetry,
}: {
  title?: string;
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div
      role="alert"
      className="flex items-start justify-between gap-3 rounded-lg border border-rose-500/40 bg-rose-500/10 p-3.5 text-sm text-rose-200"
    >
      <div className="flex items-start gap-2.5">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
        <div>
          <p className="font-medium text-rose-100">{title}</p>
          <p className="mt-0.5 text-xs text-rose-200/90">{message}</p>
        </div>
      </div>
      {onRetry && (
        <Button variant="outline" size="sm" onClick={onRetry} className="border-rose-500/40 text-rose-100">
          Retry
        </Button>
      )}
    </div>
  );
}

export function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-zinc-800 bg-zinc-950/40 px-6 py-12 text-center">
      <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-full border border-zinc-800 bg-zinc-900 text-muted-foreground">
        {icon ?? <Info className="h-5 w-5" />}
      </div>
      <h3 className="text-sm font-medium text-zinc-200">{title}</h3>
      {description && <p className="mt-1 max-w-md text-xs text-muted-foreground">{description}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function DefensiveNotice() {
  return (
    <div className="flex items-center gap-2 rounded-md border border-cyan-500/30 bg-cyan-500/10 px-3 py-2 text-xs text-cyan-200">
      <ShieldAlert className="h-4 w-4 shrink-0 text-cyan-400" />
      <span>
        Authorized defensive audit mode — passive and safe verification checks only. No exploit payloads or
        destructive requests are executed.
      </span>
    </div>
  );
}
