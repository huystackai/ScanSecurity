"use client";

import * as React from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Crosshair, Plus, Trash2, ShieldCheck, ExternalLink } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/form-controls";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { AuthzStatusBadge, EmptyState, ErrorBanner } from "@/components/status-badges";
import { api, errorMessage } from "@/lib/api";
import { formatDate, humanize } from "@/lib/utils";

export default function TargetsPage() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const [dialogOpen, setDialogOpen] = React.useState(false);
  const [name, setName] = React.useState("");
  const [baseUrl, setBaseUrl] = React.useState("");
  const [allowedHosts, setAllowedHosts] = React.useState("");

  const targetsQuery = useQuery({
    queryKey: ["targets"],
    queryFn: () => api.listTargets(),
  });

  const createMutation = useMutation({
    mutationFn: () => {
      const hosts = allowedHosts
        .split(",")
        .map((h) => h.trim())
        .filter(Boolean);
      return api.createTarget({
        name: name.trim(),
        base_url: baseUrl.trim(),
        ...(hosts.length ? { allowed_hosts: hosts } : {}),
      });
    },
    onSuccess: (created) => {
      queryClient.invalidateQueries({ queryKey: ["targets"] });
      setDialogOpen(false);
      setName("");
      setBaseUrl("");
      setAllowedHosts("");
      router.push(`/targets/${created.id}`);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteTarget(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["targets"] });
    },
  });

  const targets = targetsQuery.data?.items ?? [];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-zinc-100">Target Inventory</h1>
          <p className="text-xs text-muted-foreground">
            Register web applications, verify domain ownership, configure scope limits, and store write-only test
            credentials.
          </p>
        </div>

        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button size="sm">
              <Plus className="h-4 w-4" />
              Add Target
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Register New Target</DialogTitle>
              <DialogDescription>
                Add an application you own or are explicitly authorized to test. Ownership verification is required
                before scanning.
              </DialogDescription>
            </DialogHeader>
            {createMutation.isError && <ErrorBanner message={errorMessage(createMutation.error)} />}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                createMutation.mutate();
              }}
              className="space-y-3.5"
            >
              <div className="space-y-1.5">
                <Label htmlFor="target-name">Application Name</Label>
                <Input
                  id="target-name"
                  required
                  placeholder="My Lovable / Next.js SaaS"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="target-url">Base URL</Label>
                <Input
                  id="target-url"
                  type="url"
                  required
                  placeholder="https://app.example.com"
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="target-hosts">Allowed Hosts (comma-separated, optional)</Label>
                <Input
                  id="target-hosts"
                  placeholder="app.example.com, api.app.example.com"
                  value={allowedHosts}
                  onChange={(e) => setAllowedHosts(e.target.value)}
                />
              </div>
              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => setDialogOpen(false)}>
                  Cancel
                </Button>
                <Button type="submit" disabled={createMutation.isPending}>
                  {createMutation.isPending ? "Creating…" : "Create & Configure Verification"}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {targetsQuery.isError && (
        <ErrorBanner
          message={errorMessage(targetsQuery.error)}
          onRetry={() => void targetsQuery.refetch()}
        />
      )}

      {targets.length === 0 && !targetsQuery.isLoading ? (
        <EmptyState
          icon={<Crosshair className="h-5 w-5" />}
          title="No targets registered"
          description="Add a web application target and verify ownership via DNS TXT, well-known file, or HTML meta tag."
          action={
            <Button size="sm" onClick={() => setDialogOpen(true)}>
              <Plus className="h-4 w-4" />
              Register First Target
            </Button>
          }
        />
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Target Name</TableHead>
                <TableHead>Base URL & Allowed Hosts</TableHead>
                <TableHead>Authorization</TableHead>
                <TableHead>Method</TableHead>
                <TableHead>Test Roles</TableHead>
                <TableHead>Last Scan</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {targets.map((t) => (
                <TableRow key={t.id}>
                  <TableCell>
                    <Link href={`/targets/${t.id}`} className="font-medium text-zinc-100 hover:text-cyan-400">
                      {t.name}
                    </Link>
                  </TableCell>
                  <TableCell>
                    <div className="font-mono text-xs text-zinc-200">{t.base_url}</div>
                    <div className="font-mono text-[11px] text-muted-foreground">
                      Hosts: {t.allowed_hosts.join(", ")}
                    </div>
                  </TableCell>
                  <TableCell>
                    <AuthzStatusBadge status={t.authorization_status} />
                  </TableCell>
                  <TableCell className="text-xs text-zinc-300">
                    {t.verification_method ? humanize(t.verification_method) : "—"}
                  </TableCell>
                  <TableCell className="font-mono text-xs text-zinc-300">
                    {t.credential_roles.length ? t.credential_roles.join(", ") : "None"}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {formatDate(t.last_scan_at)}
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="inline-flex items-center gap-1.5">
                      <Button asChild variant="outline" size="sm" className="h-7 text-xs">
                        <Link href={`/targets/${t.id}`}>
                          <ShieldCheck className="h-3.5 w-3.5" />
                          Configure & Verify
                        </Link>
                      </Button>
                      {(t.authorization_status === "verified" || t.authorization_status === "attested") && (
                        <Button asChild size="sm" className="h-7 text-xs">
                          <Link href={`/scans/new?target=${t.id}`}>
                            Scan
                            <ExternalLink className="h-3 w-3" />
                          </Link>
                        </Button>
                      )}
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <Button variant="ghost" size="icon-sm" className="text-zinc-400 hover:text-rose-400">
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogTitle>Archive target &ldquo;{t.name}&rdquo;?</AlertDialogTitle>
                          <AlertDialogDescription>
                            Archiving removes this target from active scan selection while preserving historical audit
                            logs.
                          </AlertDialogDescription>
                          <div className="flex justify-end gap-2">
                            <AlertDialogCancel>Cancel</AlertDialogCancel>
                            <AlertDialogAction
                              destructive
                              onClick={() => deleteMutation.mutate(t.id)}
                            >
                              Archive Target
                            </AlertDialogAction>
                          </div>
                        </AlertDialogContent>
                      </AlertDialog>
                    </div>
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
