"use client";

import * as React from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Shield, Lock } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, SecretInput } from "@/components/ui/input";
import { Label } from "@/components/ui/form-controls";
import { Button } from "@/components/ui/button";
import { ErrorBanner } from "@/components/status-badges";
import { api, errorMessage, setCsrfToken } from "@/lib/api";
import { useAuth } from "@/components/providers";

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { refreshAuth } = useAuth();
  const [email, setEmail] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const session = await api.login({ email: email.trim(), password });
      setCsrfToken(session.csrf_token);
      await refreshAuth();
      const rawNext = searchParams.get("next") || "/";
      const next = rawNext.startsWith("/") && !rawNext.startsWith("//") ? rawNext : "/";
      router.replace(next);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-md border-zinc-800 bg-zinc-950/90 shadow-2xl">
        <CardHeader className="space-y-2 text-center">
          <div className="mx-auto flex h-11 w-11 items-center justify-center rounded-lg border border-cyan-500/40 bg-cyan-500/15 text-cyan-400">
            <Shield className="h-5 w-5" />
          </div>
          <CardTitle className="text-lg">Sign in to VibeScan</CardTitle>
          <CardDescription>
            Authorized defensive security auditing platform. Operator authentication is required.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {error && (
            <div className="mb-4">
              <ErrorBanner title="Authentication failed" message={error} />
            </div>
          )}
          <form onSubmit={onSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="login-email">Operator Email</Label>
              <Input
                id="login-email"
                type="email"
                required
                autoComplete="username"
                placeholder="operator@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="login-password">Password</Label>
              <SecretInput
                id="login-password"
                required
                placeholder="••••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            <Button type="submit" className="w-full" disabled={loading}>
              <Lock className="h-4 w-4" />
              {loading ? "Authenticating…" : "Sign In"}
            </Button>
          </form>
          <p className="mt-4 text-center text-[11px] text-muted-foreground">
            All sessions and scan authorizations are recorded in the platform audit log.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}

export default function LoginPage() {
  return (
    <React.Suspense fallback={<div className="flex min-h-screen items-center justify-center">Loading…</div>}>
      <LoginForm />
    </React.Suspense>
  );
}
