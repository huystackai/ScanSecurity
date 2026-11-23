"use client";

import * as React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  PlusCircle,
  Radar,
  Crosshair,
  ShieldAlert,
  KeyRound,
  Settings2,
  Webhook,
  FileCode2,
  Sparkles,
  FileText,
  Sliders,
  LogOut,
  Shield,
  ShieldCheck,
  Menu,
} from "lucide-react";
import { useAuth } from "@/components/providers";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Sheet, SheetContent, SheetTitle } from "@/components/ui/dialog";
import { cn } from "@/lib/utils";

interface NavItem {
  href: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  matchPrefix?: boolean;
}

const NAV_GROUPS: { group: string; items: NavItem[] }[] = [
  {
    group: "Operations",
    items: [
      { href: "/", label: "Dashboard", icon: LayoutDashboard },
      { href: "/scans/new", label: "New Scan", icon: PlusCircle },
      { href: "/scans", label: "Scans", icon: Radar, matchPrefix: true },
      { href: "/targets", label: "Target Inventory", icon: Crosshair, matchPrefix: true },
    ],
  },
  {
    group: "Attack Surface & Findings",
    items: [
      { href: "/pentest", label: "Pentest & Sensitive Data", icon: ShieldCheck },
      { href: "/admin-surfaces", label: "Admin Surfaces", icon: ShieldAlert },
      { href: "/access-control", label: "Access Control", icon: KeyRound },
      { href: "/configuration", label: "Configuration Audit", icon: Settings2 },
      { href: "/api-explorer", label: "API Explorer", icon: Webhook },
      { href: "/source-audit", label: "Source Code Audit", icon: FileCode2 },
    ],
  },
  {
    group: "Intelligence & Output",
    items: [
      { href: "/ai-analysis", label: "AI Security Analysis", icon: Sparkles },
      { href: "/reports", label: "Reports", icon: FileText },
      { href: "/settings", label: "Settings & Audit", icon: Sliders },
    ],
  },
];

function SidebarContent({ onNavigate }: { onNavigate?: () => void }) {
  const pathname = usePathname();
  const { operator, logout } = useAuth();

  const isActive = (item: NavItem) => {
    if (item.href === "/") return pathname === "/";
    if (item.href === "/scans" && pathname === "/scans/new") return false;
    return item.matchPrefix ? pathname?.startsWith(item.href) : pathname === item.href;
  };

  return (
    <div className="flex h-full flex-col justify-between bg-zinc-950 text-zinc-200">
      <div>
        {/* Brand header */}
        <div className="flex h-14 items-center justify-between border-b border-zinc-800/80 px-4">
          <Link href="/" onClick={onNavigate} className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-md border border-cyan-500/40 bg-cyan-500/15 text-cyan-400">
              <Shield className="h-4 w-4" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="text-sm font-bold tracking-tight text-zinc-100">VibeScan</span>
                <span className="rounded bg-cyan-500/15 px-1.5 py-0.2 font-mono text-[10px] font-semibold text-cyan-300">
                  DEFENSIVE
                </span>
              </div>
              <p className="text-[10px] text-muted-foreground">Web & AI App Security Audit</p>
            </div>
          </Link>
        </div>

        {/* Navigation groups */}
        <nav className="space-y-5 px-3 py-4">
          {NAV_GROUPS.map((g) => (
            <div key={g.group}>
              <p className="mb-1.5 px-2.5 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
                {g.group}
              </p>
              <ul className="space-y-0.5">
                {g.items.map((item) => {
                  const Icon = item.icon;
                  const active = isActive(item);
                  return (
                    <li key={item.href}>
                      <Link
                        href={item.href}
                        onClick={onNavigate}
                        className={cn(
                          "flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors",
                          active
                            ? "border border-cyan-500/30 bg-cyan-500/10 text-cyan-300"
                            : "text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200",
                        )}
                      >
                        <Icon className={cn("h-4 w-4 shrink-0", active ? "text-cyan-400" : "text-zinc-500")} />
                        <span>{item.label}</span>
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </nav>
      </div>

      {/* Operator footer */}
      <div className="border-t border-zinc-800/80 p-3">
        {operator ? (
          <div className="flex items-center justify-between gap-2 rounded-md border border-zinc-800/80 bg-zinc-900/50 px-2.5 py-2">
            <div className="min-w-0">
              <div className="flex items-center gap-1.5">
                <p className="truncate text-xs font-medium text-zinc-200">{operator.display_name}</p>
                <Badge variant="outline" className="px-1 py-0 text-[10px] uppercase">
                  {operator.role}
                </Badge>
              </div>
              <p className="truncate font-mono text-[11px] text-muted-foreground">{operator.email}</p>
            </div>
            <Button
              variant="ghost"
              size="icon-sm"
              title="Sign out"
              onClick={() => void logout()}
              className="text-zinc-400 hover:text-rose-300"
            >
              <LogOut className="h-3.5 w-3.5" />
            </Button>
          </div>
        ) : (
          <Button asChild variant="outline" size="sm" className="w-full">
            <Link href="/login">Sign In</Link>
          </Button>
        )}
      </div>
    </div>
  );
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = React.useState(false);

  if (pathname?.startsWith("/login")) {
    return <main className="min-h-screen bg-cyber-grid">{children}</main>;
  }

  return (
    <div className="flex min-h-screen bg-background">
      {/* Desktop sidebar */}
      <aside className="hidden w-60 shrink-0 border-r border-zinc-800/80 lg:block">
        <div className="sticky top-0 h-screen overflow-y-auto">
          <SidebarContent />
        </div>
      </aside>

      {/* Mobile drawer */}
      <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
        <SheetContent side="left" className="w-64 p-0">
          <SheetTitle className="sr-only">Navigation Menu</SheetTitle>
          <SidebarContent onNavigate={() => setMobileOpen(false)} />
        </SheetContent>
      </Sheet>

      {/* Main area */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-12 items-center justify-between border-b border-zinc-800/80 bg-zinc-950/85 px-4 backdrop-blur lg:hidden">
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="icon-sm" onClick={() => setMobileOpen(true)}>
              <Menu className="h-4 w-4" />
            </Button>
            <span className="text-sm font-bold text-zinc-100">VibeScan</span>
          </div>
          <Button asChild size="sm" variant="outline" className="h-7 text-xs">
            <Link href="/scans/new">New Scan</Link>
          </Button>
        </header>

        <main className="flex-1 bg-cyber-grid p-4 sm:p-6">
          <div className="mx-auto max-w-[1440px] space-y-6">{children}</div>
        </main>
      </div>
    </div>
  );
}
