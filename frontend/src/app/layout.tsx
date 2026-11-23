import type { Metadata } from "next";
import "./globals.css";
import { Providers } from "@/components/providers";
import { AppShell } from "@/components/app-shell";

export const metadata: Metadata = {
  title: "VibeScan — Authorized Web & AI App Security Auditing",
  description:
    "Defensive security auditing platform for modern web applications, AI-generated apps, and BaaS deployments.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-background font-sans text-foreground">
        <Providers>
          <AppShell>{children}</AppShell>
        </Providers>
      </body>
    </html>
  );
}
