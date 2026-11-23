"""Tests for Phase 4: safe ZIP extraction, zip-slip/symlink/zip-bomb protection, and static source analysis."""

from __future__ import annotations

import io
import zipfile

import pytest

from app.scanner.source_analysis import (
    UnsafeArchiveError,
    analyze_source_entries,
    extract_safe_zip_entries,
)


def _make_zip(files: dict[str, bytes], symlink_name: str | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
        if symlink_name:
            info = zipfile.ZipInfo(symlink_name)
            info.external_attr = 0o120777 << 16
            zf.writestr(info, b"/etc/passwd")
    return buf.getvalue()


class TestPhase4SourceCodeAnalysis:
    def test_rejects_zip_slip_symlinks_and_zip_bombs(self) -> None:
        slip_zip = _make_zip({"../../etc/passwd": b"root:x:0:0"})
        with pytest.raises(UnsafeArchiveError, match="traversal"):
            extract_safe_zip_entries(slip_zip)

        sym_zip = _make_zip({"src/index.ts": b"const x = 1;"}, symlink_name="src/link")
        with pytest.raises(UnsafeArchiveError, match="symbolic link"):
            extract_safe_zip_entries(sym_zip)

        bomb_zip = _make_zip({"src/huge.ts": b"A" * 50000})
        with pytest.raises(UnsafeArchiveError, match="uncompressed size"):
            extract_safe_zip_entries(bomb_zip, max_total_bytes=10000)

    async def test_detects_frontend_backend_and_database_rls_weaknesses(self) -> None:
        raw_openai = "sk-proj-" + "A" * 24 + "T3BlbkFJ" + "B" * 24
        files = {
            "src/pages/AdminPage.tsx": f"""
import React, {{ useState }} from 'react';
export function AdminPage({{ user }}) {{
  const [isAdmin, setIsAdmin] = useState(false);
  const role = localStorage.getItem("role");
  const key = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;
  const ai = "{raw_openai}";
  return <div>{{isAdmin && <button onClick={{() => fetch('/api/admin/deleteUser')}}>Delete</button>}}</div>;
}}
""".encode(),
            "app/api/admin/users/route.ts": b"""
import { NextResponse } from 'next/server';
export async function GET(req: Request) {
  try {
    return NextResponse.json({ users: [] });
  } catch (err: any) {
    return NextResponse.json({ error: err.stack }, { status: 500 });
  }
}
""",
            "app/api/upload/route.ts": b"""
import { NextResponse } from 'next/server';
export async function POST(req: Request) {
  const form = await req.formData();
  const file = form.get("file");
  return NextResponse.json({ ok: true });
}
""",
            "supabase/migrations/001_init.sql": b"""
CREATE TABLE public.customer_invoices (
  id uuid primary key,
  user_id uuid,
  amount integer
);
CREATE TABLE public.audit_events (
  id uuid primary key,
  payload jsonb
);
ALTER TABLE public.audit_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY "allow_all_writes" ON public.audit_events FOR ALL USING (true) WITH CHECK (true);
""",
            "firestore.rules": b"""
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;
    }
  }
}
""",
        }

        entries, count = extract_safe_zip_entries(_make_zip(files))
        assert count == 5
        drafts = await analyze_source_entries(entries, run_semgrep_if_available=False)
        rule_ids = {d.rule_id for d in drafts}

        assert "SRC-FE-LOCALSTORAGE-ROLE" in rule_ids
        assert "SRC-FE-REACT-STATE-ADMIN-GUARD" in rule_ids
        assert "SRC-FE-PUBLIC-ENV-SECRET" in rule_ids
        assert "SRC-FE-HIDDEN-ADMIN-CONTROL" in rule_ids
        assert "SRC-HARDCODED-SECRET" in rule_ids
        assert "SRC-BE-MISSING-AUTH-MIDDLEWARE" in rule_ids
        assert "SRC-BE-UNSAFE-ERROR-RESPONSE" in rule_ids
        assert "SRC-BE-INSECURE-FILE-UPLOAD" in rule_ids
        assert "SRC-DB-RLS-MISSING" in rule_ids
        assert "SRC-DB-RLS-OVERPERMISSIVE" in rule_ids
        assert "SRC-DB-FIRESTORE-ALLOW-TRUE" in rule_ids

        # Ensure the raw OpenAI key never appears unmasked in any draft evidence
        for d in drafts:
            for ev in d.evidence:
                assert raw_openai not in str(ev.get("snippet", ""))
                assert raw_openai not in str(ev.get("detail", ""))
