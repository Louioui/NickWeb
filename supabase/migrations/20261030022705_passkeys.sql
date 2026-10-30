-- Passkeys (WebAuthn) for clients and for Nick. Only public keys are stored: a passkey's private key never leaves the
-- person's phone, computer or security key. Challenges are single-use and expire after 5 minutes.
-- Same security pattern as the other tables: row-level security on, public roles denied.
create table if not exists public.webauthn_credentials (
  credential_id text primary key check (credential_id ~ '^[A-Za-z0-9_-]{16,1400}$'),
  owner_kind text not null check (owner_kind in ('client', 'admin')),
  owner_email text not null,
  owner_user_id uuid,                     -- clients: the Supabase user it was made for (a deleted account stays deleted)
  public_key text not null check (char_length(public_key) <= 2000),
  counter bigint not null default 0 check (counter >= 0),
  transports text[] not null default '{}',
  label text check (label is null or char_length(label) <= 80),
  created_at timestamptz not null default now(),
  last_used_at timestamptz
);
create index if not exists webauthn_credentials_owner_idx on public.webauthn_credentials (owner_kind, owner_email);

create table if not exists public.webauthn_challenges (
  id uuid primary key default gen_random_uuid(),
  owner_kind text not null check (owner_kind in ('client', 'admin')),
  owner_email text,                       -- null for a sign-in, where the passkey itself says who it is
  purpose text not null check (purpose in ('register', 'login')),
  challenge text not null check (challenge ~ '^[A-Za-z0-9_-]{32,128}$'),
  used boolean not null default false,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);
create index if not exists webauthn_challenges_expires_idx on public.webauthn_challenges (expires_at);

alter table public.webauthn_credentials enable row level security;
alter table public.webauthn_challenges enable row level security;
revoke all on table public.webauthn_credentials from public, anon, authenticated;
revoke all on table public.webauthn_challenges from public, anon, authenticated;
drop policy if exists "deny public roles" on public.webauthn_credentials;
create policy "deny public roles" on public.webauthn_credentials
  as restrictive for all to anon, authenticated using (false) with check (false);
drop policy if exists "deny public roles" on public.webauthn_challenges;
create policy "deny public roles" on public.webauthn_challenges
  as restrictive for all to anon, authenticated using (false) with check (false);
