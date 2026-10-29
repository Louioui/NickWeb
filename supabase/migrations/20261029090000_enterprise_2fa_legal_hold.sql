-- ============================================================
-- Enterprise 2FA, Legal Hold, Chain-of-Custody & Append-Only Audit
-- Pillars 1, 2, 3, 4 Hardening
-- ============================================================

-- 1. Staff 2-Step Verification (TOTP Authenticator App Secrets)
create table if not exists public.admin_totp_secrets (
  email text primary key,
  secret text not null,
  enabled boolean not null default false,
  updated_at timestamptz not null default now()
);

alter table public.admin_totp_secrets enable row level security;

drop policy if exists "deny_all_admin_totp_secrets" on public.admin_totp_secrets;
create policy "deny_all_admin_totp_secrets" on public.admin_totp_secrets
  for all to anon, authenticated
  using (false)
  with check (false);

-- 2. Client Portal 2FA / Security PIN & Default Document Lock Settings
create table if not exists public.client_security_settings (
  email text primary key,
  pin_hash text,
  totp_secret text,
  totp_enabled boolean not null default false,
  doc_lock_default boolean not null default false,
  failed_tries int not null default 0,
  locked_until timestamptz,
  updated_at timestamptz not null default now()
);

alter table public.client_security_settings enable row level security;

drop policy if exists "deny_all_client_security_settings" on public.client_security_settings;
create policy "deny_all_client_security_settings" on public.client_security_settings
  for all to anon, authenticated
  using (false)
  with check (false);

-- 3. 2-Step Document Unlock Codes for Tracking Links
create table if not exists public.track_unlock_codes (
  order_id uuid primary key references public.orders(id) on delete cascade,
  code_hash text not null,
  tries int not null default 0,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

alter table public.track_unlock_codes enable row level security;

drop policy if exists "deny_all_track_unlock_codes" on public.track_unlock_codes;
create policy "deny_all_track_unlock_codes" on public.track_unlock_codes
  for all to anon, authenticated
  using (false)
  with check (false);

-- 4. Order-level Legal Hold & 2-Step Document Lock Columns
alter table public.orders
  add column if not exists legal_hold boolean not null default false,
  add column if not exists doc_lock boolean not null default false;

-- 5. Append-Only Protection on Critical Chain-of-Custody Events (attempt, attestation, proof)
create or replace function public.prevent_critical_event_mutation()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if tg_op = 'UPDATE' and old.kind in ('attempt', 'attestation', 'proof') then
    raise exception 'Chain-of-custody events (%) are immutable and append-only.', old.kind;
  end if;
  if tg_op = 'DELETE' and old.kind in ('attempt', 'attestation', 'proof') then
    -- Allow cascade deletion only when the parent order itself is already deleted
    if exists (select 1 from public.orders where id = old.order_id) then
      raise exception 'Chain-of-custody events (%) cannot be deleted individually.', old.kind;
    end if;
  end if;
  if tg_op = 'DELETE' then
    return old;
  end if;
  return new;
end;
$$;

drop trigger if exists trg_prevent_critical_event_mutation on public.order_events;
create trigger trg_prevent_critical_event_mutation
  before update or delete on public.order_events
  for each row execute function public.prevent_critical_event_mutation();
