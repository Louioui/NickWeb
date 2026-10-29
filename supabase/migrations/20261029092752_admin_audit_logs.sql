-- Append-only, tamper-evident admin security audit log.
-- Records admin logins, failed attempts, recovery-code usage, data exports, and permanent order deletions.

create table if not exists public.admin_audit_logs (
  id uuid primary key default gen_random_uuid(),
  email text not null,
  action text not null,
  target_code text,
  detail text,
  ip_hash text,
  created_at timestamptz not null default now(),
  constraint admin_audit_logs_ip_hash_chk check (ip_hash is null or ip_hash ~ '^[0-9a-f]{64}$'),
  constraint admin_audit_logs_target_code_chk check (target_code is null or target_code ~ '^NP-[0-9]{6}$')
);

create index if not exists admin_audit_logs_email_created_idx
  on public.admin_audit_logs (email, created_at desc);

alter table public.admin_audit_logs enable row level security;

revoke all on table public.admin_audit_logs from public, anon, authenticated;

drop policy if exists "deny public roles" on public.admin_audit_logs;
create policy "deny public roles" on public.admin_audit_logs
  as restrictive
  for all
  to anon, authenticated
  using (false)
  with check (false);

create or replace function public.prevent_audit_log_mutation()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  raise exception 'admin_audit_logs is append-only and cannot be modified or deleted';
end;
$$;

revoke all on function public.prevent_audit_log_mutation() from public, anon, authenticated;

drop trigger if exists admin_audit_logs_immutable_trg on public.admin_audit_logs;
create trigger admin_audit_logs_immutable_trg
  before update or delete on public.admin_audit_logs
  for each row execute function public.prevent_audit_log_mutation();
