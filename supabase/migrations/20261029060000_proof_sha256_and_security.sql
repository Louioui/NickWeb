-- Phase 2: Chain-of-custody SHA-256 fingerprints on uploaded files & single-use admin backup recovery codes

alter table public.order_files
  add column if not exists sha256 text;

create table if not exists public.admin_recovery_codes (
  id uuid primary key default gen_random_uuid(),
  email text not null,
  code_hash text not null,
  used boolean not null default false,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists admin_recovery_codes_email_idx
  on public.admin_recovery_codes (email, used);

alter table public.admin_recovery_codes enable row level security;

revoke all on table public.admin_recovery_codes from public, anon, authenticated;

drop policy if exists "deny public roles" on public.admin_recovery_codes;
create policy "deny public roles" on public.admin_recovery_codes
  as restrictive
  for all
  to anon, authenticated
  using (false)
  with check (false);

create or replace function public.use_admin_recovery_code(p_email text, p_hash text)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_id uuid;
begin
  update public.admin_recovery_codes
     set used = true,
         used_at = now()
   where id = (
     select id
       from public.admin_recovery_codes
      where email = p_email
        and code_hash = p_hash
        and used = false
      limit 1
      for update
   )
  returning id into v_id;

  return v_id is not null;
end;
$$;

revoke all on function public.use_admin_recovery_code(text, text) from public, anon, authenticated;
grant execute on function public.use_admin_recovery_code(text, text) to service_role;
