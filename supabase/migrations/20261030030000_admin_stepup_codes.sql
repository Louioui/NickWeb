-- Keep login codes and short-lived sensitive-action codes in separate namespaces.
alter table public.admin_codes add column if not exists purpose text not null default 'login';
alter table public.admin_codes add constraint admin_codes_purpose_check check (purpose in ('login', 'stepup'));
alter table public.admin_codes enable row level security;
revoke all on public.admin_codes from anon, authenticated;
drop policy if exists admin_codes_deny_public on public.admin_codes;
create policy admin_codes_deny_public on public.admin_codes as restrictive for all to anon, authenticated using (false) with check (false);

create or replace function public.use_admin_code(p_email text, p_hash text)
returns boolean language plpgsql security definer set search_path to 'public' as $$
declare r admin_codes%rowtype;
begin
  select * into r from admin_codes where email = p_email and purpose = 'login' and not used and expires_at > now()
    order by created_at desc limit 1 for update;
  if not found or r.attempts >= 5 then return false; end if;
  update admin_codes set attempts = r.attempts + 1, used = (r.code_hash = p_hash) where id = r.id;
  return r.code_hash = p_hash;
end $$;

create or replace function public.use_admin_stepup_code(p_email text, p_hash text)
returns boolean language plpgsql security definer set search_path to 'public' as $$
declare r admin_codes%rowtype;
begin
  select * into r from admin_codes where email = p_email and purpose = 'stepup' and not used and expires_at > now()
    order by created_at desc limit 1 for update;
  if not found or r.attempts >= 5 then return false; end if;
  update admin_codes set attempts = r.attempts + 1, used = (r.code_hash = p_hash) where id = r.id;
  return r.code_hash = p_hash;
end $$;

revoke all on function public.use_admin_code(text, text) from public, anon, authenticated;
grant execute on function public.use_admin_code(text, text) to service_role;
revoke all on function public.use_admin_stepup_code(text, text) from public, anon, authenticated;
grant execute on function public.use_admin_stepup_code(text, text) to service_role;
