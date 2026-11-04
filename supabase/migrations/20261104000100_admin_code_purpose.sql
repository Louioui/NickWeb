-- Keep Nick's login codes and his emailed step-up codes (sensitive dashboard actions without an authenticator) apart.
-- Both live in admin_codes. Before this, use_admin_code checked only an address's newest code, so a step-up code
-- requested on the dashboard took the place of a pending login code, and wrong guesses on the login page used up the
-- step-up code's five attempts (and the other way round). Each purpose now has its own newest code and its own
-- 25-wrong-guesses-in-15-minutes cap. The advisory lock and cap from 20261030022657 are kept unchanged.
-- Replaces the branch-only migration 20261030030000_admin_stepup_codes, which was never applied.
alter table public.admin_codes add column if not exists purpose text not null default 'login';
alter table public.admin_codes drop constraint if exists admin_codes_purpose_check;
alter table public.admin_codes add constraint admin_codes_purpose_check check (purpose in ('login', 'stepup'));

create or replace function public.use_admin_code(p_email text, p_hash text)
returns boolean
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  r admin_codes%rowtype;
  recent integer;
begin
  -- Serialize checks for this address so parallel requests can't all slip under the cap.
  perform pg_advisory_xact_lock(hashtext('admin_code:' || p_email));

  select coalesce(sum(attempts), 0) into recent
    from admin_codes where email = p_email and purpose = 'login' and created_at > now() - interval '15 minutes';
  if recent >= 25 then
    return false;
  end if;

  select * into r from admin_codes
   where email = p_email and purpose = 'login' and not used and expires_at > now()
   order by created_at desc limit 1
   for update;
  if not found or r.attempts >= 5 then
    return false;
  end if;
  update admin_codes
     set attempts = r.attempts + 1,
         used = (r.code_hash = p_hash)
   where id = r.id;
  return r.code_hash = p_hash;
end $$;

create or replace function public.use_admin_stepup_code(p_email text, p_hash text)
returns boolean
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  r admin_codes%rowtype;
  recent integer;
begin
  perform pg_advisory_xact_lock(hashtext('admin_stepup_code:' || p_email));

  select coalesce(sum(attempts), 0) into recent
    from admin_codes where email = p_email and purpose = 'stepup' and created_at > now() - interval '15 minutes';
  if recent >= 25 then
    return false;
  end if;

  select * into r from admin_codes
   where email = p_email and purpose = 'stepup' and not used and expires_at > now()
   order by created_at desc limit 1
   for update;
  if not found or r.attempts >= 5 then
    return false;
  end if;
  update admin_codes
     set attempts = r.attempts + 1,
         used = (r.code_hash = p_hash)
   where id = r.id;
  return r.code_hash = p_hash;
end $$;

revoke all on function public.use_admin_code(text, text) from public, anon, authenticated;
grant execute on function public.use_admin_code(text, text) to service_role;
revoke all on function public.use_admin_stepup_code(text, text) from public, anon, authenticated;
grant execute on function public.use_admin_stepup_code(text, text) to service_role;
