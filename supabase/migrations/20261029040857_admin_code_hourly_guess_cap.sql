-- Per-code locking alone lets an attacker request fresh codes for Nick's (public) address and keep guessing.
-- This also caps wrong guesses across ALL of an address's codes at 25 per rolling hour. A lockout only blocks new
-- logins for that hour; sessions already signed in keep working.
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
  -- Serialize checks for this address so parallel requests can't all slip under the hourly cap.
  perform pg_advisory_xact_lock(hashtext('admin_code:' || p_email));

  select coalesce(sum(attempts), 0) into recent
    from admin_codes where email = p_email and created_at > now() - interval '1 hour';
  if recent >= 25 then
    return false;
  end if;

  select * into r from admin_codes
   where email = p_email and not used and expires_at > now()
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

-- How many codes were issued for an address in the last hour (the server refuses to send more than 10).
create or replace function public.admin_codes_last_hour(p_email text)
returns integer
language sql
security definer
set search_path to 'public'
as $$ select count(*)::integer from admin_codes where email = p_email and created_at > now() - interval '1 hour' $$;

revoke all on function public.admin_codes_last_hour(text) from public, anon, authenticated;
grant execute on function public.admin_codes_last_hour(text) to service_role;
