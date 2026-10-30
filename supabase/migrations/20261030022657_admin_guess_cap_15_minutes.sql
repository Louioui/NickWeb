-- Shortens the wrong-guess cap for Nick's login codes from one hour to 15 minutes.
-- Limit: 25 wrong guesses across all of an address's codes in a rolling 15 minutes (was 25 in an hour).
-- A lockout now lasts at most 15 minutes. Sessions already signed in are unaffected.
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
    from admin_codes where email = p_email and created_at > now() - interval '15 minutes';
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
