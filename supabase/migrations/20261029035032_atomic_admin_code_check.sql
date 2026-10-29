-- Checks a dashboard login code in one locked step, so parallel guesses can't get more than 5 tries at a code.
create or replace function public.use_admin_code(p_email text, p_hash text)
returns boolean
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  r admin_codes%rowtype;
begin
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
