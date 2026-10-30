-- F-09: when the authenticator app is off, sensitive dashboard actions (delete a request, unlock legal hold, new recovery
-- codes, authenticator setup, passkey changes) need a fresh 8-digit code emailed to Nick, on top of the session cookie.
-- The code belongs to one signed-in session, allows 5 guesses, expires after 10 minutes, and a correct code confirms
-- sensitive actions on that session for 5 minutes (last_step_up_at).
alter table public.admin_sessions
  add column if not exists stepup_code_hash text check (stepup_code_hash is null or stepup_code_hash ~ '^[0-9a-f]{64}$'),
  add column if not exists stepup_expires_at timestamptz,
  add column if not exists stepup_attempts integer not null default 0 check (stepup_attempts >= 0),
  add column if not exists last_step_up_at timestamptz;

-- Checks a step-up code in one locked step, so parallel guesses can't share one attempt count.
create or replace function public.use_admin_stepup_code(p_token_hash text, p_code_hash text)
returns boolean
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  r admin_sessions%rowtype;
begin
  select * into r from admin_sessions where token_hash = p_token_hash for update;
  if not found or r.stepup_code_hash is null or r.stepup_expires_at is null
     or r.stepup_expires_at <= now() or r.stepup_attempts >= 5 then
    return false;
  end if;
  if r.stepup_code_hash = p_code_hash then
    update admin_sessions
       set stepup_code_hash = null, stepup_expires_at = null, stepup_attempts = 0, last_step_up_at = now()
     where token_hash = p_token_hash;
    return true;
  end if;
  update admin_sessions set stepup_attempts = r.stepup_attempts + 1 where token_hash = p_token_hash;
  return false;
end $$;

revoke all on function public.use_admin_stepup_code(text, text) from public, anon, authenticated;
grant execute on function public.use_admin_stepup_code(text, text) to service_role;
