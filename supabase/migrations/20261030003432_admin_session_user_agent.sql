-- Lets the dashboard list Nick's signed-in devices by browser, so he can sign out one he doesn't recognise.
-- Optional for the app: until this is applied, sessions are listed without a browser name. (Applied live 2026-10-30.)
alter table public.admin_sessions
  add column if not exists user_agent text check (user_agent is null or char_length(user_agent) <= 200);
