-- Defense in depth for the public API roles (anon = anyone with the public key, authenticated = any Supabase Auth user).
-- The site never uses them: only the server's service role (which bypasses RLS) touches these tables.
-- 1) Take away their table and sequence privileges, now and for tables created later.
revoke all on all tables in schema public from anon, authenticated;
revoke all on all sequences in schema public from anon, authenticated;
alter default privileges in schema public revoke all on tables from anon, authenticated;
alter default privileges in schema public revoke all on sequences from anon, authenticated;
alter default privileges in schema public revoke execute on functions from anon, authenticated, public;

-- 2) An explicit RESTRICTIVE deny on every table. Restrictive policies are ANDed with any permissive ones, so even if
--    someone later adds a permissive policy (or re-grants privileges) by mistake, these roles still see and change nothing.
do $$
declare t text;
begin
  foreach t in array array['orders','order_events','order_files','admin_codes','admin_sessions','rate_limits'] loop
    execute format('create policy "deny public roles" on public.%I as restrictive for all to anon, authenticated using (false) with check (false)', t);
  end loop;
end $$;
