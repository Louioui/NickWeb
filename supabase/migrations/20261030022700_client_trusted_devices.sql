-- Devices a client has chosen to trust for 30 days. A trusted device skips the Security PIN (the email code or sign-in
-- link is still required). A sign-in from a device that is not trusted triggers a login alert. Only a hash of each
-- device token is stored. Same security pattern as the other tables: row-level security on, public roles denied.
create table if not exists public.client_trusted_devices (
  token_hash text primary key check (token_hash ~ '^[0-9a-f]{64}$'),
  email text not null,
  user_agent text check (user_agent is null or char_length(user_agent) <= 200),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);
create index if not exists client_trusted_devices_email_idx on public.client_trusted_devices (email);

alter table public.client_trusted_devices enable row level security;
revoke all on table public.client_trusted_devices from public, anon, authenticated;
drop policy if exists "deny public roles" on public.client_trusted_devices;
create policy "deny public roles" on public.client_trusted_devices
  as restrictive for all to anon, authenticated using (false) with check (false);
