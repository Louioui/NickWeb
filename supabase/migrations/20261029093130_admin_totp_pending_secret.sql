-- Changing to a new authenticator keeps the current one working until the new one is confirmed with a valid code,
-- so an abandoned setup can neither switch two-step login off nor lock Nick out.
alter table public.admin_totp
  add column if not exists pending_secret_enc text
  check (pending_secret_enc is null or pending_secret_enc ~ '^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$');
