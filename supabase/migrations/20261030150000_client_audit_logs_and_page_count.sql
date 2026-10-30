-- 1. Append-only record of what a client did on their request: unlocking it, viewing it unlocked, downloading files,
--    replying, and payments being confirmed. Used in the dispute & court evidence pack.
--    order_id has no foreign key on purpose: rows can never be changed or deleted (prevent_audit_log_mutation), so a
--    cascade from deleting a request would fail; the record of what happened outlives the request itself.
create table if not exists public.client_audit_logs (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null,
  order_code text check (order_code is null or order_code ~ '^NP-[0-9]{6}$'),
  action text not null check (action in ('unlock', 'view_unlocked', 'download', 'reply', 'payment_confirmed', 'payment_link_refreshed')),
  ip_hash text check (ip_hash is null or ip_hash ~ '^[0-9a-f]{64}$'),
  user_agent text check (user_agent is null or char_length(user_agent) <= 200),
  detail text check (detail is null or char_length(detail) <= 300),
  created_at timestamptz not null default now()
);
create index if not exists client_audit_logs_order_idx on public.client_audit_logs (order_id, created_at);

alter table public.client_audit_logs enable row level security;
revoke all on table public.client_audit_logs from public, anon, authenticated;
drop policy if exists "deny public roles" on public.client_audit_logs;
create policy "deny public roles" on public.client_audit_logs
  as restrictive for all to anon, authenticated using (false) with check (false);

drop trigger if exists client_audit_logs_immutable_trg on public.client_audit_logs;
create trigger client_audit_logs_immutable_trg
  before update or delete on public.client_audit_logs
  for each row execute function public.prevent_audit_log_mutation();

-- 2. Page count of each uploaded PDF (counted on the server without running anything in the file), for the printing fee:
--    first 100 pages free, then $0.15 per page.
alter table public.order_files
  add column if not exists page_count integer check (page_count is null or (page_count >= 0 and page_count <= 100000));
