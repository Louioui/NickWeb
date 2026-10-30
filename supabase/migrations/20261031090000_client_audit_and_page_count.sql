-- 1. An append-only record of what clients do on their tracking page: views (at most one an hour per visitor), unlocks,
--    downloads, replies and payments. The network address is stored only as a SHA-256 hash. It backs the dispute
--    evidence pack. Rows can be added, never changed or removed (the order's own deletion removes its rows).
-- 2. The page count of each uploaded PDF, so the printing fee (first 100 pages free, $0.15 a page after) is worked out
--    for Nick instead of counted by hand.
-- Same security pattern as the other tables: row-level security on, public roles denied.
create table if not exists public.client_audit_logs (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.orders(id) on delete cascade,
  action text not null check (action in ('view', 'unlock', 'download', 'reply', 'payment', 'renew_payment')),
  detail text check (detail is null or char_length(detail) <= 300),
  ip_hash text check (ip_hash is null or ip_hash ~ '^[0-9a-f]{64}$'),
  user_agent text check (user_agent is null or char_length(user_agent) <= 200),
  created_at timestamptz not null default now()
);
create index if not exists client_audit_logs_order_idx on public.client_audit_logs (order_id, created_at);

create or replace function public.client_audit_logs_append_only() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if tg_op = 'UPDATE' then
    raise exception 'Client audit entries are append-only and cannot be edited.';
  end if;
  -- Deleting the whole order (privacy request) cascades here; removing entries on their own is refused.
  if exists (select 1 from public.orders where id = old.order_id) then
    raise exception 'Client audit entries cannot be deleted on their own.';
  end if;
  return old;
end $$;
drop trigger if exists client_audit_logs_append_only on public.client_audit_logs;
create trigger client_audit_logs_append_only before update or delete on public.client_audit_logs
  for each row execute function public.client_audit_logs_append_only();

alter table public.client_audit_logs enable row level security;
revoke all on table public.client_audit_logs from public, anon, authenticated;
revoke all on function public.client_audit_logs_append_only() from public, anon, authenticated;
drop policy if exists "deny public roles" on public.client_audit_logs;
create policy "deny public roles" on public.client_audit_logs
  as restrictive for all to anon, authenticated using (false) with check (false);

alter table public.order_files add column if not exists page_count integer check (page_count is null or page_count between 0 and 100000);
