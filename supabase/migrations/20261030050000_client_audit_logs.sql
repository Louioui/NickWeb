-- Client activity evidence. Store a one-way IP digest, never the raw address or tracking token.
create table public.client_audit_logs (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null,
  action text not null check (action in ('tracking_view', 'document_unlock', 'file_download', 'action_reply', 'payment_confirmation')),
  file_id uuid,
  ip_hash text not null check (ip_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default now()
);
create index client_audit_logs_order_created_idx on public.client_audit_logs (order_id, created_at desc);

alter table public.client_audit_logs enable row level security;
revoke all on public.client_audit_logs from public, anon, authenticated;
grant select, insert on public.client_audit_logs to service_role;
create policy client_audit_logs_deny_public on public.client_audit_logs
  as restrictive for all to anon, authenticated using (false) with check (false);

create function public.prevent_client_audit_log_mutation()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  raise exception 'client_audit_logs is append-only and cannot be modified or deleted';
end $$;
revoke all on function public.prevent_client_audit_log_mutation() from public, anon, authenticated;
create trigger client_audit_logs_immutable_trg before update or delete on public.client_audit_logs
  for each row execute function public.prevent_client_audit_log_mutation();
