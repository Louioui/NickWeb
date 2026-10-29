-- Two-step login, document lock, legal hold, and a tamper-evident timeline.
-- Everything here is enforced by the database itself, so a bug or a crafted request in the app cannot get around it.
-- New tables follow the project rule: row-level security on, no privileges for anon/authenticated, restrictive deny policy.

-- 1. Nick's authenticator-app second factor (RFC 6238 TOTP).
--    The secret is encrypted by the server (AES-256-GCM, key from server-only env) before it is stored, so a copy of the
--    database alone cannot generate codes. last_used_step blocks replaying a code inside its 30-second window.
create table if not exists public.admin_totp (
  email text primary key,
  secret_enc text not null check (secret_enc ~ '^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'),
  enabled boolean not null default false,
  last_used_step bigint not null default 0,
  updated_at timestamptz not null default now()
);

-- Consumes one 30-second step atomically: a code that was already used (or an older one) is refused, even in parallel.
create or replace function public.use_admin_totp_step(p_email text, p_step bigint)
returns boolean
language sql
security definer
set search_path = ''
as $$
  with hit as (
    update public.admin_totp set last_used_step = p_step, updated_at = now()
     where email = p_email and last_used_step < p_step
    returning 1
  )
  select exists (select 1 from hit);
$$;

-- 2. Client Security PIN (scrypt with a per-record salt; verified and counted by the server).
create table if not exists public.client_security_settings (
  email text primary key,
  pin_hash text check (pin_hash is null or pin_hash ~ '^scrypt\$[0-9]+\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$'),
  failed_tries integer not null default 0 check (failed_tries >= 0),
  locked_until timestamptz,
  updated_at timestamptz not null default now()
);

-- 3. One-time codes that unlock a locked tracking page (emailed to the client on the order).
create table if not exists public.track_unlock_codes (
  order_id uuid primary key references public.orders(id) on delete cascade,
  code_hash text not null check (code_hash ~ '^[0-9a-f]{64}$'),
  tries integer not null default 0 check (tries >= 0),
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

-- 4. Per-order flags, plus a last-seen time for idle session expiry.
alter table public.orders
  add column if not exists legal_hold boolean not null default false,
  add column if not exists doc_lock boolean not null default false;
alter table public.admin_sessions
  add column if not exists last_seen_at timestamptz not null default now();

-- 5. Allow the client's submission attestation as a timeline entry.
alter table public.order_events drop constraint if exists order_events_kind_check;
alter table public.order_events add constraint order_events_kind_check check (kind in
  ('created','status','attempt','note','action','action_response','payment','proof','attestation'));

-- 6. Tamper-evident timeline: every entry is chained to the one before it with SHA-256 when it is written.
--    Changing, removing or reordering any past entry breaks every hash after it (see verify_order_chain).
alter table public.order_events
  add column if not exists seq integer,
  add column if not exists prev_hash text,
  add column if not exists chain_hash text;

create or replace function public.order_event_chain_payload(e public.order_events)
returns text
language sql
stable
set search_path = ''
as $$
  -- jsonb text output is deterministic, and the array keeps fields unambiguous (no delimiter tricks).
  -- The timestamp is written out in UTC explicitly so the hash never depends on the session's time zone.
  select jsonb_build_array('NPS-CHAIN-V1', e.order_id, e.seq, coalesce(e.prev_hash, 'GENESIS'), e.kind, e.title,
                           coalesce(e.detail, ''), e.client_visible,
                           to_char(e.created_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))::text;
$$;

create or replace function public.seal_order_event()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  last_row record;
begin
  -- One writer per order at a time, so two entries can never claim the same place in the chain.
  perform 1 from public.orders where id = new.order_id for update;
  select seq, chain_hash into last_row from public.order_events
   where order_id = new.order_id order by seq desc limit 1;
  new.created_at := coalesce(new.created_at, now());
  new.seq := coalesce(last_row.seq, 0) + 1;
  new.prev_hash := last_row.chain_hash;
  new.chain_hash := encode(sha256(convert_to(public.order_event_chain_payload(new), 'UTF8')), 'hex');
  return new;
end;
$$;

drop trigger if exists order_events_seal_trg on public.order_events;
create trigger order_events_seal_trg before insert on public.order_events
  for each row execute function public.seal_order_event();

-- Append-only: timeline entries can never be edited, and can only disappear together with their order.
create or replace function public.protect_order_events()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if tg_op = 'UPDATE' then
    raise exception 'Timeline entries are append-only and cannot be edited.';
  end if;
  if exists (select 1 from public.orders where id = old.order_id) then
    raise exception 'Timeline entries cannot be deleted on their own.';
  end if;
  return old;
end;
$$;

drop trigger if exists trg_prevent_critical_event_mutation on public.order_events;
drop trigger if exists order_events_protect_trg on public.order_events;
create trigger order_events_protect_trg before update or delete on public.order_events
  for each row execute function public.protect_order_events();
drop function if exists public.prevent_critical_event_mutation();

-- Recomputes an order's chain from the stored rows. ok = false means something was altered after it was written.
create or replace function public.verify_order_chain(p_order uuid)
returns table (ok boolean, head text, entries integer)
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  r public.order_events;
  expected_prev text := null;
  expected_seq integer := 0;
  good boolean := true;
  last_hash text := null;
  n integer := 0;
begin
  for r in select * from public.order_events where order_id = p_order order by seq loop
    n := n + 1;
    expected_seq := expected_seq + 1;
    if r.seq is distinct from expected_seq
       or r.prev_hash is distinct from expected_prev
       or r.chain_hash is distinct from encode(sha256(convert_to(public.order_event_chain_payload(r), 'UTF8')), 'hex') then
      good := false;
    end if;
    expected_prev := r.chain_hash;
    last_hash := r.chain_hash;
  end loop;
  return query select good, last_hash, n;
end;
$$;

-- 7. Legal hold: once an order is served it is locked. While locked, it cannot be deleted, rolled back to an earlier
--    status, or have its core record changed, and its proof files cannot be removed. Unlocking is a separate, audited
--    update (legal_hold = false) that the app only performs after a fresh second-factor check.
create or replace function public.enforce_legal_hold()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if tg_op = 'DELETE' then
    if old.legal_hold then
      raise exception 'Order % is under legal hold and cannot be deleted. Unlock it first.', old.code;
    end if;
    return old;
  end if;
  if old.legal_hold and new.legal_hold then
    if new.status is distinct from old.status and new.status not in ('served', 'closed') then
      raise exception 'Order % is under legal hold; its status cannot be moved back.', old.code;
    end if;
    -- The service record itself is frozen. Billing can still happen after service (Nick sometimes serves first),
    -- but a recorded payment can never be erased or rewritten.
    if (new.client_name, new.client_email, new.recipient_name, new.doc_type, new.address, new.unit, new.city, new.zip,
        new.case_number, new.court, new.served_at)
       is distinct from
       (old.client_name, old.client_email, old.recipient_name, old.doc_type, old.address, old.unit, old.city, old.zip,
        old.case_number, old.court, old.served_at) then
      raise exception 'Order % is under legal hold; its record cannot be changed.', old.code;
    end if;
    if old.paid_at is not null and new.paid_at is distinct from old.paid_at then
      raise exception 'Order % is under legal hold; its recorded payment cannot be changed.', old.code;
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists orders_legal_hold_trg on public.orders;
create trigger orders_legal_hold_trg before update or delete on public.orders
  for each row execute function public.enforce_legal_hold();

create or replace function public.protect_held_proofs()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if old.kind = 'proof' and exists (select 1 from public.orders where id = old.order_id and legal_hold) then
    raise exception 'Proof of service files cannot be removed while the order is under legal hold.';
  end if;
  return old;
end;
$$;

drop trigger if exists order_files_hold_trg on public.order_files;
create trigger order_files_hold_trg before delete on public.order_files
  for each row execute function public.protect_held_proofs();

-- 8. Lock everything down for the public API roles, matching the rest of the schema.
do $$
declare t text;
begin
  foreach t in array array['admin_totp', 'client_security_settings', 'track_unlock_codes'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('revoke all on table public.%I from public, anon, authenticated', t);
    execute format('drop policy if exists "deny public roles" on public.%I', t);
    execute format('create policy "deny public roles" on public.%I as restrictive for all to anon, authenticated using (false) with check (false)', t);
  end loop;
end $$;

revoke all on function public.use_admin_totp_step(text, bigint) from public, anon, authenticated;
revoke all on function public.verify_order_chain(uuid) from public, anon, authenticated;
revoke all on function public.seal_order_event() from public, anon, authenticated;
revoke all on function public.protect_order_events() from public, anon, authenticated;
revoke all on function public.enforce_legal_hold() from public, anon, authenticated;
revoke all on function public.protect_held_proofs() from public, anon, authenticated;
revoke all on function public.order_event_chain_payload(public.order_events) from public, anon, authenticated;
grant execute on function public.use_admin_totp_step(text, bigint) to service_role;
grant execute on function public.verify_order_chain(uuid) to service_role;
