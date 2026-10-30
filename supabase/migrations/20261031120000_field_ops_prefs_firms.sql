-- Phase 3: Nick's field tools, the client email preference, and the foundation for law-firm accounts.
-- Every table: row-level security on, public roles denied (only the server's service key can reach them).

-- 1. Miles and fees per job, for Nick's taxes. Never shown to the client.
create table if not exists public.order_expenses (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.orders(id) on delete cascade,
  miles numeric(7,1) not null default 0 check (miles >= 0 and miles <= 2000),
  fees_cents integer not null default 0 check (fees_cents >= 0 and fees_cents <= 1000000),
  label text check (label is null or char_length(label) <= 120),
  created_at timestamptz not null default now()
);
create index if not exists order_expenses_created_idx on public.order_expenses (created_at);

-- 2. Safe-Walk: Nick's emergency contact, and each check-in timer.
create table if not exists public.admin_settings (
  email text primary key,
  emergency_email text check (emergency_email is null or char_length(emergency_email) <= 254),
  updated_at timestamptz not null default now()
);
create table if not exists public.safe_walks (
  id uuid primary key default gen_random_uuid(),
  email text not null,
  started_at timestamptz not null default now(),
  due_at timestamptz not null,
  order_code text check (order_code is null or order_code ~ '^NP-[0-9]{6}$'),
  address text check (address is null or char_length(address) <= 300),
  checked_in_at timestamptz,
  alerted_at timestamptz
);
create index if not exists safe_walks_due_idx on public.safe_walks (due_at) where checked_in_at is null and alerted_at is null;

-- 3. A client's choice of an email per update or one daily summary.
create table if not exists public.client_preferences (
  email text primary key,
  notify_mode text not null default 'instant' check (notify_mode in ('instant', 'daily')),
  updated_at timestamptz not null default now()
);

-- 4. Law-firm accounts (foundation only; nothing in the site uses them until the firm screens are built).
create table if not exists public.firms (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 160),
  created_at timestamptz not null default now()
);
create table if not exists public.firm_members (
  firm_id uuid not null references public.firms(id) on delete cascade,
  email text not null check (char_length(email) <= 254),
  role text not null check (role in ('admin', 'billing', 'paralegal')),
  added_by text,
  created_at timestamptz not null default now(),
  removed_at timestamptz,
  primary key (firm_id, email)
);
create index if not exists firm_members_email_idx on public.firm_members (email) where removed_at is null;
alter table public.orders add column if not exists firm_id uuid references public.firms(id) on delete set null;

-- Removing a departing staff member, all in one step: they stop being a member, their remembered devices and passkeys
-- are deleted, their sign-in sessions end, and the private tracking link of every open request they made for the firm is
-- replaced (the firm's admins get the new links). Only an admin of that firm may do it, and the last admin can't be removed.
create or replace function public.firm_remove_member(p_firm uuid, p_email text, p_actor text)
returns table (order_id uuid, code text, track_token text)
language plpgsql security definer set search_path = '' as $$
declare
  v_email text := lower(trim(p_email));
begin
  if not exists (select 1 from public.firm_members m where m.firm_id = p_firm and m.email = lower(trim(p_actor))
                 and m.role = 'admin' and m.removed_at is null) then
    raise exception 'Only an admin of this firm can remove staff.';
  end if;
  if exists (select 1 from public.firm_members m where m.firm_id = p_firm and m.email = v_email and m.role = 'admin' and m.removed_at is null)
     and (select count(*) from public.firm_members m where m.firm_id = p_firm and m.role = 'admin' and m.removed_at is null) <= 1 then
    raise exception 'The last admin of a firm cannot be removed.';
  end if;
  update public.firm_members m set removed_at = now() where m.firm_id = p_firm and m.email = v_email and m.removed_at is null;
  if not found then raise exception 'That person is not a current member of this firm.'; end if;
  delete from public.client_trusted_devices d where d.email = v_email;
  delete from public.webauthn_credentials c where c.owner_kind = 'client' and c.owner_email = v_email;
  delete from auth.refresh_tokens r where r.user_id in (select u.id::text from auth.users u where lower(u.email) = v_email);
  delete from auth.sessions s where s.user_id in (select u.id from auth.users u where lower(u.email) = v_email);
  return query
    update public.orders o
       set track_token = rtrim(translate(encode(extensions.gen_random_bytes(32), 'base64'), '+/', '-_'), '=')
     where o.firm_id = p_firm and o.client_email = v_email and o.status not in ('served', 'closed', 'cancelled')
    returning o.id, o.code, o.track_token;
end $$;

alter table public.order_expenses enable row level security;
alter table public.admin_settings enable row level security;
alter table public.safe_walks enable row level security;
alter table public.client_preferences enable row level security;
alter table public.firms enable row level security;
alter table public.firm_members enable row level security;
revoke all on table public.order_expenses, public.admin_settings, public.safe_walks, public.client_preferences, public.firms, public.firm_members
  from public, anon, authenticated;
revoke all on function public.firm_remove_member(uuid, text, text) from public, anon, authenticated;
grant execute on function public.firm_remove_member(uuid, text, text) to service_role;
do $$
declare t text;
begin
  foreach t in array array['order_expenses', 'admin_settings', 'safe_walks', 'client_preferences', 'firms', 'firm_members'] loop
    execute format('drop policy if exists "deny public roles" on public.%I', t);
    execute format('create policy "deny public roles" on public.%I as restrictive for all to anon, authenticated using (false) with check (false)', t);
  end loop;
end $$;
