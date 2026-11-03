-- Aura clients may send an operational message at any point without changing the order state.  Keep this separate
-- from action_response: only an explicit action request may amend address/access fields or return an order to received.
alter table public.order_events drop constraint if exists order_events_kind_check;
alter table public.order_events add constraint order_events_kind_check check (kind in
  ('created','status','attempt','note','action','action_response','client_message','payment','proof','attestation'));

-- 20261030060000 is already applied, so its partial index and function are replaced here rather than edited in place.
drop index if exists public.order_events_client_contact_idx;
create index order_events_client_contact_idx on public.order_events (order_id, created_at desc)
  where kind in ('action', 'action_response', 'client_message');

-- Same contract as before (a submitted request is the initial contact, empty search_path, service_role only); a
-- message-only exchange now also counts as contact.
create or replace function public.list_order_contact_dates(p_order_ids uuid[])
returns table(order_id uuid, last_contact_at timestamptz)
language sql stable security definer set search_path = '' as $$
  select o.id, coalesce(max(e.created_at), o.created_at)
  from public.orders o
  left join public.order_events e on e.order_id = o.id
    and e.kind in ('action', 'action_response', 'client_message')
  where o.id = any(p_order_ids)
  group by o.id, o.created_at;
$$;

revoke all on function public.list_order_contact_dates(uuid[]) from public, anon, authenticated;
grant execute on function public.list_order_contact_dates(uuid[]) to service_role;

-- A job awaits Nick when its newest client-or-Nick event is a client reply or message. Computed per order in the
-- database: an .in() id list in the URL breaks past ~150 orders, and a global row limit hides older orders' replies.
create function public.list_order_client_replied(p_order_ids uuid[])
returns table(order_id uuid, client_replied boolean)
language sql stable security definer set search_path = '' as $$
  select distinct on (e.order_id) e.order_id, e.kind in ('action_response', 'client_message')
  from public.order_events e
  where e.order_id = any(p_order_ids)
    and e.kind in ('action', 'status', 'attempt', 'payment', 'proof', 'action_response', 'client_message')
  order by e.order_id, e.created_at desc, e.seq desc nulls last;
$$;

revoke all on function public.list_order_client_replied(uuid[]) from public, anon, authenticated;
grant execute on function public.list_order_client_replied(uuid[]) to service_role;
