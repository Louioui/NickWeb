-- Aggregate the latest client exchange for dashboard badges without truncating event history.
-- A submitted request is the initial contact; later questions/replies supersede it.
create index order_events_client_contact_idx on public.order_events (order_id, created_at desc)
  where kind in ('action', 'action_response');

create function public.list_order_contact_dates(p_order_ids uuid[])
returns table(order_id uuid, last_contact_at timestamptz)
language sql stable security definer set search_path = '' as $$
  select o.id, coalesce(max(e.created_at), o.created_at)
  from public.orders o
  left join public.order_events e on e.order_id = o.id
    and e.kind in ('action', 'action_response')
  where o.id = any(p_order_ids)
  group by o.id, o.created_at;
$$;
revoke all on function public.list_order_contact_dates(uuid[]) from public, anon, authenticated;
grant execute on function public.list_order_contact_dates(uuid[]) to service_role;
