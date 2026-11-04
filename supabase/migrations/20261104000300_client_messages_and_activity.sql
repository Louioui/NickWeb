-- Client messages, and the two dashboard flags worked out in the database.
-- Replaces the branch-only migrations 20261030060000_order_last_contact_dates and 20261102103000_client_messages,
-- which were never applied.

-- 1. A client can send Nick a note on an open request without answering a question. It is its own kind of entry,
--    so only an answer to Nick's question ('action_response') can change the address or put the job back in the queue.
alter table public.order_events drop constraint if exists order_events_kind_check;
alter table public.order_events add constraint order_events_kind_check check (kind in
  ('created','status','attempt','note','action','action_response','client_message','payment','proof','attestation'));

-- 2. For each listed job: has the client written since Nick's last entry, and when did Nick last update the client?
--    "Nick's entries" are status changes, attempts, questions, proof, payment requests and the notes he shares
--    ("Update from Nick"); system notes ("files added by you", "Client reply emailed") and the client's own entries
--    don't count. Last contact is his newest entry the client can see (null when there is none).
--    Ids arrive in the request body: an .in() list in the URL fails past ~200 jobs, and a row limit across all jobs
--    hid older jobs' latest entries.
create or replace function public.list_order_activity(p_order_ids uuid[])
returns table(order_id uuid, client_replied boolean, last_contact_at timestamptz)
language sql stable security definer set search_path = '' as $$
  with relevant as (
    select e.order_id, e.kind, e.created_at, e.seq, e.client_visible,
           (e.kind in ('status', 'attempt', 'action', 'proof')
             or (e.kind = 'payment' and e.title like 'Payment requested%')
             or (e.kind = 'note' and e.title = 'Update from Nick')) as by_nick
      from public.order_events e
     where e.order_id = any(p_order_ids)
       and e.kind in ('status', 'attempt', 'action', 'proof', 'payment', 'note', 'action_response', 'client_message')
  )
  select o.id,
         coalesce((select r.kind in ('action_response', 'client_message')
                     from relevant r
                    where r.order_id = o.id and (r.by_nick or r.kind in ('action_response', 'client_message'))
                    order by r.created_at desc, r.seq desc nulls last
                    limit 1), false),
         (select max(r.created_at) from relevant r where r.order_id = o.id and r.by_nick and r.client_visible)
    from (select distinct unnest(p_order_ids) as id) o;
$$;
revoke all on function public.list_order_activity(uuid[]) from public, anon, authenticated;
grant execute on function public.list_order_activity(uuid[]) to service_role;
