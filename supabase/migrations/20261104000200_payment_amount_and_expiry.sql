-- Payments: record the amount Stripe actually captured, store each Checkout link's real expiry, and write the payment
-- and its sealed timeline entry in one transaction.
-- Replaces the branch-only migrations 20261030040000_atomic_payment_event, 20261030070000_paid_amount_receipts and
-- 20261030090000_payment_link_expiry, which were never applied. orders already has the restrictive "deny public roles"
-- policy (20261029041432), so no new policy is needed.

-- 1. The Stripe-confirmed amount, for receipts. Once recorded it can't be changed.
alter table public.orders add column if not exists paid_amount_cents integer;
alter table public.orders drop constraint if exists orders_paid_amount_cents_check;
alter table public.orders add constraint orders_paid_amount_cents_check
  check (paid_amount_cents is null or (paid_amount_cents > 0 and paid_amount_cents <= 10000000));

-- Earlier payments: their append-only timeline entry was written from Stripe's amount_total ("Payment received: $X.XX").
with prior_payments as (
  select distinct on (order_id) order_id,
    (substring(title from '^Payment received: \$([0-9]+\.[0-9]{2})$')::numeric * 100)::integer as cents
  from public.order_events
  where kind = 'payment' and title ~ '^Payment received: \$[0-9]+\.[0-9]{2}$'
  order by order_id, created_at desc
)
update public.orders o set paid_amount_cents = p.cents
from prior_payments p
where o.id = p.order_id and o.paid_at is not null and o.paid_amount_cents is null
  and p.cents between 1 and 10000000;

create or replace function public.protect_recorded_payment_amount()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if old.paid_amount_cents is not null and new.paid_amount_cents is distinct from old.paid_amount_cents then
    raise exception 'A recorded payment amount cannot be changed.';
  end if;
  return new;
end;
$$;
revoke all on function public.protect_recorded_payment_amount() from public, anon, authenticated;
drop trigger if exists orders_paid_amount_immutable on public.orders;
create trigger orders_paid_amount_immutable before update on public.orders
  for each row execute function public.protect_recorded_payment_amount();

-- 2. When the current Stripe Checkout link expires, so the tracking page can offer a renewal.
alter table public.orders add column if not exists payment_expires_at timestamptz;

-- 3. Mark an order paid and write its sealed "Payment received" entry in the same transaction. If the entry can't be
--    written, paid_at is rolled back too, so Stripe's retry can apply the payment. Same rules as canMarkPaid in
--    api/_lib/orders.mjs: unpaid, the order's own session (or none yet), and at least the amount due. A served order
--    under legal hold keeps its status.
create or replace function public.record_paid_order(p_order uuid, p_amount_cents integer, p_session_id text)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  r public.orders%rowtype;
begin
  if p_session_id is null or p_session_id !~ '^cs_[A-Za-z0-9_]{8,128}$'
     or p_amount_cents is null or p_amount_cents <= 0 or p_amount_cents > 10000000 then
    return false;
  end if;
  select * into r from public.orders where id = p_order for update;
  if not found or r.paid_at is not null
     or (r.stripe_session_id is not null and r.stripe_session_id <> p_session_id)
     or (r.amount_due_cents is not null and p_amount_cents < r.amount_due_cents) then
    return false;
  end if;
  update public.orders
     set paid_at = now(), paid_amount_cents = p_amount_cents, stripe_session_id = p_session_id,
         status = case when r.legal_hold then r.status else 'paid' end
   where id = p_order;
  insert into public.order_events (order_id, kind, title)
    values (p_order, 'payment', 'Payment received: $' || to_char(p_amount_cents / 100.0, 'FM9999990.00'));
  return true;
end;
$$;
revoke all on function public.record_paid_order(uuid, integer, text) from public, anon, authenticated;
grant execute on function public.record_paid_order(uuid, integer, text) to service_role;
