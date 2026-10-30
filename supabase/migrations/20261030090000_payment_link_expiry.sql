-- Store Stripe Checkout's actual expiry so a client can see when a link needs renewal.
alter table public.orders add column payment_expires_at timestamptz;
alter table public.orders enable row level security;
revoke all on public.orders from anon, authenticated;
drop policy if exists orders_deny_public_payment_expiry on public.orders;
create policy orders_deny_public_payment_expiry on public.orders as restrictive
  for all to anon, authenticated using (false) with check (false);
