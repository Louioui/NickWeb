-- Legal hold protects proof files that were actually stored. An upload that never finished (uploaded = false) is not
-- evidence, and the daily cleanup and the file-type check must be able to remove it, or the cleanup fails every day.
create or replace function public.protect_held_proofs()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if old.kind = 'proof' and old.uploaded
     and exists (select 1 from public.orders where id = old.order_id and legal_hold) then
    raise exception 'Proof of service files cannot be removed while the order is under legal hold.';
  end if;
  return old;
end;
$$;
revoke all on function public.protect_held_proofs() from public, anon, authenticated;
