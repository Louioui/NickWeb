-- At most 25 files per request, enforced in the database. The API counts first, but two upload batches arriving at
-- the same moment could both pass that count; this trigger serializes inserts per request and refuses the 26th file.
create or replace function public.enforce_order_files_cap()
returns trigger
language plpgsql
security definer
set search_path to 'public'
as $$
begin
  perform pg_advisory_xact_lock(hashtext('order_files:' || new.order_id::text));
  if (select count(*) from order_files where order_id = new.order_id) >= 25 then
    raise exception 'order_files_cap: at most 25 files per request' using errcode = 'P0001';
  end if;
  return new;
end $$;

revoke all on function public.enforce_order_files_cap() from public, anon, authenticated;

drop trigger if exists order_files_cap on public.order_files;
create trigger order_files_cap before insert on public.order_files
  for each row execute function public.enforce_order_files_cap();
