-- Parsed PDF page counts are stored with the confirmed file fingerprint for printing estimates.
alter table public.order_files add column page_count integer;
alter table public.order_files add constraint order_files_page_count_check
  check (page_count is null or (page_count > 0 and page_count <= 100000));
alter table public.order_files enable row level security;
revoke all on public.order_files from anon, authenticated;
drop policy if exists order_files_deny_public_page_count on public.order_files;
create policy order_files_deny_public_page_count on public.order_files as restrictive
  for all to anon, authenticated using (false) with check (false);
