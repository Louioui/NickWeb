-- Strict database-level CHECK constraints (defense-in-depth so malformed codes, tokens, sizes, or hashes can never be stored).

alter table public.orders
  drop constraint if exists orders_code_format_chk,
  add constraint orders_code_format_chk check (code ~ '^NP-[0-9]{6}$'),
  drop constraint if exists orders_track_token_format_chk,
  add constraint orders_track_token_format_chk check (track_token ~ '^[A-Za-z0-9_-]{20,64}$'),
  drop constraint if exists orders_zip_format_chk,
  add constraint orders_zip_format_chk check (zip ~ '^[0-9]{5}(-[0-9]{4})?$'),
  drop constraint if exists orders_amounts_positive_chk,
  add constraint orders_amounts_positive_chk check (
    estimated_total_cents > 0 and estimated_total_cents <= 10000000 and
    (amount_due_cents is null or (amount_due_cents >= 100 and amount_due_cents <= 10000000))
  );

alter table public.order_files
  drop constraint if exists order_files_size_bounds_chk,
  add constraint order_files_size_bounds_chk check (size_bytes is null or (size_bytes > 0 and size_bytes <= 26214400)),
  drop constraint if exists order_files_sha256_format_chk,
  add constraint order_files_sha256_format_chk check (sha256 is null or sha256 ~ '^[0-9a-f]{64}$');
