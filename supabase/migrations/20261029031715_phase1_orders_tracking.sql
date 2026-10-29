-- Orders, their timeline and files, plus Nick's login codes/sessions and simple rate limits.
-- Every table has row-level security ON and NO policies: only the server (service role) can read or write.

create table public.orders (
  id uuid primary key default gen_random_uuid(),
  code text not null unique,                 -- human reference shown to people, e.g. NP-482913 (never an access key)
  track_token text not null unique,          -- long random token in the client's private tracking link
  status text not null default 'received' check (status in
    ('received','action_required','awaiting_payment','paid','accepted','attempting','served','closed','cancelled')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  client_name text not null,
  client_firm text,
  client_email text not null,
  client_phone text not null,

  case_number text,
  court text,
  client_reference text,
  deadline date,

  recipient_name text not null,
  doc_type text not null,
  address text not null,
  unit text,
  city text,
  zip text not null,
  access_notes text,
  physical_notes text,
  instructions text,

  tier text not null,
  addons jsonb not null default '[]'::jsonb,
  estimated_total_cents integer not null,
  amount_due_cents integer,
  stripe_session_id text,
  payment_url text,
  paid_at timestamptz,

  action_note text,
  served_at timestamptz
);

create table public.order_events (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.orders(id) on delete cascade,
  created_at timestamptz not null default now(),
  kind text not null check (kind in ('created','status','attempt','note','action','action_response','payment','proof')),
  title text not null,
  detail text,
  client_visible boolean not null default true
);
create index order_events_order_idx on public.order_events(order_id, created_at);

create table public.order_files (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.orders(id) on delete cascade,
  kind text not null check (kind in ('client_document','proof','action_upload')),
  storage_path text not null unique,
  filename text not null,
  size_bytes bigint,
  content_type text,
  uploaded boolean not null default false,
  created_at timestamptz not null default now()
);
create index order_files_order_idx on public.order_files(order_id);

create table public.admin_codes (
  id uuid primary key default gen_random_uuid(),
  email text not null,
  code_hash text not null,
  expires_at timestamptz not null,
  attempts integer not null default 0,
  used boolean not null default false,
  created_at timestamptz not null default now()
);
create index admin_codes_email_idx on public.admin_codes(email, created_at desc);

create table public.admin_sessions (
  token_hash text primary key,
  email text not null,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

create table public.rate_limits (
  bucket text not null,
  window_start timestamptz not null,
  hits integer not null default 0,
  primary key (bucket, window_start)
);

-- Counts a hit in a fixed window and returns the total, atomically (used by the server to throttle abuse).
create or replace function public.hit_rate_limit(p_bucket text, p_window_seconds integer)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  w timestamptz := to_timestamp(floor(extract(epoch from now()) / p_window_seconds) * p_window_seconds);
  n integer;
begin
  insert into rate_limits(bucket, window_start, hits) values (p_bucket, w, 1)
  on conflict (bucket, window_start) do update set hits = rate_limits.hits + 1
  returning hits into n;
  delete from rate_limits where window_start < now() - interval '2 days';
  return n;
end $$;
revoke all on function public.hit_rate_limit(text, integer) from public, anon, authenticated;

create or replace function public.touch_updated_at() returns trigger
language plpgsql set search_path = public as $$
begin new.updated_at = now(); return new; end $$;
create trigger orders_touch before update on public.orders
  for each row execute function public.touch_updated_at();

alter table public.orders enable row level security;
alter table public.order_events enable row level security;
alter table public.order_files enable row level security;
alter table public.admin_codes enable row level security;
alter table public.admin_sessions enable row level security;
alter table public.rate_limits enable row level security;

-- Private bucket for court papers and proofs: 25 MB per file, documents and photos only.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('case-files', 'case-files', false, 26214400,
  array['application/pdf','application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'image/jpeg','image/png','image/heic','image/heif','image/webp']);
