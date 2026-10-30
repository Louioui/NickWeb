-- Answers to the two question sets: Nick's (from his dashboard) and his clients' (feedback.html). An answer is only
-- stored with the person's permission (consent must be true). Network addresses are stored only as a SHA-256 hash.
-- Same security pattern as the other tables: row-level security on, public roles denied.
create table if not exists public.survey_responses (
  id uuid primary key default gen_random_uuid(),
  form text not null check (form in ('nick-v1', 'client-v1')),
  respondent text check (respondent is null or char_length(respondent) <= 254),   -- Nick's login address for his answers
  contact_name text check (contact_name is null or char_length(contact_name) <= 120),
  contact_email text check (contact_email is null or char_length(contact_email) <= 254),
  answers jsonb not null default '{}'::jsonb check (jsonb_typeof(answers) = 'object' and octet_length(answers::text) <= 150000),
  consent boolean not null check (consent),
  ip_hash text check (ip_hash is null or ip_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create unique index if not exists survey_responses_one_per_respondent on public.survey_responses (form, respondent) where respondent is not null;
create index if not exists survey_responses_created_idx on public.survey_responses (created_at);

alter table public.survey_responses enable row level security;
revoke all on table public.survey_responses from public, anon, authenticated;
drop policy if exists "deny public roles" on public.survey_responses;
create policy "deny public roles" on public.survey_responses
  as restrictive for all to anon, authenticated using (false) with check (false);
