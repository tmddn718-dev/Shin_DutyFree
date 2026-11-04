-- 시연용 데이터. 로컬(supabase db reset)이나 데모 프로젝트에서만 쓰고, 실서비스에는 넣지 않는다.
-- 날짜가 실행 시점 기준이라, 30일 복귀 시연이 필요하면 이 파일을 다시 실행한다.
insert into public.members (user_id, email, name, phone)
values ('friend1234', 'friend@example.com', '친구', '010-9876-5432')
on conflict do nothing;

insert into public.email_history (email, status, phone, withdrawn_at, prev_joined_at) values
  ('rejoin@example.com',  'withdrawn', '010-1234-5678', now() - interval '10 days', '2024-03-15'),
  ('old@example.com',     'withdrawn', '010-1234-5678', now() - interval '45 days', '2023-07-01'),
  ('blocked@example.com', 'blocked',   null,            null,                       null)
on conflict (email) do update set status = excluded.status, phone = excluded.phone,
  withdrawn_at = excluded.withdrawn_at, prev_joined_at = excluded.prev_joined_at, updated_at = now();
