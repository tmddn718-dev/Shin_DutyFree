-- 닉네임을 선택 항목으로 바꾼다. 새 가입 화면은 닉네임을 받지 않고, 이전 화면은 계속 보낼 수 있다.
alter table public.members alter column nickname drop not null;

create or replace function public.create_member(p jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  s jsonb;
  returning_member boolean;
  ref_id bigint;
  joined timestamptz;
  new_id bigint;
  c jsonb := p->'consents';
begin
  if exists (select 1 from members where user_id = p->>'userId')
     or exists (select 1 from reserved_ids where user_id = p->>'userId') then
    raise exception 'id_taken';
  end if;
  -- 닉네임은 선택: 보낸 경우에만 중복을 확인한다
  if coalesce(p->>'nickname', '') <> '' and (
       exists (select 1 from members where lower(nickname) = lower(p->>'nickname'))
       or exists (select 1 from reserved_nicknames where lower(nickname) = lower(p->>'nickname'))) then
    raise exception 'nickname_taken';
  end if;
  s := email_status(p->>'email', p->>'phone');
  if s->>'status' = 'unavailable' then raise exception 'email_unavailable'; end if;

  if coalesce(p->>'referrer', '') <> '' then
    select id into ref_id from members where user_id = p->>'referrer';
    if ref_id is null then raise exception 'referrer_not_found'; end if;
  end if;

  -- 복귀 여부는 화면이 보낸 값이 아니라 여기서 다시 계산한다
  returning_member := s->>'status' = 'returning';
  joined := case when returning_member then (s->>'firstJoinedAt')::timestamptz else now() end;

  insert into members (auth_id, user_id, email, name, phone, nickname, zipcode, address1, address2,
                       member_type, first_joined_at, referrer_id)
  values ((p->>'authId')::uuid, p->>'userId', lower(p->>'email'), p->>'name', p->>'phone', p->>'nickname',
          p->'address'->>'zipcode', p->'address'->>'address1', p->'address'->>'address2',
          case when returning_member then 'returning' else 'new' end, joined, ref_id)
  returning id into new_id;

  -- 다시 회원이 되었으므로 탈퇴 이력은 지운다
  delete from email_history where email = lower(p->>'email');

  insert into consents (member_id, terms, privacy, age, services, marketing, token_hash, token_expires_at)
  values (new_id, true, true, true, c->'services', c->'marketing', p->>'tokenHash', now() + interval '30 minutes');

  return jsonb_build_object('memberType', case when returning_member then 'returning' else 'new' end,
                            'firstJoinedAt', joined);
end $$;

-- create or replace 는 실행 권한을 그대로 두지만, 안전하게 다시 지정한다
revoke execute on function public.create_member(jsonb) from public, anon, authenticated;
grant execute on function public.create_member(jsonb) to service_role;
