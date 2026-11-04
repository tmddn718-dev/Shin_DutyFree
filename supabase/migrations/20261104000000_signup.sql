-- 회원가입 스키마. 모든 접근은 Edge Function(api)이 service_role 로 한다.
-- 화면(브라우저)이 테이블을 직접 읽거나 쓰지 못하도록 RLS 를 켜고 정책은 만들지 않는다.

create table public.members (
  id              bigint generated always as identity primary key,
  auth_id         uuid unique references auth.users(id) on delete cascade, -- 비밀번호는 Supabase Auth 가 해시해 보관
  user_id         text not null,
  email           text not null,
  name            text not null,
  phone           text not null,
  nickname        text not null,
  zipcode         text,
  address1        text,
  address2        text,
  member_type     text not null default 'new' check (member_type in ('new', 'returning')),
  first_joined_at timestamptz not null default now(),
  referrer_id     bigint references public.members(id),
  created_at      timestamptz not null default now()
);
create unique index members_user_id  on public.members (user_id);
create unique index members_email    on public.members (lower(email));
create unique index members_nickname on public.members (lower(nickname));

-- 아이디·닉네임으로 쓸 수 없는 예약어
create table public.reserved_ids (user_id text primary key);
create table public.reserved_nicknames (nickname text primary key);
create unique index reserved_nicknames_lower on public.reserved_nicknames (lower(nickname));

-- 이전 가입 이력: withdrawn = 탈퇴, blocked = 가입 제한
create table public.email_history (
  email          text primary key,
  status         text not null check (status in ('withdrawn', 'blocked')),
  phone          text,          -- 탈퇴 회원의 본인인증 휴대폰
  withdrawn_at   timestamptz,
  prev_joined_at timestamptz,   -- 탈퇴 전 가입일
  updated_at     timestamptz not null default now()
);

create table public.consents (
  member_id        bigint primary key references public.members(id) on delete cascade,
  terms            boolean not null,
  privacy          boolean not null,
  age              boolean not null,
  services         jsonb not null,   -- {"서비스명": true/false}
  marketing        jsonb not null,   -- {"point": {...}, "duty": {...}, "night": bool}
  token_hash       text not null unique, -- 가입 직후 동의 수정용 토큰의 SHA-256
  token_expires_at timestamptz not null,
  agreed_at        timestamptz not null default now(),
  updated_at       timestamptz not null default now()
);

alter table public.members            enable row level security;
alter table public.reserved_ids       enable row level security;
alter table public.reserved_nicknames enable row level security;
alter table public.email_history      enable row level security;
alter table public.consents           enable row level security;
revoke all on public.members, public.reserved_ids, public.reserved_nicknames,
              public.email_history, public.consents from anon, authenticated;

insert into public.reserved_ids (user_id) values ('admin'), ('shinsegae'), ('test1234'), ('gudals4360')
  on conflict do nothing;
insert into public.reserved_nicknames (nickname) values ('관리자'), ('운영자'), ('admin'), ('신세계')
  on conflict do nothing;

-- 이메일 가입 가능 여부. 복귀/신규 판단은 여기 한 곳에서만 한다 (확인 API 와 가입 처리가 같이 쓴다).
-- status: available | returning | rejoin_new | unavailable
-- 이미 가입된 이메일과 가입 제한 이메일은 같은 값(unavailable)으로 돌려줘 사유를 드러내지 않는다.
create function public.email_status(p_email text, p_phone text) returns jsonb
language plpgsql stable set search_path = public as $$
declare
  h public.email_history;
  elapsed interval;
begin
  if exists (select 1 from public.members where lower(email) = lower(p_email)) then
    return jsonb_build_object('status', 'unavailable');
  end if;
  select * into h from public.email_history where email = lower(p_email);
  if not found then
    return jsonb_build_object('status', 'available');
  end if;
  if h.status = 'blocked' then
    return jsonb_build_object('status', 'unavailable');
  end if;
  -- 휴대폰이 같아야 같은 사람으로 보고, 그때만 남은 기간·만료 사유를 알려 준다
  if coalesce(p_phone, '') = '' or h.phone is distinct from p_phone or h.withdrawn_at is null then
    return jsonb_build_object('status', 'rejoin_new');
  end if;
  elapsed := now() - h.withdrawn_at;
  if elapsed <= interval '30 days' then
    return jsonb_build_object('status', 'returning',
      'daysLeft', 30 - extract(day from elapsed)::int,
      'firstJoinedAt', h.prev_joined_at);
  end if;
  return jsonb_build_object('status', 'rejoin_new', 'reason', 'expired');
end $$;

-- 가입: 회원 + 동의를 한 트랜잭션으로 저장. 오류는 message 에 코드를 담아 던진다.
-- p: {authId, userId, email, name, phone, nickname, address, referrer, consents, tokenHash}
create function public.create_member(p jsonb) returns jsonb
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
  if exists (select 1 from members where lower(nickname) = lower(p->>'nickname'))
     or exists (select 1 from reserved_nicknames where lower(nickname) = lower(p->>'nickname')) then
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

-- 가입 직후 동의 수정 (가입 응답의 토큰이 있어야 하고 30분간 유효)
create function public.update_consents(p_token_hash text, c jsonb) returns void
language plpgsql security definer set search_path = public as $$
declare row_c public.consents;
begin
  select * into row_c from consents where token_hash = p_token_hash;
  if not found then raise exception 'invalid_token'; end if;
  if row_c.token_expires_at < now() then raise exception 'token_expired'; end if;
  update consents set terms = true, privacy = true, age = true,
         services = c->'services', marketing = c->'marketing', updated_at = now()
   where member_id = row_c.member_id;
end $$;

revoke execute on function public.email_status(text, text), public.create_member(jsonb),
                           public.update_consents(text, jsonb) from public, anon, authenticated;
grant execute on function public.email_status(text, text), public.create_member(jsonb),
                          public.update_consents(text, jsonb) to service_role;
