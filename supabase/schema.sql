create table if not exists public.farm_members (
  user_id uuid primary key references auth.users(id) on delete cascade,
  email text not null unique,
  display_name text not null default '',
  role text not null check (role in ('admin', 'user')),
  active boolean not null default true,
  must_change_password boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.farm_members enable row level security;
revoke all on public.farm_members from anon, authenticated;
grant select on public.farm_members to authenticated;
grant all on public.farm_members to service_role;

drop policy if exists farm_members_read_self on public.farm_members;
create policy farm_members_read_self
  on public.farm_members
  for select
  to authenticated
  using (user_id = (select auth.uid()));

create table if not exists public.farm_bootstrap (
  singleton boolean primary key default true check (singleton),
  admin_email text not null,
  claimed_user_id uuid references auth.users(id),
  claimed_at timestamptz,
  created_at timestamptz not null default now()
);

alter table public.farm_bootstrap enable row level security;
revoke all on public.farm_bootstrap from public, anon, authenticated;
grant all on public.farm_bootstrap to service_role;

create table if not exists public.farm_state (
  id smallint primary key default 1 check (id = 1),
  state jsonb not null default '{"inventory":[],"health":[],"records":[],"animals":[]}'::jsonb,
  updated_at timestamptz not null default now(),
  updated_by uuid references auth.users(id)
);

insert into public.farm_state (id, state)
values (1, '{"inventory":[],"health":[],"records":[],"animals":[]}'::jsonb)
on conflict (id) do nothing;

alter table public.farm_state enable row level security;
revoke all on public.farm_state from anon;
grant select, insert, update on public.farm_state to authenticated;
grant all on public.farm_state to service_role;

drop policy if exists farm_state_read_member on public.farm_state;
create policy farm_state_read_member
  on public.farm_state
  for select
  to authenticated
  using (
    exists (
      select 1
      from public.farm_members m
      where m.user_id = (select auth.uid())
        and m.active = true
        and m.must_change_password = false
    )
  );

drop policy if exists farm_state_insert_member on public.farm_state;
create policy farm_state_insert_member
  on public.farm_state
  for insert
  to authenticated
  with check (
    exists (
      select 1
      from public.farm_members m
      where m.user_id = (select auth.uid())
        and m.active = true
        and m.must_change_password = false
    )
    and updated_by = (select auth.uid())
  );

drop policy if exists farm_state_update_member on public.farm_state;
create policy farm_state_update_member
  on public.farm_state
  for update
  to authenticated
  using (
    exists (
      select 1
      from public.farm_members m
      where m.user_id = (select auth.uid())
        and m.active = true
        and m.must_change_password = false
    )
  )
  with check (
    exists (
      select 1
      from public.farm_members m
      where m.user_id = (select auth.uid())
        and m.active = true
        and m.must_change_password = false
    )
    and updated_by = (select auth.uid())
  );

-- Add the allowlisted first administrator email privately after project creation.
