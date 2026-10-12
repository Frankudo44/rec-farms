-- ============================================================
-- REC LIVESTOCK & AGRO FARMS — Admin Console migration
-- ADDITIVE + IDEMPOTENT. Safe to run repeatedly in the Supabase SQL editor.
-- Run AFTER schema.sql. Creates only genuinely missing objects and never
-- deletes or rewrites existing data.
--
-- What it adds:
--   1. Granular staff roles on public.profiles (owner, administrator,
--      orders_manager, inventory_manager, content_manager) + helpers.
--   2. New columns on existing tables (products, categories, blog_posts,
--      contact_messages, orders, bulk_quote_requests, inventory).
--   3. New tables: payments, order_status_history, notifications,
--      activity_logs, farm_visit_bookings, quotations, quotation_items,
--      deliveries.
--   4. Row Level Security + policies for every new table.
--   5. Triggers: order status history, activity logging, admin
--      notifications, quotation number generator.
-- ============================================================

-- ============================================================
-- 1. GRANULAR ROLES
-- ============================================================
-- Widen the existing 2-value check. All existing rows use 'customer' or
-- 'admin', both of which remain valid, so this cannot fail on live data.
alter table public.profiles drop constraint if exists profiles_role_check;
alter table public.profiles add constraint profiles_role_check
  check (role in (
    'customer',
    'owner',
    'administrator',
    'orders_manager',
    'inventory_manager',
    'content_manager',
    'admin'          -- legacy full-admin value, kept for backward compatibility
  ));

-- Current caller's role name (null when not signed in).
create or replace function public.current_role_name()
returns text
language sql security definer set search_path = public stable
as $$
  select p.role from public.profiles p where p.id = auth.uid();
$$;

-- True when the caller holds any of the given roles.
create or replace function public.has_role(variadic p_roles text[])
returns boolean
language sql security definer set search_path = public stable
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role = any(p_roles)
  );
$$;

-- Full administrative access (owner, administrator, legacy admin).
create or replace function public.is_admin()
returns boolean
language sql security definer set search_path = public stable
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role in ('owner','administrator','admin')
  );
$$;

-- Owner only (used to guard privilege escalation).
create or replace function public.is_owner()
returns boolean
language sql security definer set search_path = public stable
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role = 'owner'
  );
$$;

-- Any signed-in staff member (admin panel access, no write guarantee).
create or replace function public.is_staff()
returns boolean
language sql security definer set search_path = public stable
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid()
      and role in ('owner','administrator','admin',
                   'orders_manager','inventory_manager','content_manager')
  );
$$;

-- Module-level permission check. Mirrors the client-side mapping in
-- js/app.js; the database remains the authority for real access.
create or replace function public.has_permission(p_permission text)
returns boolean
language sql security definer set search_path = public stable
as $$
  select case
    when p.role in ('owner','administrator','admin') then true
    when p.role = 'orders_manager'
      then p_permission in ('orders','payments','delivery','customers','reports')
    when p.role = 'inventory_manager'
      then p_permission in ('products','categories','inventory','batches','reports')
    when p.role = 'content_manager'
      then p_permission in ('blog','content','testimonials','reviews','messages')
    else false
  end
  from public.profiles p
  where p.id = auth.uid();
$$;

-- Rebuild the role-protection trigger so:
--   * admins keep the ability to change roles (as before),
--   * only an owner / postgres / service_role may grant 'owner',
--   * a normal browser session can never change its own role.
create or replace function public.protect_profile_role()
returns trigger
language plpgsql security definer set search_path = public
as $$
begin
  if tg_op = 'UPDATE' and new.role is distinct from old.role then
    if new.role = 'owner'
       and not public.is_owner()
       and session_user not in ('postgres', 'supabase_admin')
       and current_user <> 'service_role' then
      raise exception 'Only an owner can grant the owner role';
    end if;
    if public.is_admin() then
      return new;
    end if;
    if session_user in ('postgres', 'supabase_admin') then
      return new;
    end if;
    if current_user = 'service_role' then
      return new;
    end if;
    raise exception 'You cannot change your own role';
  end if;
  return new;
end;
$$;

drop trigger if exists protect_profile_role on public.profiles;
create trigger protect_profile_role before update on public.profiles
  for each row execute function public.protect_profile_role();

-- ============================================================
-- 2. NEW COLUMNS ON EXISTING TABLES
-- ============================================================

-- products: SKU, short description, SEO, archive, reserved stock
alter table public.products add column if not exists sku text;
alter table public.products add column if not exists short_description text;
alter table public.products add column if not exists seo_title text;
alter table public.products add column if not exists meta_description text;
alter table public.products add column if not exists archived_at timestamptz;
alter table public.products add column if not exists reserved_quantity int not null default 0;
create unique index if not exists idx_products_sku on public.products(sku) where sku is not null;

-- categories: parent/child + publish flag
alter table public.categories add column if not exists parent_id bigint references public.categories(id) on delete set null;
alter table public.categories add column if not exists active boolean not null default true;

-- blog_posts: SEO + archive
alter table public.blog_posts add column if not exists seo_title text;
alter table public.blog_posts add column if not exists meta_description text;
alter table public.blog_posts add column if not exists archived boolean not null default false;

-- contact_messages: workflow status, assignment, notes, linked product
alter table public.contact_messages add column if not exists status text not null default 'new'
  check (status in ('new','read','in_progress','resolved'));
alter table public.contact_messages add column if not exists assigned_to uuid references public.profiles(id) on delete set null;
alter table public.contact_messages add column if not exists internal_notes text;
alter table public.contact_messages add column if not exists product_id uuid references public.products(id) on delete set null;
update public.contact_messages
  set status = 'resolved'
  where handled = true and status = 'new';

-- orders: assignment, dispatch + cancellation detail
alter table public.orders add column if not exists assigned_to uuid references public.profiles(id) on delete set null;
alter table public.orders add column if not exists internal_notes text;
alter table public.orders add column if not exists delivery_reference text;
alter table public.orders add column if not exists dispatched_at timestamptz;
alter table public.orders add column if not exists cancellation_reason text;

-- bulk_quote_requests: richer workflow + assignment
alter table public.bulk_quote_requests add column if not exists assigned_to uuid references public.profiles(id) on delete set null;
alter table public.bulk_quote_requests add column if not exists internal_notes text;
alter table public.bulk_quote_requests add column if not exists quoted_at timestamptz;

-- inventory: last adjustment stamp
alter table public.inventory add column if not exists last_adjustment_at timestamptz;

-- ============================================================
-- 3. NEW TABLES
-- ============================================================

-- payments: product payments and (separately) delivery charges.
create table if not exists public.payments (
  id uuid primary key default gen_random_uuid(),
  order_id uuid references public.orders(id) on delete cascade,
  order_number text,
  customer_id uuid references public.customers(id) on delete set null,
  amount numeric(12,2) not null default 0 check (amount >= 0),
  method text not null default 'manual'
    check (method in ('paystack','transfer','pay_on_delivery','manual','cash')),
  kind text not null default 'product' check (kind in ('product','delivery')),
  status text not null default 'pending'
    check (status in ('pending','awaiting_verification','successful','failed','refunded')),
  reference text,
  provider_reference text,
  proof_url text,
  verified_by uuid references auth.users(id) on delete set null,
  verified_at timestamptz,
  note text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists idx_payments_order on public.payments(order_id);
create index if not exists idx_payments_status on public.payments(status);
create index if not exists idx_payments_created on public.payments(created_at desc);
create unique index if not exists idx_payments_provider_ref
  on public.payments(provider_reference) where provider_reference is not null;

-- order_status_history: immutable audit of status transitions.
create table if not exists public.order_status_history (
  id bigint generated always as identity primary key,
  order_id uuid not null references public.orders(id) on delete cascade,
  from_status text,
  to_status text not null,
  changed_by uuid references auth.users(id) on delete set null,
  note text,
  created_at timestamptz not null default now()
);
create index if not exists idx_order_history_order on public.order_status_history(order_id, created_at desc);

-- notifications: internal admin feed + customer notifications kept separate.
create table if not exists public.notifications (
  id uuid primary key default gen_random_uuid(),
  audience text not null default 'admin' check (audience in ('admin','customer')),
  user_id uuid references auth.users(id) on delete cascade,
  kind text not null default 'general',
  title text not null,
  body text,
  link text,
  read boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists idx_notifications_audience on public.notifications(audience, read, created_at desc);
create index if not exists idx_notifications_user on public.notifications(user_id, created_at desc);

-- activity_logs: append-only audit trail (never edited/deleted via API).
create table if not exists public.activity_logs (
  id bigint generated always as identity primary key,
  actor uuid references auth.users(id) on delete set null,
  actor_email text,
  action text not null,
  entity text,
  entity_id text,
  detail jsonb,
  created_at timestamptz not null default now()
);
create index if not exists idx_activity_created on public.activity_logs(created_at desc);
create index if not exists idx_activity_entity on public.activity_logs(entity, entity_id);

-- farm_visit_bookings
create table if not exists public.farm_visit_bookings (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  phone text not null,
  email text,
  preferred_date date,
  preferred_time text,
  visitors int not null default 1 check (visitors > 0),
  purpose text,
  status text not null default 'new'
    check (status in ('new','confirmed','rescheduled','rejected','completed','cancelled')),
  staff_notes text,
  assigned_to uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists idx_farmvisits_status on public.farm_visit_bookings(status);
create index if not exists idx_farmvisits_created on public.farm_visit_bookings(created_at desc);

-- quotations (prepared from bulk_quote_requests)
create table if not exists public.quotations (
  id uuid primary key default gen_random_uuid(),
  request_id uuid references public.bulk_quote_requests(id) on delete set null,
  reference text unique,
  customer_name text,
  phone text,
  email text,
  status text not null default 'draft'
    check (status in ('draft','sent','accepted','rejected','expired')),
  valid_until date,
  subtotal numeric(12,2) not null default 0,
  delivery_fee numeric(12,2) not null default 0,
  total numeric(12,2) not null default 0,
  notes text,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists idx_quotations_status on public.quotations(status);
create index if not exists idx_quotations_created on public.quotations(created_at desc);

create table if not exists public.quotation_items (
  id bigint generated always as identity primary key,
  quotation_id uuid not null references public.quotations(id) on delete cascade,
  product_id uuid references public.products(id) on delete set null,
  name text not null,
  quantity int not null default 1 check (quantity > 0),
  unit_price numeric(12,2) not null default 0,
  subtotal numeric(12,2) not null default 0
);
create index if not exists idx_quotation_items_q on public.quotation_items(quotation_id);

-- deliveries: dispatch / tracking records per order.
create table if not exists public.deliveries (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.orders(id) on delete cascade,
  status text not null default 'pending'
    check (status in ('pending','dispatched','in_transit','delivered','failed','returned')),
  courier text,
  tracking_reference text,
  destination_state text,
  destination_lga text,
  dispatched_at timestamptz,
  delivered_at timestamptz,
  note text,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists idx_deliveries_order on public.deliveries(order_id);
create index if not exists idx_deliveries_status on public.deliveries(status);

-- ============================================================
-- 4. ROW LEVEL SECURITY
-- ============================================================
alter table public.payments enable row level security;
alter table public.order_status_history enable row level security;
alter table public.notifications enable row level security;
alter table public.activity_logs enable row level security;
alter table public.farm_visit_bookings enable row level security;
alter table public.quotations enable row level security;
alter table public.quotation_items enable row level security;
alter table public.deliveries enable row level security;

-- payments: staff with orders/payments permission; no public access.
drop policy if exists "payments_staff_read" on public.payments;
create policy "payments_staff_read" on public.payments
  for select using (public.has_permission('payments'));
drop policy if exists "payments_staff_write" on public.payments;
create policy "payments_staff_write" on public.payments
  for all using (public.has_permission('payments'))
  with check (public.has_permission('payments'));

-- order_status_history: read for orders staff; inserts come only from
-- SECURITY DEFINER triggers, so no INSERT policy is exposed.
drop policy if exists "order_history_staff_read" on public.order_status_history;
create policy "order_history_staff_read" on public.order_status_history
  for select using (public.has_permission('orders'));

-- notifications: admins see the admin feed; customers see their own.
drop policy if exists "notifications_admin_read" on public.notifications;
create policy "notifications_admin_read" on public.notifications
  for select using (
    (audience = 'admin' and public.is_staff())
    or (audience = 'customer' and user_id = auth.uid())
  );
drop policy if exists "notifications_admin_update" on public.notifications;
create policy "notifications_admin_update" on public.notifications
  for update using (
    (audience = 'admin' and public.is_staff())
    or (audience = 'customer' and user_id = auth.uid())
  )
  with check (
    (audience = 'admin' and public.is_staff())
    or (audience = 'customer' and user_id = auth.uid())
  );
drop policy if exists "notifications_admin_delete" on public.notifications;
create policy "notifications_admin_delete" on public.notifications
  for delete using (audience = 'admin' and public.is_staff());

-- activity_logs: read for full admins only. No update/delete policies at all,
-- so audit history cannot be altered through the API.
drop policy if exists "activity_admin_read" on public.activity_logs;
create policy "activity_admin_read" on public.activity_logs
  for select using (public.is_admin());

-- farm_visit_bookings: anyone may submit; staff manage.
drop policy if exists "farmvisits_insert_any" on public.farm_visit_bookings;
create policy "farmvisits_insert_any" on public.farm_visit_bookings
  for insert with check (true);
drop policy if exists "farmvisits_staff_all" on public.farm_visit_bookings;
create policy "farmvisits_staff_all" on public.farm_visit_bookings
  for all using (public.has_permission('orders'))
  with check (public.has_permission('orders'));

-- quotations: staff with orders permission.
drop policy if exists "quotations_staff_all" on public.quotations;
create policy "quotations_staff_all" on public.quotations
  for all using (public.has_permission('orders'))
  with check (public.has_permission('orders'));
drop policy if exists "quotation_items_staff_all" on public.quotation_items;
create policy "quotation_items_staff_all" on public.quotation_items
  for all using (public.has_permission('orders'))
  with check (public.has_permission('orders'));

-- deliveries: staff with delivery permission.
drop policy if exists "deliveries_staff_all" on public.deliveries;
create policy "deliveries_staff_all" on public.deliveries
  for all using (public.has_permission('delivery'))
  with check (public.has_permission('delivery'));

-- ============================================================
-- 5. TRIGGERS
-- ============================================================

-- updated_at stamps for the new mutable tables.
drop trigger if exists trg_payments_updated on public.payments;
create trigger trg_payments_updated before update on public.payments
  for each row execute function public.set_updated_at();

drop trigger if exists trg_farmvisits_updated on public.farm_visit_bookings;
create trigger trg_farmvisits_updated before update on public.farm_visit_bookings
  for each row execute function public.set_updated_at();

drop trigger if exists trg_quotations_updated on public.quotations;
create trigger trg_quotations_updated before update on public.quotations
  for each row execute function public.set_updated_at();

drop trigger if exists trg_deliveries_updated on public.deliveries;
create trigger trg_deliveries_updated before update on public.deliveries
  for each row execute function public.set_updated_at();

-- quotation reference: REC-Q-YYYY-XXXXXXXX
create or replace function public.assign_quotation_number()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  if new.reference is null or new.reference = '' then
    new.reference := 'REC-Q-' || to_char(now(), 'YYYY') || '-' ||
      upper(substring(md5(random()::text || clock_timestamp()::text) from 1 for 8));
  end if;
  return new;
end;
$$;
drop trigger if exists trg_assign_quotation_number on public.quotations;
create trigger trg_assign_quotation_number before insert on public.quotations
  for each row execute function public.assign_quotation_number();

-- order status -> history + activity log (runs as definer, bypasses RLS).
create or replace function public.log_order_status_change()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  if new.status is distinct from old.status then
    insert into public.order_status_history (order_id, from_status, to_status, changed_by)
    values (new.id, old.status, new.status, auth.uid());
    insert into public.activity_logs (actor, actor_email, action, entity, entity_id, detail)
    values (
      auth.uid(),
      (select email from auth.users where id = auth.uid()),
      'order.status_changed',
      'orders',
      new.id::text,
      jsonb_build_object('from', old.status, 'to', new.status, 'order_number', new.order_number)
    );
  end if;
  return new;
end;
$$;
drop trigger if exists trg_order_status_change on public.orders;
create trigger trg_order_status_change after update of status on public.orders
  for each row execute function public.log_order_status_change();

-- activity logging for the most important mutations.
create or replace function public.log_activity()
returns trigger language plpgsql security definer set search_path = public
as $$
declare
  v_action text;
  v_entity text := tg_table_name;
  v_id text;
begin
  if tg_op = 'INSERT' then v_action := v_entity || '.created';
  elsif tg_op = 'UPDATE' then v_action := v_entity || '.updated';
  else v_action := v_entity || '.deleted'; end if;

  if tg_op = 'DELETE' then v_id := old.id::text; else v_id := new.id::text; end if;

  insert into public.activity_logs (actor, actor_email, action, entity, entity_id)
  values (auth.uid(), (select email from auth.users where id = auth.uid()), v_action, v_entity, v_id);
  if tg_op = 'DELETE' then return old; end if;
  return new;
end;
$$;

drop trigger if exists trg_activity_products on public.products;
create trigger trg_activity_products after insert or update or delete on public.products
  for each row execute function public.log_activity();

-- admin notifications for new inbound records.
create or replace function public.notify_admin()
returns trigger language plpgsql security definer set search_path = public
as $$
declare
  v_kind text := tg_table_name;
  v_title text;
  v_link text;
begin
  v_title := case tg_table_name
    when 'orders' then 'New order ' || coalesce(new.order_number, '')
    when 'contact_messages' then 'New contact message'
    when 'bulk_quote_requests' then 'New bulk/quote request'
    when 'farm_visit_bookings' then 'New farm visit request'
    else 'New ' || tg_table_name || ' record'
  end;
  v_link := case tg_table_name
    when 'orders' then 'rule/orders.html'
    when 'contact_messages' then 'rule/messages.html'
    when 'bulk_quote_requests' then 'rule/bulk_requests.html'
    when 'farm_visit_bookings' then 'rule/farm_visits.html'
    else null
  end;
  insert into public.notifications (audience, kind, title, body, link)
  values ('admin', v_kind, v_title, null, v_link);
  return new;
end;
$$;

drop trigger if exists trg_notify_order on public.orders;
create trigger trg_notify_order after insert on public.orders
  for each row execute function public.notify_admin();

drop trigger if exists trg_notify_message on public.contact_messages;
create trigger trg_notify_message after insert on public.contact_messages
  for each row execute function public.notify_admin();

drop trigger if exists trg_notify_bulk on public.bulk_quote_requests;
create trigger trg_notify_bulk after insert on public.bulk_quote_requests
  for each row execute function public.notify_admin();

drop trigger if exists trg_notify_farmvisit on public.farm_visit_bookings;
create trigger trg_notify_farmvisit after insert on public.farm_visit_bookings
  for each row execute function public.notify_admin();

-- ============================================================
-- NOTE
-- ============================================================
-- After running this, existing admins (role='admin') keep full access.
-- To create an owner:
--   update public.profiles set role='owner'
--   where id = (select id from auth.users where email='you@example.com');
-- (run in the SQL editor; allowed because session_user = postgres).
