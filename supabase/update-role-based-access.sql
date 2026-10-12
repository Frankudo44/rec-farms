-- ============================================================
-- REC LIVESTOCK & AGRO FARMS — Role-Based Access Control
-- (Owner / Manager / Seller management system)
-- ADDITIVE + IDEMPOTENT. Safe to run repeatedly in the SQL editor.
-- Run AFTER update-admin-console.sql and update-role-manager-seller.sql.
--
-- Adds: profiles.active/suspended_at, seller_assignments, stock_requests,
-- role helpers aware of suspension, broader manager permissions,
-- seller permissions, order-access RLS, an order-update safeguard
-- trigger, and audit triggers for the new tables.
-- ============================================================

-- ============================================================
-- 1. PROFILES: account status (suspension/activation)
-- ============================================================
alter table public.profiles add column if not exists active boolean not null default true;
alter table public.profiles add column if not exists suspended_at timestamptz;

create or replace function public.is_admin()
returns boolean
language sql security definer set search_path = public stable
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid()
      and role in ('owner','administrator','admin')
      and coalesce(active, true)
  );
$$;

create or replace function public.is_owner()
returns boolean
language sql security definer set search_path = public stable
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role = 'owner' and coalesce(active, true)
  );
$$;

create or replace function public.is_staff()
returns boolean
language sql security definer set search_path = public stable
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid()
      and role in ('owner','administrator','admin','manager','seller')
      and coalesce(active, true)
  );
$$;

create or replace function public.has_permission(p_permission text)
returns boolean
language sql security definer set search_path = public stable
as $$
  select case
    when p.role in ('owner','administrator','admin') then true
    when p.role = 'manager'
      then p_permission in ('orders','payments','delivery','customers',
                            'products','categories','inventory','batches',
                            'testimonials','reviews','blog','messages',
                            'reports','audit','assignments','stock_requests',
                            'staff_view')
    when p.role = 'seller'
      then p_permission in ('my_orders','sales','stock_requests','inventory_view','product_view')
    else false
  end
  from public.profiles p
  where p.id = auth.uid() and coalesce(p.active, true);
$$;

-- ============================================================
-- 2. SELLER ASSIGNMENTS (order -> seller)
-- ============================================================
create table if not exists public.seller_assignments (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.orders(id) on delete cascade,
  seller_id uuid not null references public.profiles(id) on delete cascade,
  assigned_by uuid references auth.users(id) on delete set null,
  status text not null default 'assigned'
    check (status in ('assigned','accepted','completed','reassigned','unassigned')),
  notes text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint seller_assignments_order_once unique (order_id)
);
create index if not exists idx_seller_assignments_seller
  on public.seller_assignments(seller_id, created_at desc);

alter table public.seller_assignments enable row level security;

drop policy if exists "assignments_staff_all" on public.seller_assignments;
create policy "assignments_staff_all" on public.seller_assignments
  for all using (public.is_admin() or public.has_permission('assignments'))
  with check (public.is_admin() or public.has_permission('assignments'));

-- Seller sees only their own assignment (and may update notes/status only).
drop policy if exists "assignments_seller_read" on public.seller_assignments;
create policy "assignments_seller_read" on public.seller_assignments
  for select using (seller_id = auth.uid());

drop policy if exists "assignments_seller_update_own" on public.seller_assignments;
create policy "assignments_seller_update_own" on public.seller_assignments
  for update using (seller_id = auth.uid())
  with check (seller_id = auth.uid());

-- ============================================================
-- 3. STOCK / PRODUCT REQUESTS (sellers request, managers approve)
-- ============================================================
create table if not exists public.stock_requests (
  id uuid primary key default gen_random_uuid(),
  kind text not null check (kind in ('add_stock','correct_stock','new_product','price_change','correction')),
  product_id uuid references public.products(id) on delete set null,
  product_name text,
  requested_qty int,
  reason text,
  payload jsonb,
  status text not null default 'pending'
    check (status in ('pending','approved','rejected','fulfilled')),
  requested_by uuid references auth.users(id) on delete set null,
  reviewed_by uuid references auth.users(id) on delete set null,
  review_note text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists idx_stock_requests_by on public.stock_requests(requested_by, created_at desc);
create index if not exists idx_stock_requests_status on public.stock_requests(status);

alter table public.stock_requests enable row level security;

drop policy if exists "stock_req_insert_own" on public.stock_requests;
create policy "stock_req_insert_own" on public.stock_requests
  for insert with check (requested_by = auth.uid() and public.is_staff());

drop policy if exists "stock_req_read_own_or_staff" on public.stock_requests;
create policy "stock_req_read_own_or_staff" on public.stock_requests
  for select using (
    requested_by = auth.uid()
    or public.is_admin()
    or public.has_permission('stock_requests')
  );

drop policy if exists "stock_req_review_staff" on public.stock_requests;
create policy "stock_req_review_staff" on public.stock_requests
  for update using (public.is_admin() or public.has_permission('stock_requests'))
  with check (public.is_admin() or public.has_permission('stock_requests'));

-- ============================================================
-- 4. ORDER ACCESS (manager full, seller ONLY assigned)
-- ============================================================
drop policy if exists "orders_select_own_or_admin" on public.orders;
create policy "orders_select_own_or_admin" on public.orders
  for select using (
    public.is_admin()
    or public.has_permission('orders')
    or (customer_id is not null
        and exists (select 1 from public.customers c
                    where c.id = orders.customer_id and c.user_id = auth.uid()))
    or exists (select 1 from public.seller_assignments sa
               where sa.order_id = orders.id and sa.seller_id = auth.uid())
  );

drop policy if exists "orders_update_admin" on public.orders;
create policy "orders_update_admin" on public.orders
  for update using (public.is_admin() or public.has_permission('orders'))
  with check (public.is_admin() or public.has_permission('orders'));

-- Sellers may update only the status of an assigned order; the safeguard
-- trigger below enforces the allowed transitions and protected fields.
drop policy if exists "orders_update_seller_assigned" on public.orders;
create policy "orders_update_seller_assigned" on public.orders
  for update using (
    exists (select 1 from public.seller_assignments sa
            where sa.order_id = orders.id and sa.seller_id = auth.uid())
  )
  with check (true);

-- Managers may view the customer records needed for fulfilment.
drop policy if exists "customers_select_own_or_admin" on public.customers;
create policy "customers_select_own_or_admin" on public.customers
  for select using (
    auth.uid() = user_id
    or public.is_admin()
    or public.has_permission('customers')
    or public.has_permission('orders')
  );

drop policy if exists "customers_update_own_or_admin" on public.customers;
create policy "customers_update_own_or_admin" on public.customers
  for update using (auth.uid() = user_id or public.is_admin())
  with check (auth.uid() = user_id or public.is_admin());

-- Inventory movements: managers record adjustments (reason required).
drop policy if exists "movements_admin_read" on public.inventory_movements;
create policy "movements_admin_read" on public.inventory_movements
  for select using (public.is_admin() or public.has_permission('inventory'));

drop policy if exists "movements_admin_write" on public.inventory_movements;
create policy "movements_admin_write" on public.inventory_movements
  for all using (public.is_admin() or public.has_permission('inventory'))
  with check (public.is_admin() or public.has_permission('inventory'));

-- Staff directory: staff may read other staff profiles (no customer data).
drop policy if exists "profiles_staff_read" on public.profiles;
create policy "profiles_staff_read" on public.profiles
  for select using (
    auth.uid() = id
    or public.is_admin()
    or (public.is_staff()
        and role in ('owner','administrator','admin','manager','seller'))
  );

-- Only full admins (and owner for role assignment) may manage accounts.
drop policy if exists "profiles_staff_admin_write" on public.profiles;
create policy "profiles_staff_admin_write" on public.profiles
  for update using (public.is_admin())
  with check (public.is_admin());

-- Audit: managers may read activity, nobody may edit/delete via API.
drop policy if exists "activity_admin_read" on public.activity_logs;
create policy "activity_admin_read" on public.activity_logs
  for select using (public.is_admin() or public.has_permission('audit'));

-- ============================================================
-- 4.5 WIDEN SCHEMA WRITE POLICIES FOR MANAGER
--     The base schema.sql guards every write with is_admin() only.
--     Managers manage the catalogue + content, so each write policy is
--     re-declared to accept the matching has_permission() flag. Full
--     admins keep all access; sellers stay read-only (public policies).
-- ============================================================
drop policy if exists "products_admin_write" on public.products;
create policy "products_admin_write" on public.products
  for all using (public.is_admin() or public.has_permission('products'))
  with check (public.is_admin() or public.has_permission('products'));

drop policy if exists "categories_admin_write" on public.categories;
create policy "categories_admin_write" on public.categories
  for all using (public.is_admin() or public.has_permission('categories'))
  with check (public.is_admin() or public.has_permission('categories'));

drop policy if exists "inventory_admin_write" on public.inventory;
create policy "inventory_admin_write" on public.inventory
  for all using (public.is_admin() or public.has_permission('inventory'))
  with check (public.is_admin() or public.has_permission('inventory'));

drop policy if exists "batches_admin_write" on public.product_batches;
create policy "batches_admin_write" on public.product_batches
  for all using (public.is_admin() or public.has_permission('batches'))
  with check (public.is_admin() or public.has_permission('batches'));

drop policy if exists "delivery_admin_write" on public.delivery_zones;
create policy "delivery_admin_write" on public.delivery_zones
  for all using (public.is_admin() or public.has_permission('delivery'))
  with check (public.is_admin() or public.has_permission('delivery'));

drop policy if exists "pickup_admin_write" on public.pickup_stations;
create policy "pickup_admin_write" on public.pickup_stations
  for all using (public.is_admin() or public.has_permission('delivery'))
  with check (public.is_admin() or public.has_permission('delivery'));

drop policy if exists "testimonials_admin_write" on public.testimonials;
create policy "testimonials_admin_write" on public.testimonials
  for all using (public.is_admin() or public.has_permission('testimonials'))
  with check (public.is_admin() or public.has_permission('testimonials'));

drop policy if exists "blog_admin_write" on public.blog_posts;
create policy "blog_admin_write" on public.blog_posts
  for all using (public.is_admin() or public.has_permission('blog'))
  with check (public.is_admin() or public.has_permission('blog'));

drop policy if exists "reviews_public_read" on public.product_reviews;
create policy "reviews_public_read" on public.product_reviews
  for select using (approved = true or public.is_admin() or public.has_permission('reviews'));

drop policy if exists "reviews_update_own_or_admin" on public.product_reviews;
create policy "reviews_update_own_or_admin" on public.product_reviews
  for update using (
    public.is_admin() or public.has_permission('reviews') or auth.uid() = user_id
  )
  with check (
    public.is_admin()
    or public.has_permission('reviews')
    or (auth.uid() = user_id and approved = false)
  );

drop policy if exists "reviews_delete_own_or_admin" on public.product_reviews;
create policy "reviews_delete_own_or_admin" on public.product_reviews
  for delete using (auth.uid() = user_id or public.is_admin());

drop policy if exists "contact_admin_read" on public.contact_messages;
create policy "contact_admin_read" on public.contact_messages
  for select using (public.is_admin() or public.has_permission('messages'));

drop policy if exists "contact_admin_update" on public.contact_messages;
create policy "contact_admin_update" on public.contact_messages
  for update using (public.is_admin() or public.has_permission('messages'))
  with check (public.is_admin() or public.has_permission('messages'));

drop policy if exists "order_items_admin_read" on public.order_items;
create policy "order_items_admin_read" on public.order_items
  for select using (public.is_admin() or public.has_permission('orders'));

-- Product media uploads: managers manage the catalogue too.
drop policy if exists "rec_media_admin_insert" on storage.objects;
create policy "rec_media_admin_insert" on storage.objects
  for insert with check (
    bucket_id = 'rec-media'
    and (public.is_admin() or public.has_permission('products'))
  );

drop policy if exists "rec_media_admin_update" on storage.objects;
create policy "rec_media_admin_update" on storage.objects
  for update using (
    bucket_id = 'rec-media'
    and (public.is_admin() or public.has_permission('products'))
  );

drop policy if exists "rec_media_admin_delete" on storage.objects;
create policy "rec_media_admin_delete" on storage.objects
  for delete using (
    bucket_id = 'rec-media'
    and (public.is_admin() or public.has_permission('products'))
  );

-- ============================================================
-- 4.6 PROFILE SELF-SERVICE + OWNER-GRANT GUARD
-- ============================================================
-- Any signed-in user may update their own display name / phone / avatar,
-- but never their own role, active flag or suspension timestamps.
drop policy if exists "profiles_update_own" on public.profiles;
create policy "profiles_update_own" on public.profiles
  for update using (auth.uid() = id)
  with check (
    auth.uid() = id
    and role = (select role from public.profiles where id = auth.uid())
    and active = (select active from public.profiles where id = auth.uid())
    and suspended_at is not distinct from (select suspended_at from public.profiles where id = auth.uid())
  );

-- Keep orders.assigned_to in sync with the active assignment.
create or replace function public.sync_assignment_to_order()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  if tg_op = 'DELETE' then
    update public.orders set assigned_to = null where id = old.order_id;
    return old;
  end if;
  update public.orders set assigned_to = new.seller_id where id = new.order_id;
  return new;
end;
$$;

drop trigger if exists trg_sync_assignment on public.seller_assignments;
create trigger trg_sync_assignment after insert or update or delete on public.seller_assignments
  for each row execute function public.sync_assignment_to_order();

-- Only the current OWNER may grant the owner role to someone.
create or replace function public.protect_profile_role()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if tg_op = 'UPDATE' and new.role is distinct from old.role then
    if new.role = 'owner' and not public.is_owner() then
      raise exception 'Only the current owner can grant the owner role';
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
-- 5. ORDER UPDATE SAFEGUARD
--    - Only staff can change order rows.
--    - Sellers: only 'status' on assigned orders, allowed transitions only.
--    - Anyone: totals / payment fields / order_number never silently change.
-- ============================================================
create or replace function public.validate_order_update()
returns trigger
language plpgsql security definer set search_path = public
as $$
declare
  v_role text;
begin
  select p.role into v_role
  from public.profiles p where p.id = auth.uid();

  if v_role is null then
    raise exception 'Not signed in';
  end if;

  -- Totals and payment verification are admin-only.
  if new.total is distinct from old.total
     or new.subtotal is distinct from old.subtotal
     or new.delivery_fee is distinct from old.delivery_fee
     or new.payment_status is distinct from old.payment_status
     or new.paid_at is distinct from old.paid_at
     or new.payment_reference is distinct from old.payment_reference
     or new.amount_paid is distinct from old.amount_paid
     or new.order_number is distinct from old.order_number then
    if not public.is_admin() then
      raise exception 'Only administrators may change order totals or payment status';
    end if;
  end if;

  -- Sellers may only move the status of an assigned order.
  if v_role in ('seller', 'owner', 'administrator', 'admin', 'manager') then
    if v_role = 'seller' then
      if new.status is distinct from old.status then
        if not (
          (old.status = 'pending' and new.status in ('confirmed','processing'))
          or (old.status = 'confirmed' and new.status in ('processing','cancelled'))
          or (old.status = 'processing' and new.status in ('ready'))
          or (old.status = 'ready' and new.status in ('out for delivery','cancelled'))
        ) then
          raise exception 'Status transition % -> % is not allowed for a seller', old.status, new.status;
        end if;
      end if;
      -- Every editable field is off-limits to sellers; only `status` may move.
      if new.customer_id is distinct from old.customer_id
         or new.full_name is distinct from old.full_name
         or new.phone is distinct from old.phone
         or new.email is distinct from old.email
         or new.state is distinct from old.state
         or new.lga is distinct from old.lga
         or new.delivery_address is distinct from old.delivery_address
         or new.notes is distinct from old.notes
         or new.items is distinct from old.items
         or new.subtotal is distinct from old.subtotal
         or new.delivery_fee is distinct from old.delivery_fee
         or new.total is distinct from old.total
         or new.payment_status is distinct from old.payment_status
         or new.paid_at is distinct from old.paid_at
         or new.payment_reference is distinct from old.payment_reference
         or new.amount_paid is distinct from old.amount_paid
         or new.assigned_to is distinct from old.assigned_to
         or new.internal_notes is distinct from old.internal_notes
         or new.delivery_reference is distinct from old.delivery_reference
         or new.dispatched_at is distinct from old.dispatched_at
         or new.cancellation_reason is distinct from old.cancellation_reason
         or new.fulfillment_method is distinct from old.fulfillment_method
         or new.pickup_station_id is distinct from old.pickup_station_id
         or new.pickup_station_name is distinct from old.pickup_station_name
         or new.pickup_station_address is distinct from old.pickup_station_address
         or new.order_number is distinct from old.order_number then
        raise exception 'Sellers may not change order details';
      end if;
    end if;
  else
    raise exception 'Unauthorized role';
  end if;

  return new;
end;
$$;

drop trigger if exists trg_validate_order_update on public.orders;
create trigger trg_validate_order_update before update on public.orders
  for each row execute function public.validate_order_update();

-- ============================================================
-- 6. AUDIT TRIGGERS (append-only activity_logs)
-- ============================================================
drop trigger if exists trg_activity_inventory_movements on public.inventory_movements;
create trigger trg_activity_inventory_movements after insert or update on public.inventory_movements
  for each row execute function public.log_activity();

drop trigger if exists trg_activity_assignments on public.seller_assignments;
create trigger trg_activity_assignments after insert or update or delete on public.seller_assignments
  for each row execute function public.log_activity();

drop trigger if exists trg_activity_stock_requests on public.stock_requests;
create trigger trg_activity_stock_requests after insert or update or delete on public.stock_requests
  for each row execute function public.log_activity();

-- ============================================================
-- SETUP NOTES (no destructive operations)
--   update public.profiles set role='manager'
--     where id=(select id from auth.users where email='manager@example.com');
--   update public.profiles set role='seller'
--     where id=(select id from auth.users where email='seller@example.com');
--   -- suspend a seller:
--   update public.profiles set active=false, suspended_at=now()
--     where id=(select id from auth.users where email='seller@example.com');
-- ============================================================