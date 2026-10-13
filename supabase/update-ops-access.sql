-- ============================================================
-- REC LIVESTOCK & AGRO FARMS — Operations pages access
-- ADDITIVE + IDEMPOTENT. Safe to run repeatedly in the SQL editor.
-- Run AFTER update-role-based-access.sql.
--
-- The new admin pages (Bulk Requests, Farm Visits, Quotations,
-- Batches, Inventory Movements, Notifications) need managers to be
-- able to read/write the backing tables. Base schema.sql guarded
-- some of these with is_admin() only; this migration widens them to
-- the matching has_permission() flag. Full admins keep all access.
--
-- No destructive operations.
-- ============================================================

-- ------------------------------------------------------------
-- bulk_quote_requests: managers with 'orders' permission manage.
-- ------------------------------------------------------------
drop policy if exists "quotes_admin_all" on public.bulk_quote_requests;
create policy "quotes_admin_all" on public.bulk_quote_requests
  for all using (public.is_admin() or public.has_permission('orders'))
  with check (public.is_admin() or public.has_permission('orders'));

drop policy if exists "quotes_insert_any" on public.bulk_quote_requests;
create policy "quotes_insert_any" on public.bulk_quote_requests
  for insert with check (true);

-- ------------------------------------------------------------
-- farm_visit_bookings: anyone may book; managers manage.
-- (Re-declared so the policy is present even if only schema.sql ran.)
-- ------------------------------------------------------------
alter table public.farm_visit_bookings enable row level security;

drop policy if exists "farmvisits_insert_any" on public.farm_visit_bookings;
create policy "farmvisits_insert_any" on public.farm_visit_bookings
  for insert with check (true);

drop policy if exists "farmvisits_staff_all" on public.farm_visit_bookings;
create policy "farmvisits_staff_all" on public.farm_visit_bookings
  for all using (public.is_admin() or public.has_permission('orders'))
  with check (public.is_admin() or public.has_permission('orders'));

-- ------------------------------------------------------------
-- quotations + quotation_items: managers with 'orders' permission.
-- ------------------------------------------------------------
alter table public.quotations enable row level security;
alter table public.quotation_items enable row level security;

drop policy if exists "quotations_staff_all" on public.quotations;
create policy "quotations_staff_all" on public.quotations
  for all using (public.is_admin() or public.has_permission('orders'))
  with check (public.is_admin() or public.has_permission('orders'));

drop policy if exists "quotation_items_staff_all" on public.quotation_items;
create policy "quotation_items_staff_all" on public.quotation_items
  for all using (public.is_admin() or public.has_permission('orders'))
  with check (public.is_admin() or public.has_permission('orders'));

-- ------------------------------------------------------------
-- product_batches + inventory_movements: managers/sellers.
-- ------------------------------------------------------------
drop policy if exists "batches_public_read" on public.product_batches;
create policy "batches_public_read" on public.product_batches
  for select using (
    public.is_admin()
    or public.has_permission('batches')
    or exists (
      select 1 from public.products p
      where p.id = product_batches.product_id and p.active = true
    )
  );

drop policy if exists "batches_admin_write" on public.product_batches;
create policy "batches_admin_write" on public.product_batches
  for all using (public.is_admin() or public.has_permission('batches'))
  with check (public.is_admin() or public.has_permission('batches'));

drop policy if exists "movements_admin_read" on public.inventory_movements;
create policy "movements_admin_read" on public.inventory_movements
  for select using (public.is_admin() or public.has_permission('inventory'));

drop policy if exists "movements_admin_write" on public.inventory_movements;
create policy "movements_admin_write" on public.inventory_movements
  for all using (public.is_admin() or public.has_permission('inventory'))
  with check (public.is_admin() or public.has_permission('inventory'));

-- ------------------------------------------------------------
-- notifications: any active staff member may read + mark read.
-- ------------------------------------------------------------
alter table public.notifications enable row level security;

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

-- ============================================================
-- NOTE
-- ============================================================
-- After running this, managers can manage bulk requests, farm
-- visits, quotations, batches and inventory movements; any staff
-- member can read the admin notification feed.
