-- ============================================================
-- REC LIVESTOCK & AGRO FARMS — Replace specialist managers with
-- "manager" + "seller" roles
-- ADDITIVE + IDEMPOTENT. Safe to run repeatedly in the SQL editor.
-- Run AFTER update-admin-console.sql.
--
-- Remap:
--   orders_manager    -> manager
--   content_manager   -> manager
--   inventory_manager -> seller
--
-- New roles:
--   manager  : products, categories, inventory, batches + frontend
--              content (blog, reviews, testimonials, messages)
--   seller   : products, categories, inventory, batches only
--
-- Also opens RLS on the core tables (products, categories, inventory,
-- product_batches, product_reviews, testimonials, blog_posts,
-- contact_messages) and the rec-media storage bucket to these roles.
-- ============================================================

-- ============================================================
-- 1. ROLE SET + REMAP
-- ============================================================
alter table public.profiles drop constraint if exists profiles_role_check;

update public.profiles set role = case
  when role in ('orders_manager', 'content_manager') then 'manager'
  when role = 'inventory_manager' then 'seller'
  else role
end;

alter table public.profiles add constraint profiles_role_check
  check (role in (
    'customer',
    'owner',
    'administrator',
    'admin',          -- legacy full-admin value, kept for backward compatibility
    'manager',
    'seller'
  ));

-- ============================================================
-- 2. STAFF + PERMISSION HELPERS
-- ============================================================
create or replace function public.is_staff()
returns boolean
language sql security definer set search_path = public stable
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid()
      and role in ('owner','administrator','admin','manager','seller')
  );
$$;

create or replace function public.has_permission(p_permission text)
returns boolean
language sql security definer set search_path = public stable
as $$
  select case
    when p.role in ('owner','administrator','admin') then true
    when p.role = 'manager'
      then p_permission in ('products','categories','inventory','batches',
                            'blog','content','testimonials','reviews',
                            'messages','reports')
    when p.role = 'seller'
      then p_permission in ('products','categories','inventory','batches','reports')
    else false
  end
  from public.profiles p
  where p.id = auth.uid();
$$;

-- ============================================================
-- 3. CORE TABLE POLICIES (manager / seller read + write)
-- ============================================================

-- products
drop policy if exists "products_public_read" on public.products;
create policy "products_public_read" on public.products
  for select using (active = true or public.is_admin() or public.has_permission('products'));

drop policy if exists "products_admin_write" on public.products;
create policy "products_admin_write" on public.products
  for all using (public.is_admin() or public.has_permission('products'))
  with check (public.is_admin() or public.has_permission('products'));

-- categories
drop policy if exists "categories_admin_write" on public.categories;
create policy "categories_admin_write" on public.categories
  for all using (public.is_admin() or public.has_permission('categories'))
  with check (public.is_admin() or public.has_permission('categories'));

-- inventory (stock levels live on products; inventory table write too)
drop policy if exists "inventory_admin_write" on public.inventory;
create policy "inventory_admin_write" on public.inventory
  for all using (public.is_admin() or public.has_permission('inventory'))
  with check (public.is_admin() or public.has_permission('inventory'));

-- product_batches
drop policy if exists "batches_admin_write" on public.product_batches;
create policy "batches_admin_write" on public.product_batches
  for all using (public.is_admin() or public.has_permission('batches'))
  with check (public.is_admin() or public.has_permission('batches'));

-- product_reviews (frontend content: manager moderates)
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
  for delete using (auth.uid() = user_id or public.is_admin() or public.has_permission('reviews'));

-- testimonials (frontend content: manager)
drop policy if exists "testimonials_public_read" on public.testimonials;
create policy "testimonials_public_read" on public.testimonials
  for select using (published = true or public.is_admin() or public.has_permission('testimonials'));

drop policy if exists "testimonials_admin_write" on public.testimonials;
create policy "testimonials_admin_write" on public.testimonials
  for all using (public.is_admin() or public.has_permission('testimonials'))
  with check (public.is_admin() or public.has_permission('testimonials'));

-- blog (frontend content: manager)
drop policy if exists "blog_public_read" on public.blog_posts;
create policy "blog_public_read" on public.blog_posts
  for select using (published = true or public.is_admin() or public.has_permission('blog'));

drop policy if exists "blog_admin_write" on public.blog_posts;
create policy "blog_admin_write" on public.blog_posts
  for all using (public.is_admin() or public.has_permission('blog'))
  with check (public.is_admin() or public.has_permission('blog'));

-- contact_messages (frontend content: manager)
drop policy if exists "contact_admin_read" on public.contact_messages;
create policy "contact_admin_read" on public.contact_messages
  for select using (public.is_admin() or public.has_permission('messages'));

drop policy if exists "contact_admin_update" on public.contact_messages;
create policy "contact_admin_update" on public.contact_messages
  for update using (public.is_admin() or public.has_permission('messages'))
  with check (public.is_admin() or public.has_permission('messages'));

drop policy if exists "contact_admin_delete" on public.contact_messages;
create policy "contact_admin_delete" on public.contact_messages
  for delete using (public.is_admin() or public.has_permission('messages'));

-- ============================================================
-- 4. STORAGE (managers upload product/blog/testimonial images;
--    sellers upload product images)
-- ============================================================
drop policy if exists "rec_media_admin_insert" on storage.objects;
create policy "rec_media_admin_insert" on storage.objects
  for insert with check (
    bucket_id = 'rec-media'
    and (public.is_admin()
         or public.has_permission('products')
         or public.has_permission('blog')
         or public.has_permission('testimonials')
         or public.has_permission('content'))
  );

drop policy if exists "rec_media_admin_update" on storage.objects;
create policy "rec_media_admin_update" on storage.objects
  for update using (
    bucket_id = 'rec-media'
    and (public.is_admin()
         or public.has_permission('products')
         or public.has_permission('blog')
         or public.has_permission('testimonials')
         or public.has_permission('content'))
  );

drop policy if exists "rec_media_admin_delete" on storage.objects;
create policy "rec_media_admin_delete" on storage.objects
  for delete using (
    bucket_id = 'rec-media'
    and (public.is_admin()
         or public.has_permission('products')
         or public.has_permission('blog')
         or public.has_permission('testimonials')
         or public.has_permission('content'))
  );

-- ============================================================
-- NOTE
-- ============================================================
-- orders, customers, delivery/pickups, payments, settings and other
-- tables remain full-admin (owner/administrator/admin) only.
-- To set a role:
--   update public.profiles set role = 'manager'
--   where id = (select id from auth.users where email='you@example.com');
--   update public.profiles set role = 'seller'
--   where id = (select id from auth.users where email='you@example.com');
-- (run in the SQL editor; session_user = postgres bypasses the trigger).