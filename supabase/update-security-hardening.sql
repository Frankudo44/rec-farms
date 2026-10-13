-- ============================================================
-- REC LIVESTOCK & AGRO FARMS — Security hardening
--
-- Addresses these Supabase Database Linter advisories:
--   * 0011 function_search_path_mutable      (set_updated_at, touch_updated_at)
--   * 0028 anon_security_definer_function_executable
--   * 0029 authenticated_security_definer_function_executable
--   * 0025 public_bucket_allows_listing       (rec-media bucket)
--
-- Run AFTER the other migrations, in the Supabase SQL Editor as the project
-- owner:
--   schema.sql
--   -> update-admin-console.sql
--   -> update-role-manager-seller.sql
--   -> update-role-based-access.sql
--   -> update-egg-sizes.sql
--   -> update-reviews-editing.sql
--   -> update-remove-sample-testimonials.sql
--   -> update-ops-access.sql
--   -> update-security-hardening.sql   <-- this file
--
-- DELIBERATELY NOT CHANGED:
--   * The `rls_policy_always_true` warnings on bulk_quote_requests,
--     contact_messages, customers and farm_visit_bookings are INTENTIONAL.
--     Anonymous storefront visitors must be able to INSERT form submissions.
--   * The `auth_leaked_password_protection` advisory is a dashboard toggle
--     (Authentication -> Providers/Policies -> Password Strength), not SQL.
-- ============================================================

-- ============================================================
-- 1. PIN search_path ON EVERY public FUNCTION
--    Trigger helpers such as set_updated_at()/touch_updated_at() shipped
--    without an explicit search_path, which the linter flags as mutable.
--    Pinning it removes the advisory. Wrapped so a function we do not own
--    is skipped instead of aborting the migration.
-- ============================================================
do $$
declare
  r record;
begin
  for r in
    select p.oid::regprocedure as sig
    from pg_proc p
    join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public'
  loop
    begin
      execute format('alter function %s set search_path = public, extensions, pg_temp', r.sig);
    exception when others then
      raise notice 'search_path skipped for %: %', r.sig, sqlerrm;
    end;
  end loop;
end $$;

-- ============================================================
-- 2. REVOKE EXECUTE ON INTERNAL / TRIGGER-ONLY FUNCTIONS
--    These run from triggers or from other functions, never from the
--    browser, so their /rest/v1/rpc/<fn> entry points can be closed.
--    The RLS helper functions (is_admin, is_owner, is_staff, has_role,
--    has_permission, current_role_name) are intentionally NOT in this list:
--    Postgres checks EXECUTE against the querying role when a row-level
--    policy expression calls a function, so revoking them would break RLS.
-- ============================================================
do $$
declare
  fns text[] := array[
    'public.set_updated_at()',
    'public.touch_updated_at()',
    'public.handle_new_user()',
    'public.protect_profile_role()',
    'public.assign_order_number()',
    'public.assign_quotation_number()',
    'public.sync_order_items()',
    'public.log_order_movements()',
    'public.validate_order_amounts()',
    'public.restock_on_cancel()',
    'public.ensure_inventory()',
    'public.log_order_status_change()',
    'public.log_activity()',
    'public.notify_admin()',
    'public.sync_assignment_to_order()',
    'public.validate_order_update()',
    'public.rls_auto_enable()'
  ];
  f text;
begin
  foreach f in array fns loop
    begin
      execute format('revoke all on function %s from public, anon, authenticated', f);
    exception when others then
      raise notice 'revoke skipped for %: %', f, sqlerrm;
    end;
  end loop;
end $$;

-- ============================================================
-- 3. KEEP THE INTENDED PUBLIC RPC SURFACE WORKING
--    track_order() is the only function the storefront calls directly
--    (js/app.js). Re-granted explicitly so a repeat run cannot lock it out.
--    The RLS helpers must stay callable by anon/authenticated so policies
--    on public tables can be evaluated for signed-out visitors.
-- ============================================================
grant execute on function public.track_order(text) to anon, authenticated;
grant execute on function public.is_admin() to anon, authenticated;
grant execute on function public.is_owner() to anon, authenticated;
grant execute on function public.is_staff() to anon, authenticated;
grant execute on function public.has_role(text[]) to anon, authenticated;
grant execute on function public.has_permission(text) to anon, authenticated;
grant execute on function public.current_role_name() to anon, authenticated;

-- ============================================================
-- 4. TRIM PUBLIC STORAGE LISTING POLICY
--    `rec-media` is a public bucket, so objects are still served through
--    /storage/v1/object/public/... with no policy at all. The broad SELECT
--    policy only let clients *enumerate* every file. The app never calls
--    storage.list()/download() (only upload + getPublicUrl), so removing
--    the public listing is safe. An admin-gated read policy is kept so the
--    dashboard / future admin tools can still list objects when signed in.
-- ============================================================
drop policy if exists "rec_media_public_read" on storage.objects;

drop policy if exists "rec_media_admin_read" on storage.objects;
create policy "rec_media_admin_read" on storage.objects
  for select using (bucket_id = 'rec-media' and public.is_admin());

-- ============================================================
-- Done. Re-run Dashboard -> Advisors -> Security to confirm the
-- function_search_path_mutable, anon/authenticated SECURITY DEFINER and
-- public_bucket_allows_listing advisories are cleared.
-- ============================================================
