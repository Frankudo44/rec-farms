# REC Livestock & Agro Farms Enterprises

**Growing Excellence, Feeding the Future.**

Production website for REC Livestock & Agro Farms Enterprises — a Nigerian livestock
and agro marketplace in lagos State. Fresh farm produce, livestock, eggs, fish,
supplies — all sourced with integrity and delivered cold & fresh.

- Live config-driven storefront (vanilla HTML/CSS/JS + Supabase)
- Full admin panel for products, orders, inventory, reviews, blog and more
- Ready for Vercel deployment with zero build step

---

## Features

- **Storefront** — homepage, shop with filters & search, product details, cart, checkout, order tracking
- **Policy support** — certain items (e.g. broiler meat, pigs) are marked *“Visit Farm to Purchase”* and cannot be ordered online
- **Supabase data layer** — all catalogue, settings, blog and review content is read live from Supabase (Row-Level Security enforced)
- **Graceful demo fallback** — before Supabase keys are added, the site runs on sample demo data so you can still explore the UI
- **Auth** — customer sign up/sign in via Supabase Auth; `profiles.role = 'admin'` unlocks the admin panel
- **Admin panel** — `/rule` with dashboard KPIs, order status workflow, product CRUD + image upload, inventory, categories, delivery zones, testimonials, product review moderation, blog, contact inbox, customers, site settings
- **Product reviews** — signed-in customers rate and comment on each item; reviews go live only after an admin approves them (approve / hide / feature / delete)
- **Delivery zones** — fee + minimum order per zone drives a structured checkout tax
- **WhatsApp-first support** — one-click WhatsApp chat replaces a JS map, meeting the “no JS map library” requirement
- **SEO / polish** — semantic markup, OG tags, robots.txt, sitemap.xml, custom 404, SVG favicon & logo
- **Catching invite**: design boards, receiving + sizing areas, AI cohort recommendations (see roadmap)

---

## Tech Stack

| Layer     | Choice                                                        |
|-----------|---------------------------------------------------------------|
| Frontend  | Vanilla HTML5, CSS3, Vanilla JavaScript (no frameworks)       |
| Backend   | Supabase (PostgreSQL, Auth, Storage, Row-Level Security)      |
| Hosting   | Vercel (static, zero config)                                  |
| Fonts     | Fraunces (display) + Manrope (UI), via Google Fonts           |

---

## Project Structure

```
rec-livestock/                # <- repo root, deploy this directory as-is
├── index.html                 # Homepage (site entry point, stays at root)
├── pages/                     # All other storefront pages
│   ├── shop.html              # Shop / marketplace listing
│   ├── product.html           # Product detail
│   ├── cart.html / checkout.html
│   ├── order-success.html     # Order confirmation + tracking
│   ├── account.html           # Auth + order history
│   ├── about.html / contact.html
│   ├── blog.html / blog-post.html
│   └── privacy.html / terms.html / 404.html
├── rule/                      # Restricted area (requires admin role)
│   ├── login.html / index.html
│   ├── products.html / orders.html / inventory.html
│   ├── categories.html / delivery.html / pickups.html
│   ├── testimonials.html / reviews.html / customers.html
│   └── blog.html / messages.html / settings.html
├── api/                       # Vercel serverless functions
│   ├── sitemap.js             # Dynamic sitemap from Supabase
│   ├── verify-payment.js      # Paystack payment verification
│   └── admin-create-staff.js  # Owner/admin: create staff logins (service-role)
├── css/                       # variables, global, components, layout,
│                              # responsive, shop, admin
├── js/
│   ├── core/                  # Loaded by every page
│   │   ├── config.js          # Config + REC.root/page/asset path helpers
│   │   ├── ui.js              # Icons, toast, money/date formatting
│   │   ├── supabase.js        # Client bootstrap
│   │   ├── auth.js            # Session + profile helpers
│   │   ├── products.js        # Catalogue data layer + demo fallback
│   │   ├── cart.js            # Cart store (localStorage)
│   │   ├── orders.js          # Order creation
│   │   ├── render.js          # Shared product/category/cart templates
│   │   ├── navigation.js      # Header + mobile drawer
│   │   ├── footer.js          # Footer
│   │   └── whatsapp.js        # Floating WhatsApp button
│   ├── storefront/            # One controller per storefront page
│   │   └── home, shop, product, cart, cart-page, checkout,
│   │       order-success, blog, blog-post, reviews, contact, account
│   └── admin/                 # One controller per admin page
│       └── admin-shell, admin-login, admin-dashboard, admin-orders,
│           admin-products, admin-categories, admin-inventory,
│           admin-customers, admin-delivery, admin-pickups,
│           admin-testimonials, admin-reviews, admin-blog,
│           admin-messages, admin-settings
├── assets/
│   ├── logo/                  # rec-logo.jpg (main logo / favicon)
│   ├── icons/                 # svg sprite (sprite.svg)
│   └── images/                # hero, categories, product photos
├── docs/
│   └── design-reference.png   # Reference mockups (not deployed content)
├── supabase/
│   ├── schema.sql             # Full schema + RLS + triggers + storage
│   └── seed.sql               # Sample categories, products, settings, zones…
└── vercel.json / robots.txt / .env.example / .gitignore
```

### Path convention

Pages live at different depths (`/`, `/pages`, `/rule`), so never hand-write
relative paths in JavaScript. `js/core/config.js` resolves the site root once
from its own script URL and exposes:

```js
REC.page("shop")            // -> <root>/pages/shop.html
REC.page("cart") + "?id=4"
REC.asset("images/hero.png") // -> <root>/assets/images/hero.png
REC.sprite("i-cart")         // -> <root>/assets/icons/sprite.svg#i-cart
```

Both absolute URLs and `data:` / `blob:` / already-public values pass through
`REC.asset` untouched, so values straight from the database can be piped
through it safely.

Public URLs are kept stable by the `rewrites` in `vercel.json` — `/shop.html`,
`/shop` and `/pages/shop.html` all serve the same page, so the canonical tags
and `sitemap.xml` entries stay valid.

---

## Quick Start

```bash
# from the repo root:
# serve statically (any static server is fine):
python -m http.server 8080
# or
npx serve .
```

Open http://localhost:8080 — the site runs immediately using demo data.

---

## Connect Supabase

> The frontend uses only the **anon key** with Row-Level Security protecting every
> table. Never put your service-role key in browser code.

1. Create a project at [supabase.com](https://supabase.com).
2. Open **SQL Editor** and run `supabase/schema.sql` (tables, indexes, RLS,
   triggers, storage bucket `rec-media`).
3. Optional: run `supabase/seed.sql` to load sample products, categories, zones,
   a site-settings row and sample blog posts/testimonials. Delete sample rows
   before going live.
4. The site reads its keys directly from `js/config.js` — the Supabase URL and
   **anon** key are committed there on purpose. The anon key is public by design
   and safe to ship to the browser; RLS protects every table.

```js
// js/config.js
supabaseUrl: "https://<project>.supabase.co",
supabaseAnonKey: "your-anon-key",
```

> These client values are **not** read from Vercel environment variables — the
> site is fully static with no build step, so anything the browser needs must be
> in `config.js`. Env vars are only used by the serverless functions in `api/`
> (Paystack verification), which run on the server.

### Create your admin user

1. In Supabase **Authentication → Users**, add the email you will use.
2. In **SQL Editor**, run:

```sql
update public.profiles
set role = 'admin', full_name = 'Farm Admin'
where id = (select id from auth.users where email = 'you@example.com');
```

> `public.profiles` has **no `email` column** — join through `auth.users`, as above.
> `handle_new_user()` auto-creates the profile row (as `role = 'customer'`) the moment
> the auth user is created, so the row already exists before you promote it.
>
> Run this in the Supabase **SQL Editor**. `protect_profile_role` normally blocks role
> changes for non-admins, but it permits this one because the editor connects as
> `postgres` — so there is no need to disable the trigger first. A regular
> authenticated browser session is still refused, which is what stops a customer
> from promoting themselves.

Verify it landed:

```sql
select p.role, u.email from public.profiles p
join auth.users u on u.id = p.id
where u.email = 'you@example.com';
```

3. Sign in at `https://<your-site>/rule/login.html` — done.

### Storage (product/blog images)

`rec-media` is created by `schema.sql` with **public read** and **write restricted
to admins**. When you upload images in the admin panel they are stored there;
customer/anon access is read-only thanks to storage RLS.

---

## Orders & Checkout

- Orders go into `public.orders`; the database trigger `assign_order_number` assigns
  references like `REC-2026-000001`.
- Items are stored as JSON (`items`), and a second trigger `sync_order_items`
  normalizes them into `order_items`.
- Fulfilment statuses: `pending → confirmed → processing → ready →
  out for delivery → completed` (or `cancelled`). Guests track orders on
  `order-success.html` via the `track_order(p_reference)` RPC — no sensitive data exposed.

---

## Deployment (Vercel)

The project is fully static — no build step.

1. Push to GitHub, then **Import Project → Vercel** and choose the repo.
2. Framework preset: **Other**. Output directory: leave as project root.
3. The storefront needs no env vars — the Supabase URL + anon key are inlined in
   `js/app.js`. The serverless routes need secrets:
   - `SUPABASE_URL` — required by both functions
   - `SUPABASE_SERVICE_ROLE_KEY` — required by both functions
   - `PAYSTACK_SECRET_KEY` — only if you enable Paystack checkout
4. Attach your custom domain (`rec-farms.com`), add the 
   `robots.txt`/`sitemap.xml` and you're live.

`vercel.json` maps every public URL onto the file that serves it and sets
long-lived cache headers for `/assets`, no-cache for `/css` and `/js`.

---

## Security Notes

- RLS is enabled on every table; anonymous access is limited to the exact
  `SELECT` needed by the storefront.
- Only `profiles.role = 'admin'` (enforced by `is_admin()`) can insert/update/delete
  products, orders, settings, etc.
- `track_order` returns only order status/eta fields to guests.
- The admin account is created inside your own Supabase — no shared credentials.

---

## Roadmap

- Store pickup scheduling & branch pickup alerts
- Bulk/B2B order flow & custom quotations
- Weather-based delivery advisories
- AI cohort recommendations (safe, privacy-preserving)
- Optional: ad skip / premium content upgrades
- On-farm tour bookings

---

## License

Proprietary — all rights reserved. Content, design and assets belong to
REC Livestock & Agro Farms Enterprises unless otherwise noted.