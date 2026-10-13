/* ============================================================
   REC — Admin: create staff accounts (Vercel serverless)
   ------------------------------------------------------------
   Creating an authenticated user requires the Supabase service-role
   key, which must NEVER reach the browser. This function:
     1. verifies the caller's Supabase access token,
     2. confirms the caller is a full admin (owner/administrator/admin),
     3. creates the auth user with the service-role key,
     4. promotes the auto-created profile to the requested staff role.

   Env vars (Vercel → Settings → Environment Variables):
     SUPABASE_URL                 (same as verify-payment.js)
     SUPABASE_SERVICE_ROLE_KEY    (same as verify-payment.js)

   Body (JSON): { email, password, full_name, phone, role }
     role ∈ administrator | admin | manager | seller
   Header: Authorization: Bearer <signed-in user's access token>
   ============================================================ */

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

const FULL_ADMIN_ROLES = ["owner", "administrator", "admin"];
const ASSIGNABLE_ROLES = ["administrator", "manager", "seller"];

function json(res, status, body) {
  return res.status(status).json(body);
}

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Cache-Control", "no-store");
}

function serviceHeaders(extra) {
  return Object.assign(
    {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: "Bearer " + SUPABASE_SERVICE_ROLE_KEY,
    },
    extra || {}
  );
}

function parseBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  if (typeof req.body === "string" && req.body.trim()) {
    try {
      return JSON.parse(req.body);
    } catch (e) {
      return null;
    }
  }
  return null;
}

export default async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") {
    return json(res, 405, { ok: false, error: "Method not allowed" });
  }
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    return json(res, 500, { ok: false, error: "Staff creation is not configured on the server." });
  }

  // 1. Identify the caller from their bearer token.
  const authHeader = String(req.headers.authorization || "");
  const token = authHeader.toLowerCase().startsWith("bearer ")
    ? authHeader.slice(7).trim()
    : "";
  if (!token) return json(res, 401, { ok: false, error: "Missing session. Please sign in again." });

  let caller;
  try {
    const ur = await fetch(SUPABASE_URL + "/auth/v1/user", {
      headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: "Bearer " + token },
    });
    caller = await ur.json().catch(() => null);
    if (!ur.ok || !caller || !caller.id) {
      return json(res, 401, { ok: false, error: "Your session has expired. Please sign in again." });
    }
  } catch (e) {
    return json(res, 401, { ok: false, error: "Could not verify your session." });
  }

  // 2. The caller must be a full admin.
  try {
    const pr = await fetch(
      SUPABASE_URL +
        "/rest/v1/profiles?id=eq." +
        encodeURIComponent(caller.id) +
        "&select=role,active",
      { headers: serviceHeaders() }
    );
    const rows = await pr.json().catch(() => null);
    const profile = Array.isArray(rows) ? rows[0] : null;
    if (!profile || FULL_ADMIN_ROLES.indexOf(profile.role) === -1 || profile.active === false) {
      return json(res, 403, { ok: false, error: "Only an owner or administrator can add staff." });
    }
  } catch (e) {
    return json(res, 403, { ok: false, error: "Could not confirm your permissions." });
  }

  // 3. Validate the request.
  const body = parseBody(req);
  if (!body) return json(res, 400, { ok: false, error: "Invalid request body." });

  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  const full_name = String(body.full_name || "").trim();
  const phone = String(body.phone || "").trim();
  const role = String(body.role || "").trim().toLowerCase();

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return json(res, 400, { ok: false, error: "Enter a valid email address." });
  }
  if (password.length < 8) {
    return json(res, 400, { ok: false, error: "Password must be at least 8 characters." });
  }
  if (!full_name) {
    return json(res, 400, { ok: false, error: "Full name is required." });
  }
  if (ASSIGNABLE_ROLES.indexOf(role) === -1) {
    return json(res, 400, {
      ok: false,
      error: "Role must be administrator, manager or seller.",
    });
  }

  // 4. Create the auth user (email auto-confirmed; owner sets a temp password).
  let created;
  try {
    const cr = await fetch(SUPABASE_URL + "/auth/v1/admin/users", {
      method: "POST",
      headers: serviceHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        email,
        password,
        email_confirm: true,
        user_metadata: { full_name, phone },
      }),
    });
    created = await cr.json().catch(() => null);
    if (!cr.ok || !created || !created.id) {
      const msg = (created && (created.msg || created.message || created.error_description)) || "";
      if (cr.status === 422 || /already|registered|exists/i.test(msg)) {
        return json(res, 409, { ok: false, error: "A user with this email already exists." });
      }
      return json(res, 400, { ok: false, error: msg || "Could not create the staff account." });
    }
  } catch (e) {
    return json(res, 500, { ok: false, error: "Could not reach the authentication service." });
  }

  // 5. Promote the profile (created as 'customer' by the on-signup trigger).
  try {
    const ur = await fetch(
      SUPABASE_URL + "/rest/v1/profiles?id=eq." + encodeURIComponent(created.id),
      {
        method: "PATCH",
        headers: serviceHeaders({
          "Content-Type": "application/json",
          Prefer: "return=representation",
        }),
        body: JSON.stringify({ role, full_name, phone: phone || null }),
      }
    );
    const updated = await ur.json().catch(() => null);
    if (!ur.ok) {
      return json(res, 500, {
        ok: false,
        error: "Account created but the role could not be assigned. Set it from the staff list.",
      });
    }
    // 6. Best-effort audit entry (never fail the request over logging).
    try {
      await fetch(SUPABASE_URL + "/rest/v1/activity_logs", {
        method: "POST",
        headers: serviceHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          actor: caller.id,
          actor_email: caller.email || null,
          action: "staff.created",
          entity: "profiles",
          entity_id: created.id,
          detail: { email, role, full_name },
        }),
      });
    } catch (e) {}

    return json(res, 200, {
      ok: true,
      user: {
        id: created.id,
        email,
        full_name,
        role: Array.isArray(updated) && updated[0] ? updated[0].role : role,
      },
    });
  } catch (e) {
    return json(res, 500, {
      ok: false,
      error: "Account created but the role could not be assigned. Set it from the staff list.",
    });
  }
}
