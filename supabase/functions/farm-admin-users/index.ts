import { createClient } from "npm:@supabase/supabase-js@2.119.0";

const origin = "https://smugerwa9-sketch.github.io";
const corsHeaders = {
  "Access-Control-Allow-Origin": origin,
  "Access-Control-Allow-Headers": "authorization, apikey, x-client-info, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Vary": "Origin",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });

function keys(name: string) {
  const raw = Deno.env.get(name) ?? "{}";
  try { return JSON.parse(raw); } catch { return {}; }
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  const authHeader = req.headers.get("Authorization") ?? "";
  const accessToken = authHeader.replace(/^Bearer\s+/i, "");
  if (!accessToken || accessToken === authHeader) return json({ error: "Sign in first." }, 401);
  const url = Deno.env.get("SUPABASE_URL");
  const publishable = keys("SUPABASE_PUBLISHABLE_KEYS").default ?? Deno.env.get("SUPABASE_ANON_KEY");
  const secret = keys("SUPABASE_SECRET_KEYS").default ?? Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !publishable || !secret) return json({ error: "Server authentication is not configured." }, 500);

  const caller = createClient(url, publishable, { auth: { persistSession: false, autoRefreshToken: false } });
  const { data: userData, error: userError } = await caller.auth.getUser(accessToken);
  const user = userData.user;
  if (userError || !user) return json({ error: "Your sign-in session is invalid." }, 401);

  const admin = createClient(url, secret, { auth: { persistSession: false, autoRefreshToken: false } });
  const { data: membership, error: membershipError } = await admin
    .from("farm_members")
    .select("role, active, must_change_password")
    .eq("user_id", user.id)
    .maybeSingle();
  if (membershipError) return json({ error: "Could not check farm access." }, 500);
  if (!membership || membership.role !== "admin" || !membership.active || membership.must_change_password) {
    return json({ error: "Administrator access is required." }, 403);
  }

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return json({ error: "Invalid request body." }, 400); }
  const action = String(body.action ?? "");

  if (action === "list") {
    const { data, error } = await admin
      .from("farm_members")
      .select("user_id, email, display_name, role, active, must_change_password, created_at")
      .order("created_at", { ascending: true });
    if (error) return json({ error: "Could not load farm accounts." }, 500);
    return json({ users: data ?? [] });
  }

  if (action === "create") {
    const email = String(body.email ?? "").trim().toLowerCase();
    const displayName = String(body.display_name ?? "").trim().slice(0, 80);
    const password = String(body.password ?? "");
    const role = body.role === "admin" ? "admin" : body.role === "user" ? "user" : "";
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: "Enter a valid email address." }, 400);
    if (password.length < 12) return json({ error: "Temporary passwords must contain at least 12 characters." }, 400);
    if (!role) return json({ error: "Choose a valid account role." }, 400);

    const { data: created, error: createError } = await admin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { display_name: displayName },
    });
    if (createError || !created.user) return json({ error: createError?.message ?? "Could not create the account." }, 400);

    const { error: insertError } = await admin.from("farm_members").insert({
      user_id: created.user.id,
      email,
      display_name: displayName,
      role,
      active: true,
      must_change_password: true,
    });
    if (insertError) {
      await admin.auth.admin.deleteUser(created.user.id);
      return json({ error: "The account was created but could not be added to farm access. Please retry." }, 500);
    }
    return json({ user: { user_id: created.user.id, email, display_name: displayName, role, must_change_password: true } }, 201);
  }

  if (action === "reset_password") {
    const targetId = String(body.user_id ?? "");
    const password = String(body.password ?? "");
    if (!targetId) return json({ error: "Choose a farm account." }, 400);
    if (password.length < 12) return json({ error: "Temporary passwords must contain at least 12 characters." }, 400);
    if (targetId === user.id) return json({ error: "Use your own account settings to change your password." }, 400);

    const { data: target, error: targetError } = await admin
      .from("farm_members")
      .select("user_id")
      .eq("user_id", targetId)
      .maybeSingle();
    if (targetError || !target) return json({ error: "Farm account not found." }, 404);
    const { error: passwordError } = await admin.auth.admin.updateUserById(targetId, { password });
    if (passwordError) return json({ error: "Could not reset the password." }, 400);
    const { error: flagError } = await admin
      .from("farm_members")
      .update({ must_change_password: true, updated_at: new Date().toISOString() })
      .eq("user_id", targetId);
    if (flagError) return json({ error: "Password changed, but the account reset flag could not be updated." }, 500);
    return json({ ok: true });
  }

  if (action === "set_role") {
    const targetId = String(body.user_id ?? "");
    const role = body.role === "admin" ? "admin" : body.role === "user" ? "user" : "";
    if (!targetId || !role) return json({ error: "Choose an account and role." }, 400);
    if (targetId === user.id && role !== "admin") return json({ error: "You cannot remove your own administrator access here." }, 400);
    const { data: target, error: targetError } = await admin
      .from("farm_members")
      .select("role, active")
      .eq("user_id", targetId)
      .maybeSingle();
    if (targetError || !target) return json({ error: "Farm account not found." }, 404);
    if (target.role === "admin" && target.active && role !== "admin") {
      const { count, error: countError } = await admin
        .from("farm_members")
        .select("user_id", { count: "exact", head: true })
        .eq("role", "admin")
        .eq("active", true);
      if (countError || (count ?? 0) <= 1) return json({ error: "Keep at least one active farm administrator." }, 409);
    }
    const { error } = await admin.from("farm_members")
      .update({ role, updated_at: new Date().toISOString() })
      .eq("user_id", targetId);
    if (error) return json({ error: "Could not update the account role." }, 500);
    return json({ ok: true });
  }

  if (action === "set_active") {
    const targetId = String(body.user_id ?? "");
    const active = body.active === true;
    if (!targetId) return json({ error: "Choose a farm account." }, 400);
    if (targetId === user.id && !active) return json({ error: "You cannot deactivate your own administrator account." }, 400);
    const { data: target, error: targetError } = await admin
      .from("farm_members")
      .select("role, active")
      .eq("user_id", targetId)
      .maybeSingle();
    if (targetError || !target) return json({ error: "Farm account not found." }, 404);
    if (!active && target.role === "admin" && target.active) {
      const { count, error: countError } = await admin
        .from("farm_members")
        .select("user_id", { count: "exact", head: true })
        .eq("role", "admin")
        .eq("active", true);
      if (countError || (count ?? 0) <= 1) return json({ error: "Keep at least one active farm administrator." }, 409);
    }
    const { error } = await admin.from("farm_members")
      .update({ active, updated_at: new Date().toISOString() })
      .eq("user_id", targetId);
    if (error) return json({ error: "Could not update the account status." }, 500);
    return json({ ok: true });
  }

  return json({ error: "Unknown account action." }, 400);
});
