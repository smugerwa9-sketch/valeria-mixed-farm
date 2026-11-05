import { corsHeaders as sdkCorsHeaders } from "npm:@supabase/supabase-js@2.119.0/cors";
import { createClient as createSupabaseClient } from "npm:@supabase/supabase-js@2.119.0";

const origin = "https://smugerwa9-sketch.github.io";
const corsHeaders = { ...sdkCorsHeaders, "Access-Control-Allow-Origin": origin, "Vary": "Origin" };
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

  const caller = createSupabaseClient(url, publishable, { auth: { persistSession: false, autoRefreshToken: false } });
  const { data: userData, error: userError } = await caller.auth.getUser(accessToken);
  const user = userData.user;
  if (userError || !user) return json({ error: "Your sign-in session is invalid." }, 401);
  if (!user.email_confirmed_at) return json({ error: "Verify your email before activating the farm administrator account." }, 403);

  const admin = createSupabaseClient(url, secret, { auth: { persistSession: false, autoRefreshToken: false } });
  const { data: current, error: memberError } = await admin
    .from("farm_members")
    .select("role, active")
    .eq("user_id", user.id)
    .maybeSingle();
  if (memberError) return json({ error: "Could not check farm access." }, 500);
  if (current?.role === "admin" && current.active) return json({ role: "admin", alreadyActive: true });
  if (current) return json({ error: "This account already has a farm role." }, 403);

  const { data: bootstrap, error: bootstrapError } = await admin
    .from("farm_bootstrap")
    .select("admin_email, claimed_user_id")
    .eq("singleton", true)
    .maybeSingle();
  if (bootstrapError || !bootstrap) return json({ error: "Administrator setup is unavailable." }, 500);
  if (String(user.email ?? "").toLowerCase() !== String(bootstrap.admin_email).toLowerCase()) {
    return json({ error: "This email is not authorized to initialize the farm administrator." }, 403);
  }
  if (bootstrap.claimed_user_id) return json({ error: "The first administrator has already been set up." }, 409);

  const { data: claim, error: claimError } = await admin
    .from("farm_bootstrap")
    .update({ claimed_user_id: user.id, claimed_at: new Date().toISOString() })
    .eq("singleton", true)
    .is("claimed_user_id", null)
    .select("singleton")
    .maybeSingle();
  if (claimError || !claim) return json({ error: "Administrator setup was already claimed. Sign in again." }, 409);

  const { error: insertError } = await admin.from("farm_members").insert({
    user_id: user.id,
    email: user.email,
    display_name: String(user.user_metadata?.display_name ?? ""),
    role: "admin",
    active: true,
    must_change_password: false,
  });
  if (insertError) {
    await admin.from("farm_bootstrap").update({ claimed_user_id: null, claimed_at: null }).eq("singleton", true).eq("claimed_user_id", user.id);
    return json({ error: "Could not activate the administrator account." }, 500);
  }
  return json({ role: "admin" });
});
