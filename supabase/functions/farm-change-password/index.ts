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

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return json({ error: "Invalid request body." }, 400); }
  const password = String(body.password ?? "");
  if (password.length < 12) return json({ error: "Use a password with at least 12 characters." }, 400);

  const caller = createSupabaseClient(url, publishable, { auth: { persistSession: false, autoRefreshToken: false } });
  const { data: userData, error: userError } = await caller.auth.getUser(accessToken);
  const user = userData.user;
  if (userError || !user) return json({ error: "Your sign-in session is invalid." }, 401);

  const admin = createSupabaseClient(url, secret, { auth: { persistSession: false, autoRefreshToken: false } });
  const { data: membership, error: membershipError } = await admin
    .from("farm_members")
    .select("user_id, active")
    .eq("user_id", user.id)
    .maybeSingle();
  if (membershipError || !membership || !membership.active) return json({ error: "Active farm account required." }, 403);

  const { error: passwordError } = await admin.auth.admin.updateUserById(user.id, { password });
  if (passwordError) return json({ error: passwordError.message }, 400);
  const { error: flagError } = await admin.from("farm_members")
    .update({ must_change_password: false, updated_at: new Date().toISOString() })
    .eq("user_id", user.id);
  if (flagError) return json({ error: "Password saved, but account status did not update. Contact an administrator." }, 500);
  return json({ ok: true });
});
