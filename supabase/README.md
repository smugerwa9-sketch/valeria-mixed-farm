# Valeria account service

This directory contains the Supabase schema and Edge Functions used by the Valeria app.
The project is intentionally separate from VISION 2026; do not point these functions at that project.

## Bootstrap

1. Create a dedicated Supabase organization and a project named Valeria Mixed Farm.
2. Apply `schema.sql` to that project.
3. Insert the initial administrator email into `farm_bootstrap`. The first administrator must sign up with that verified email and then use the one-time bootstrap function.
4. Deploy `bootstrap-farm-admin`, `farm-admin-users`, and `farm-change-password` with JWT verification enabled.
5. Use the project's publishable key in the public site. Keep its secret key only in Supabase Edge Function environment variables.

The app will use Supabase Auth for email/password login, a server-side membership table for roles, and a shared farm-state row protected by RLS. Admin-created accounts receive a temporary password and must change it on first sign-in. Passwords are sent to Supabase Auth over HTTPS and are never stored by the Valeria app.
