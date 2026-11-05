# Valeria account service

This directory contains the Supabase schema and Edge Functions used by the Valeria app. The project must be created in a separate Supabase organization and must never point at VISION 2026.

## Initial setup

1. Create a dedicated Supabase organization and a project named Valeria Mixed Farm.
2. Apply `schema.sql` to that project.
3. Privately insert the owner-approved first administrator email into `public.farm_bootstrap`. Do not commit that email to this public repository.
4. Add the GitHub Pages site URL to Supabase Auth's allowed redirect URLs for email confirmation and password recovery.
5. Deploy `bootstrap-farm-admin`, `farm-admin-users`, and `farm-change-password` with JWT verification enabled.
6. Put only the project's URL and publishable key in the public app. Keep the secret key in Supabase Edge Function environment variables.
7. Add the URL and publishable key to the marked constants in `index.html`, then publish the site.

The first administrator creates an account, verifies the approved email, signs in, and claims the one-time administrator role. Administrators create user and admin accounts with temporary passwords; every new or reset account must choose a new password before opening farm records. Passwords are held by Supabase Auth and are never stored in Valeria's farm tables.

The app starts with empty shared records. It does not import browser-local prototype data. Inventory, animal profiles, health observations, and activity records are read and written through the shared `farm_state` row under member-only RLS policies. The app checks for updates from other signed-in accounts and prevents an outdated browser session from silently replacing a newer farm state.

## Local configuration

The static site uses Supabase's browser CDN build. Replace `__SUPABASE_URL__` and `__SUPABASE_PUBLISHABLE_KEY__` in the app source when the dedicated project exists. Publishable keys are intended for browser use; secret keys are not.
