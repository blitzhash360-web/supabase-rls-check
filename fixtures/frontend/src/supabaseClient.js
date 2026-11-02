// BAD: service role key shipped to the browser (fake JWT for fixture only)
import { createClient } from "@supabase/supabase-js";

const supabaseUrl = "https://example.supabase.co";
// This is a fabricated JWT-shaped string for scanner tests — not a real credential.
const SUPABASE_SERVICE_ROLE_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwiZXhwIjoxOTk5OTk5OTk5fQ.fixture_not_a_real_secret_value_xxxxxx";

export const supabase = createClient(supabaseUrl, SUPABASE_SERVICE_ROLE_KEY);
