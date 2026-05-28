package config

import "testing"

func TestDefaults(t *testing.T) {
	c, err := Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.ListenAddress != "127.0.0.1:8844" || !c.Metrics.Enabled || c.Auth.Session.CookieName != "tallow_session" || !c.Auth.Local.Enabled {
		t.Fatalf("bad defaults %#v", c)
	}
}
func TestOverrides(t *testing.T) {
	c, err := Load(map[string]string{"TALLOW_SERVER_LISTEN": ":1", "TALLOW_POSTGRES_DSN": "postgres://x", "TALLOW_NATS_URL": "nats://x", "TALLOW_STORAGE_ROOT": "./data", "TALLOW_AUTH_SESSION_COOKIE_NAME": "custom_session", "TALLOW_AUTH_SESSION_TTL": "12h", "TALLOW_AUTH_SECURE_COOKIES": "false", "TALLOW_AUTH_DEV_INSECURE_COOKIES": "true", "TALLOW_AUTH_LOCAL_ENABLED": "false", "TALLOW_AUTH_LOCAL_BOOTSTRAP_ADMIN_EMAIL": "admin@example.com", "TALLOW_AUTH_LOCAL_BOOTSTRAP_ADMIN_PASSWORD": "test-password", "TALLOW_METRICS_ENABLED": "false", "TALLOW_LOG_LEVEL": "debug"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.ListenAddress != ":1" || c.Metrics.Enabled || c.Log.Level != "debug" || c.Auth.Session.CookieName != "custom_session" || c.Auth.Session.TTL != "12h" || c.Auth.Session.SecureCookies || !c.Auth.Session.DevInsecureCookies || c.Auth.Local.Enabled {
		t.Fatalf("bad override %#v", c)
	}
}
func TestInvalids(t *testing.T) {
	for _, env := range []map[string]string{{"TALLOW_STORAGE_ROOT": "/"}, {"TALLOW_LOG_LEVEL": "verbose"}, {"TALLOW_METRICS_ENABLED": "maybe"}, {"TALLOW_AUTH_SESSION_TTL": "soon"}, {"TALLOW_AUTH_SECURE_COOKIES": "maybe"}} {
		if _, err := Load(env); err == nil {
			t.Fatalf("expected error for %#v", env)
		}
	}
}
