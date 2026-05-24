package config

import "testing"

func TestDefaults(t *testing.T) {
	c, err := Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.ListenAddress != "127.0.0.1:8844" || !c.Metrics.Enabled {
		t.Fatalf("bad defaults %#v", c)
	}
}
func TestOverrides(t *testing.T) {
	c, err := Load(map[string]string{"TALLOW_SERVER_LISTEN": ":1", "TALLOW_POSTGRES_DSN": "postgres://x", "TALLOW_NATS_URL": "nats://x", "TALLOW_STORAGE_ROOT": "./data", "TALLOW_METRICS_ENABLED": "false", "TALLOW_LOG_LEVEL": "debug"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.ListenAddress != ":1" || c.Metrics.Enabled || c.Log.Level != "debug" {
		t.Fatalf("bad override %#v", c)
	}
}
func TestInvalids(t *testing.T) {
	for _, env := range []map[string]string{{"TALLOW_STORAGE_ROOT": "/"}, {"TALLOW_LOG_LEVEL": "verbose"}, {"TALLOW_METRICS_ENABLED": "maybe"}} {
		if _, err := Load(env); err == nil {
			t.Fatalf("expected error for %#v", env)
		}
	}
}
