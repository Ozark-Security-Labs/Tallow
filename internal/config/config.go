package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Server        ServerConfig
	Postgres      PostgresConfig
	NATS          NATSConfig
	Storage       StorageConfig
	Auth          AuthConfig
	Notifications NotificationsConfig
	LLM           LLMConfig
	Metrics       MetricsConfig
	Log           LogConfig
}
type ServerConfig struct{ ListenAddress string }
type PostgresConfig struct{ DSN string }
type NATSConfig struct{ URL string }
type StorageConfig struct{ Root string }
type AuthConfig struct {
	Session AuthSessionConfig
	Local   AuthLocalConfig
	GitHub  AuthGitHubConfig
}
type AuthSessionConfig struct {
	CookieName         string
	TTL                string
	SecureCookies      bool
	DevInsecureCookies bool
}
type AuthLocalConfig struct {
	Enabled                bool
	BootstrapAdminEmail    string
	BootstrapAdminPassword string
}
type AuthGitHubConfig struct {
	Enabled      bool
	ClientID     string
	ClientSecret string
	CallbackURL  string
	AllowedOrgs  []string
	AllowedTeams []string
}
type NotificationsConfig struct {
	Email NotificationsEmailConfig
	Teams NotificationsTeamsConfig
}
type NotificationsEmailConfig struct {
	Enabled     bool
	SMTPHost    string
	SMTPPort    int
	Username    string
	PasswordRef string
	From        string
	To          []string
}
type NotificationsTeamsConfig struct {
	Enabled       bool
	WebhookURLRef string
}
type MetricsConfig struct{ Enabled bool }
type LogConfig struct{ Level string }

func Default() Config {
	return Config{Server: ServerConfig{"127.0.0.1:8844"}, Postgres: PostgresConfig{"postgres://tallow:tallow@localhost:5432/tallow?sslmode=disable"}, NATS: NATSConfig{"nats://localhost:4222"}, Storage: StorageConfig{"./var/tallow/storage"}, Auth: AuthConfig{Session: AuthSessionConfig{CookieName: "tallow_session", TTL: "24h", SecureCookies: true}, Local: AuthLocalConfig{Enabled: true}}, Notifications: NotificationsConfig{Email: NotificationsEmailConfig{SMTPHost: "localhost", SMTPPort: 25, From: "tallow@example.com"}, Teams: NotificationsTeamsConfig{}}, LLM: DefaultLLMConfig(), Metrics: MetricsConfig{true}, Log: LogConfig{"info"}}
}

func Load(env map[string]string) (Config, error) {
	c := Default()
	get := func(k string) (string, bool) { v, ok := env[k]; return strings.TrimSpace(v), ok }
	if v, ok := get("TALLOW_SERVER_LISTEN"); ok {
		c.Server.ListenAddress = v
	}
	if v, ok := get("TALLOW_POSTGRES_DSN"); ok {
		c.Postgres.DSN = v
	}
	if v, ok := get("TALLOW_NATS_URL"); ok {
		c.NATS.URL = v
	}
	if v, ok := get("TALLOW_STORAGE_ROOT"); ok {
		c.Storage.Root = v
	}
	if v, ok := get("TALLOW_AUTH_SESSION_COOKIE_NAME"); ok {
		c.Auth.Session.CookieName = v
	}
	if v, ok := get("TALLOW_AUTH_SESSION_TTL"); ok {
		c.Auth.Session.TTL = v
	}
	if v, ok := get("TALLOW_AUTH_SECURE_COOKIES"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return c, fmt.Errorf("invalid TALLOW_AUTH_SECURE_COOKIES: %w", err)
		}
		c.Auth.Session.SecureCookies = b
	}
	if v, ok := get("TALLOW_AUTH_DEV_INSECURE_COOKIES"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return c, fmt.Errorf("invalid TALLOW_AUTH_DEV_INSECURE_COOKIES: %w", err)
		}
		c.Auth.Session.DevInsecureCookies = b
	}
	if v, ok := get("TALLOW_AUTH_LOCAL_ENABLED"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return c, fmt.Errorf("invalid TALLOW_AUTH_LOCAL_ENABLED: %w", err)
		}
		c.Auth.Local.Enabled = b
	}
	if v, ok := get("TALLOW_AUTH_LOCAL_BOOTSTRAP_ADMIN_EMAIL"); ok {
		c.Auth.Local.BootstrapAdminEmail = v
	}
	if v, ok := get("TALLOW_AUTH_LOCAL_BOOTSTRAP_ADMIN_PASSWORD"); ok {
		c.Auth.Local.BootstrapAdminPassword = v
	}
	if v, ok := get("TALLOW_AUTH_GITHUB_ENABLED"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return c, fmt.Errorf("invalid TALLOW_AUTH_GITHUB_ENABLED: %w", err)
		}
		c.Auth.GitHub.Enabled = b
	}
	if v, ok := get("TALLOW_AUTH_GITHUB_CLIENT_ID"); ok {
		c.Auth.GitHub.ClientID = v
	}
	if v, ok := get("TALLOW_AUTH_GITHUB_CLIENT_SECRET"); ok {
		c.Auth.GitHub.ClientSecret = v
	}
	if v, ok := get("TALLOW_AUTH_GITHUB_CALLBACK_URL"); ok {
		c.Auth.GitHub.CallbackURL = v
	}
	if v, ok := get("TALLOW_AUTH_GITHUB_ALLOWED_ORGS"); ok {
		c.Auth.GitHub.AllowedOrgs = splitCSV(v)
	}
	if v, ok := get("TALLOW_AUTH_GITHUB_ALLOWED_TEAMS"); ok {
		c.Auth.GitHub.AllowedTeams = splitCSV(v)
	}
	if v, ok := get("TALLOW_NOTIFICATIONS_EMAIL_ENABLED"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return c, fmt.Errorf("invalid TALLOW_NOTIFICATIONS_EMAIL_ENABLED: %w", err)
		}
		c.Notifications.Email.Enabled = b
	}
	if v, ok := get("TALLOW_NOTIFICATIONS_EMAIL_SMTP_HOST"); ok {
		c.Notifications.Email.SMTPHost = v
	}
	if v, ok := get("TALLOW_NOTIFICATIONS_EMAIL_SMTP_PORT"); ok {
		p, err := strconv.Atoi(v)
		if err != nil {
			return c, fmt.Errorf("invalid TALLOW_NOTIFICATIONS_EMAIL_SMTP_PORT: %w", err)
		}
		c.Notifications.Email.SMTPPort = p
	}
	if v, ok := get("TALLOW_NOTIFICATIONS_EMAIL_PASSWORD_REF"); ok {
		c.Notifications.Email.PasswordRef = v
	}
	if v, ok := get("TALLOW_NOTIFICATIONS_EMAIL_FROM"); ok {
		c.Notifications.Email.From = v
	}
	if v, ok := get("TALLOW_NOTIFICATIONS_EMAIL_TO"); ok {
		c.Notifications.Email.To = splitCSV(v)
	}
	if v, ok := get("TALLOW_NOTIFICATIONS_TEAMS_ENABLED"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return c, fmt.Errorf("invalid TALLOW_NOTIFICATIONS_TEAMS_ENABLED: %w", err)
		}
		c.Notifications.Teams.Enabled = b
	}
	if v, ok := get("TALLOW_NOTIFICATIONS_TEAMS_WEBHOOK_URL_REF"); ok {
		c.Notifications.Teams.WebhookURLRef = v
	}

	if v, ok := get("TALLOW_LLM_ENABLED"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return c, fmt.Errorf("invalid TALLOW_LLM_ENABLED: %w", err)
		}
		c.LLM.Enabled = b
	}
	if v, ok := get("TALLOW_LLM_PROVIDER_TYPE"); ok {
		c.LLM.Provider.Type = v
	}
	if v, ok := get("TALLOW_LLM_PROVIDER_NAME"); ok {
		c.LLM.Provider.Name = v
	}
	if v, ok := get("TALLOW_LLM_PROVIDER_MODEL"); ok {
		c.LLM.Provider.Model = v
	}
	if v, ok := get("TALLOW_LLM_PROVIDER_COMMAND"); ok {
		c.LLM.Provider.Command = splitCSV(v)
	}
	if v, ok := get("TALLOW_LLM_PROVIDER_ENDPOINT"); ok {
		c.LLM.Provider.Endpoint = v
	}
	if v, ok := get("TALLOW_LLM_PROVIDER_API_KEY_ENV"); ok {
		c.LLM.Provider.APIKeyEnv = v
	}
	if v, ok := get("TALLOW_LLM_PROMPT_TEMPLATE"); ok {
		c.LLM.PromptTemplate = v
	}
	if v, ok := get("TALLOW_LLM_REDACTION_POLICY"); ok {
		c.LLM.RedactionPolicy = v
	}
	if v, ok := get("TALLOW_LLM_MAX_EVIDENCE_ITEMS"); ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			return c, fmt.Errorf("invalid TALLOW_LLM_MAX_EVIDENCE_ITEMS: %w", err)
		}
		c.LLM.MaxEvidenceItems = n
	}
	if v, ok := get("TALLOW_LLM_MAX_SNIPPET_BYTES"); ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			return c, fmt.Errorf("invalid TALLOW_LLM_MAX_SNIPPET_BYTES: %w", err)
		}
		c.LLM.MaxSnippetBytes = n
	}
	if v, ok := get("TALLOW_LLM_TIMEOUT_SECONDS"); ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			return c, fmt.Errorf("invalid TALLOW_LLM_TIMEOUT_SECONDS: %w", err)
		}
		c.LLM.TimeoutSeconds = n
	}

	if v, ok := get("TALLOW_METRICS_ENABLED"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return c, fmt.Errorf("invalid TALLOW_METRICS_ENABLED: %w", err)
		}
		c.Metrics.Enabled = b
	}
	if v, ok := get("TALLOW_LOG_LEVEL"); ok {
		c.Log.Level = v
	}
	return c, c.Validate()
}
func LoadFromEnvironment() (Config, error) {
	env := map[string]string{}
	for _, e := range os.Environ() {
		parts := strings.SplitN(e, "=", 2)
		env[parts[0]] = parts[1]
	}
	return Load(env)
}
func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.Server.ListenAddress) == "" {
		return fmt.Errorf("server listen address required")
	}
	if strings.TrimSpace(c.Postgres.DSN) == "" {
		return fmt.Errorf("postgres dsn required")
	}
	if strings.TrimSpace(c.NATS.URL) == "" {
		return fmt.Errorf("nats url required")
	}
	if strings.TrimSpace(c.Storage.Root) == "" || strings.TrimSpace(c.Storage.Root) == "/" {
		return fmt.Errorf("unsafe storage root")
	}
	if strings.TrimSpace(c.Auth.Session.CookieName) == "" {
		return fmt.Errorf("auth session cookie name required")
	}
	if _, err := time.ParseDuration(c.Auth.Session.TTL); err != nil {
		return fmt.Errorf("invalid auth session ttl: %w", err)
	}
	if err := c.LLM.Validate(); err != nil {
		return err
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
		return nil
	default:
		return fmt.Errorf("invalid log level %q", c.Log.Level)
	}
}
