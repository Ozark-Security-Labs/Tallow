package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct { Server ServerConfig; Postgres PostgresConfig; NATS NATSConfig; Storage StorageConfig; Metrics MetricsConfig; Log LogConfig }
type ServerConfig struct{ ListenAddress string }
type PostgresConfig struct{ DSN string }
type NATSConfig struct{ URL string }
type StorageConfig struct{ Root string }
type MetricsConfig struct{ Enabled bool }
type LogConfig struct{ Level string }

func Default() Config { return Config{Server:ServerConfig{"127.0.0.1:8844"}, Postgres:PostgresConfig{"postgres://tallow:tallow@localhost:5432/tallow?sslmode=disable"}, NATS:NATSConfig{"nats://localhost:4222"}, Storage:StorageConfig{"./var/tallow/storage"}, Metrics:MetricsConfig{true}, Log:LogConfig{"info"}} }

func Load(env map[string]string) (Config,error){ c:=Default(); get:=func(k string)(string,bool){v,ok:=env[k]; return strings.TrimSpace(v),ok}
 if v,ok:=get("TALLOW_SERVER_LISTEN"); ok { c.Server.ListenAddress=v }
 if v,ok:=get("TALLOW_POSTGRES_DSN"); ok { c.Postgres.DSN=v }
 if v,ok:=get("TALLOW_NATS_URL"); ok { c.NATS.URL=v }
 if v,ok:=get("TALLOW_STORAGE_ROOT"); ok { c.Storage.Root=v }
 if v,ok:=get("TALLOW_METRICS_ENABLED"); ok { b,err:=strconv.ParseBool(v); if err!=nil { return c,fmt.Errorf("invalid TALLOW_METRICS_ENABLED: %w",err)}; c.Metrics.Enabled=b }
 if v,ok:=get("TALLOW_LOG_LEVEL"); ok { c.Log.Level=v }
 return c, c.Validate() }
func LoadFromEnvironment()(Config,error){ env:=map[string]string{}; for _,e:=range os.Environ(){ parts:=strings.SplitN(e,"=",2); env[parts[0]]=parts[1]}; return Load(env)}
func (c Config) Validate() error { if strings.TrimSpace(c.Server.ListenAddress)=="" {return fmt.Errorf("server listen address required")}; if strings.TrimSpace(c.Postgres.DSN)=="" {return fmt.Errorf("postgres dsn required")}; if strings.TrimSpace(c.NATS.URL)=="" {return fmt.Errorf("nats url required")}; if strings.TrimSpace(c.Storage.Root)==""||strings.TrimSpace(c.Storage.Root)=="/" {return fmt.Errorf("unsafe storage root")}; switch c.Log.Level{case "debug","info","warn","error": return nil; default: return fmt.Errorf("invalid log level %q",c.Log.Level)} }
