package community

import (
	"context"
	"errors"
	"github.com/Ozark-Security-Labs/Tallow/internal/auth"
	"github.com/Ozark-Security-Labs/Tallow/internal/config"
	"github.com/Ozark-Security-Labs/Tallow/internal/rbac"
	"sort"
)

var ErrCommunitySignalsDisabled = errors.New("community signal sharing disabled")
var ErrAdminRequired = errors.New("admin role required to enable community sharing")

type OptIn struct {
	OrganizationID       string
	Enabled              bool
	AllowedSignalClasses []string
	AnonymizationLevel   string
}
type Signal struct {
	ID        string
	Class     string
	Ecosystem string
	Package   string
}
type Store struct {
	OptIn   OptIn
	Emitted []Signal
}

func NewOptIn(cfg config.CommunitySignalsConfig) OptIn {
	classes := append([]string(nil), cfg.Sharing.AllowedSignalClasses...)
	sort.Strings(classes)
	return OptIn{OrganizationID: cfg.Sharing.OrganizationID, Enabled: cfg.Sharing.Enabled, AllowedSignalClasses: classes, AnonymizationLevel: cfg.Sharing.AnonymizationLevel}
}
func Enable(currentRoles []auth.Role, opt OptIn) (OptIn, error) {
	if !rbac.Allowed(currentRoles, rbac.ManageIntegrations) {
		return OptIn{}, ErrAdminRequired
	}
	opt.Enabled = true
	sort.Strings(opt.AllowedSignalClasses)
	return opt, nil
}
func (s *Store) Emit(ctx context.Context, sig Signal) error {
	if !s.OptIn.Enabled {
		return ErrCommunitySignalsDisabled
	}
	if !classAllowed(s.OptIn.AllowedSignalClasses, sig.Class) {
		return nil
	}
	s.Emitted = append(s.Emitted, sig)
	return nil
}
func classAllowed(classes []string, class string) bool {
	if len(classes) == 0 {
		return false
	}
	for _, c := range classes {
		if c == class {
			return true
		}
	}
	return false
}
