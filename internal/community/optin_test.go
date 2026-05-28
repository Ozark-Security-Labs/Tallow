package community

import (
	"context"
	"errors"
	"github.com/Ozark-Security-Labs/Tallow/internal/auth"
	"github.com/Ozark-Security-Labs/Tallow/internal/config"
	"testing"
)

func TestOptInStoresClassesAndAnonymization(t *testing.T) {
	opt := NewOptIn(config.CommunitySignalsConfig{Sharing: config.CommunitySignalSharingConfig{Enabled: true, OrganizationID: "org", AllowedSignalClasses: []string{"yanked", "deprecated"}, AnonymizationLevel: "hashed"}})
	if !opt.Enabled || opt.AnonymizationLevel != "hashed" || opt.AllowedSignalClasses[0] != "deprecated" {
		t.Fatalf("opt=%+v", opt)
	}
}
func TestAdminRequiredToEnable(t *testing.T) {
	if _, err := Enable([]auth.Role{auth.RoleViewer}, OptIn{}); !errors.Is(err, ErrAdminRequired) {
		t.Fatalf("err=%v", err)
	}
	opt, err := Enable([]auth.Role{auth.RoleAdmin}, OptIn{AllowedSignalClasses: []string{"yanked"}})
	if err != nil || !opt.Enabled {
		t.Fatalf("opt=%+v err=%v", opt, err)
	}
}
func TestDisabledOrgEmitsNoSignal(t *testing.T) {
	store := &Store{OptIn: OptIn{Enabled: false, AllowedSignalClasses: []string{"yanked"}}}
	err := store.Emit(context.Background(), Signal{ID: "S-1", Class: "yanked"})
	if !errors.Is(err, ErrCommunitySignalsDisabled) {
		t.Fatalf("err=%v", err)
	}
	if len(store.Emitted) != 0 {
		t.Fatalf("emitted=%+v", store.Emitted)
	}
}
