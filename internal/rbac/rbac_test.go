package rbac

import (
	"testing"

	"github.com/Ozark-Security-Labs/Tallow/internal/auth"
)

func TestRoleMatrix(t *testing.T) {
	tests := []struct {
		name  string
		roles []auth.Role
		allow []Permission
		deny  []Permission
	}{
		{
			name:  "viewer read only",
			roles: []auth.Role{auth.RoleViewer},
			allow: []Permission{ReadDashboard, ReadPackages, ReadFindings, ReadAlerts, ReadImpact, ReadAnalyzerRuns, ReadSettings},
			deny:  []Permission{TriageFindings, TriageAlerts, MutateSettings, ManageUsers, ManageIntegrations, ManageNotifications, MutateScans, TestNotifications},
		},
		{
			name:  "analyst triage only",
			roles: []auth.Role{auth.RoleAnalyst},
			allow: []Permission{ReadFindings, TriageFindings, ReadAlerts, TriageAlerts},
			deny:  []Permission{MutateSettings, ManageUsers, ManageIntegrations, ManageNotifications, MutateScans, TestNotifications},
		},
		{
			name:  "admin manages integrations",
			roles: []auth.Role{auth.RoleAdmin},
			allow: []Permission{ReadFindings, TriageFindings, MutateSettings, ManageUsers, ManageIntegrations, ManageNotifications, MutateScans, TestNotifications},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, permission := range tt.allow {
				if !Allowed(tt.roles, permission) {
					t.Fatalf("expected %v to allow %s", tt.roles, permission)
				}
			}
			for _, permission := range tt.deny {
				if Allowed(tt.roles, permission) {
					t.Fatalf("expected %v to deny %s", tt.roles, permission)
				}
			}
		})
	}
}

func TestCapabilitiesDeterministic(t *testing.T) {
	caps := Capabilities([]auth.Role{auth.RoleAdmin})
	if len(caps) != len(orderedPermissions) {
		t.Fatalf("expected all admin capabilities, got %#v", caps)
	}
	for i, cap := range caps {
		if cap != orderedPermissions[i] {
			t.Fatalf("capability order drift at %d: %s", i, cap)
		}
	}
}

func TestUnknownRoleDenied(t *testing.T) {
	if Allowed([]auth.Role{"owner"}, ManageUsers) {
		t.Fatal("unknown role should be denied")
	}
}
