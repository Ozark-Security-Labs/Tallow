package rbac

import "github.com/Ozark-Security-Labs/Tallow/internal/auth"

type Permission string

const (
	ReadDashboard       Permission = "dashboard:read"
	ReadPackages        Permission = "packages:read"
	ReadFindings        Permission = "findings:read"
	TriageFindings      Permission = "findings:triage"
	ReadAlerts          Permission = "alerts:read"
	TriageAlerts        Permission = "alerts:triage"
	ReadImpact          Permission = "impact:read"
	ReadAnalyzerRuns    Permission = "analyzer_runs:read"
	ReadSettings        Permission = "settings:read"
	MutateSettings      Permission = "settings:mutate"
	ManageUsers         Permission = "users:manage"
	ManageIntegrations  Permission = "integrations:manage"
	ManageNotifications Permission = "notifications:manage"
	MutateScans         Permission = "scans:mutate"
	TestNotifications   Permission = "notifications:test"
)

func Allowed(roles []auth.Role, permission Permission) bool {
	for _, role := range roles {
		if allowedByRole(role, permission) {
			return true
		}
	}
	return false
}

func Capabilities(roles []auth.Role) []Permission {
	seen := map[Permission]struct{}{}
	out := []Permission{}
	for _, permission := range orderedPermissions {
		if Allowed(roles, permission) {
			if _, ok := seen[permission]; !ok {
				seen[permission] = struct{}{}
				out = append(out, permission)
			}
		}
	}
	return out
}

func allowedByRole(role auth.Role, permission Permission) bool {
	switch role {
	case auth.RoleAdmin:
		return adminPermissions[permission]
	case auth.RoleAnalyst:
		return analystPermissions[permission]
	case auth.RoleViewer:
		return viewerPermissions[permission]
	default:
		return false
	}
}
