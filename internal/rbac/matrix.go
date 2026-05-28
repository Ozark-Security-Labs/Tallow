package rbac

var orderedPermissions = []Permission{
	ReadDashboard,
	ReadPackages,
	ReadFindings,
	TriageFindings,
	ReadAlerts,
	TriageAlerts,
	ReadImpact,
	ReadAnalyzerRuns,
	ReadSettings,
	MutateSettings,
	ManageUsers,
	ManageIntegrations,
	ManageNotifications,
	MutateScans,
	TestNotifications,
}

var viewerPermissions = map[Permission]bool{
	ReadDashboard:    true,
	ReadPackages:     true,
	ReadFindings:     true,
	ReadAlerts:       true,
	ReadImpact:       true,
	ReadAnalyzerRuns: true,
	ReadSettings:     true,
}

var analystPermissions = merge(viewerPermissions, map[Permission]bool{
	TriageFindings: true,
	TriageAlerts:   true,
})

var adminPermissions = merge(analystPermissions, map[Permission]bool{
	MutateSettings:      true,
	ManageUsers:         true,
	ManageIntegrations:  true,
	ManageNotifications: true,
	MutateScans:         true,
	TestNotifications:   true,
})

func merge(base, extra map[Permission]bool) map[Permission]bool {
	out := map[Permission]bool{}
	for permission, allowed := range base {
		out[permission] = allowed
	}
	for permission, allowed := range extra {
		out[permission] = allowed
	}
	return out
}
