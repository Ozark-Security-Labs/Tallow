package scheduler

type PackagePriority string

const (
	PriorityHot  PackagePriority = "hot"
	PriorityWarm PackagePriority = "warm"
	PriorityCold PackagePriority = "cold"
)

type PackageSignals struct {
	DirectDependency     bool
	ProductionDependency bool
	HighRisk             bool
}

func PriorityFor(s PackageSignals) PackagePriority {
	if s.DirectDependency || s.ProductionDependency || s.HighRisk {
		return PriorityHot
	}
	return PriorityWarm
}
