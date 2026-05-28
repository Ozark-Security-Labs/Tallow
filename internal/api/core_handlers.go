package api

import "net/http"

type listResponse[T any] struct {
	Items []T `json:"items"`
}

type packageDTO struct {
	ID        string `json:"id"`
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type versionDTO struct {
	ID        string `json:"id"`
	PackageID string `json:"package_id"`
	Version   string `json:"version"`
}

type artifactDTO struct {
	ID                 string `json:"id"`
	VerificationStatus string `json:"verification_status"`
}

type analyzerRunDTO struct {
	ID         string `json:"id"`
	AnalyzerID string `json:"analyzer_id"`
	Status     string `json:"status"`
}

func (s *Server) listPackages(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, listResponse[packageDTO]{Items: []packageDTO{}})
}
func (s *Server) getPackage(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, packageDTO{ID: "placeholder", Ecosystem: "unknown", Name: "placeholder"})
}
func (s *Server) listPackageVersions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, listResponse[versionDTO]{Items: []versionDTO{}})
}
func (s *Server) getVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, versionDTO{ID: "placeholder", Version: "unknown"})
}
func (s *Server) getArtifact(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, artifactDTO{ID: "placeholder", VerificationStatus: "unknown"})
}
func (s *Server) listObservations(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, listResponse[map[string]string]{Items: []map[string]string{}})
}
func (s *Server) listAnalyzerRuns(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, listResponse[analyzerRunDTO]{Items: []analyzerRunDTO{}})
}
func (s *Server) getAnalyzerRun(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, analyzerRunDTO{ID: "placeholder", AnalyzerID: "unknown", Status: "unknown"})
}
func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"auth": map[string]bool{"local_enabled": s.Config.Auth.Local.Enabled}, "notifications": map[string]bool{"email_enabled": s.Config.Notifications.Email.Enabled, "teams_enabled": s.Config.Notifications.Teams.Enabled}})
}
func (s *Server) updateSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}
