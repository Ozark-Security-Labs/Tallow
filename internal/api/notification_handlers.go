package api

import (
	"net/http"
	"time"

	"github.com/Ozark-Security-Labs/Tallow/internal/notifications"
	"github.com/go-chi/chi/v5"
)

type pageInfo struct {
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
	Total  int `json:"total"`
}

type notificationRouteDTO struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Channel          string `json:"channel"`
	Enabled          bool   `json:"enabled"`
	SecretConfigured bool   `json:"secret_configured"`
}

type notificationRoutesResponse struct {
	Items []notificationRouteDTO `json:"items"`
	Page  pageInfo               `json:"page"`
}

type notificationDeliveriesResponse struct {
	Items []notifications.Delivery `json:"items"`
	Page  pageInfo                 `json:"page"`
}

type alertDTO struct {
	ID          string              `json:"id"`
	FindingID   string              `json:"finding_id,omitempty"`
	Status      string              `json:"status"`
	Severity    string              `json:"severity"`
	Title       string              `json:"title"`
	Summary     string              `json:"summary,omitempty"`
	PackageName string              `json:"package_name,omitempty"`
	Version     string              `json:"version,omitempty"`
	Evidence    []map[string]string `json:"evidence_refs,omitempty"`
}

type alertsResponse struct {
	Items []alertDTO `json:"items"`
	Page  pageInfo   `json:"page"`
}

func (s *Server) listAlerts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, alertsResponse{Items: []alertDTO{}, Page: pageInfo{Limit: 50, Total: 0}})
}

func (s *Server) getAlert(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, alertDTO{ID: chi.URLParam(r, "alert_id"), Status: "open", Severity: "info", Title: "Alert details unavailable"})
}

func (s *Server) updateAlert(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, alertDTO{ID: chi.URLParam(r, "alert_id"), Status: "acknowledged", Severity: "info", Title: "Alert updated"})
}

func (s *Server) listNotificationRoutes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, notificationRoutesResponse{Items: []notificationRouteDTO{}, Page: pageInfo{Limit: 50, Total: 0}})
}

func (s *Server) createNotificationRoute(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusCreated, notificationRouteDTO{ID: "route_preview", Name: "Preview route", Channel: "email", Enabled: true, SecretConfigured: false})
}

func (s *Server) updateNotificationRoute(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, notificationRouteDTO{ID: chi.URLParam(r, "route_id"), Name: "Preview route", Channel: "email", Enabled: true, SecretConfigured: false})
}

func (s *Server) testNotificationRoute(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusAccepted, notifications.Delivery{ID: "delivery_preview", Status: notifications.StatusPending, CreatedAt: time.Now().UTC()})
}

func (s *Server) listNotificationDeliveries(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, notificationDeliveriesResponse{Items: []notifications.Delivery{}, Page: pageInfo{Limit: 50, Total: 0}})
}

func (s *Server) previewNotificationTemplate(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "preview_rendered"})
}
