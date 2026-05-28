package api

import (
	"net/http"
	"time"

	"github.com/Ozark-Security-Labs/Tallow/internal/notifications"
)

type notificationRoutesResponse struct {
	Items []notifications.Route `json:"items"`
}

type notificationDeliveriesResponse struct {
	Items []notifications.Delivery `json:"items"`
}

type alertsResponse struct {
	Items []map[string]string `json:"items"`
}

func (s *Server) listAlerts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, alertsResponse{Items: []map[string]string{}})
}

func (s *Server) getAlert(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"id": "placeholder", "status": "open"})
}

func (s *Server) updateAlert(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) listNotificationRoutes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, notificationRoutesResponse{Items: []notifications.Route{}})
}

func (s *Server) createNotificationRoute(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusCreated, notifications.Route{ID: "route_preview", Enabled: true})
}

func (s *Server) updateNotificationRoute(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, notifications.Route{ID: "route_preview", Enabled: true})
}

func (s *Server) testNotificationRoute(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusAccepted, notifications.Delivery{ID: "delivery_preview", Status: notifications.StatusPending, CreatedAt: time.Now().UTC()})
}

func (s *Server) listNotificationDeliveries(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, notificationDeliveriesResponse{Items: []notifications.Delivery{}})
}

func (s *Server) previewNotificationTemplate(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "preview_rendered"})
}
