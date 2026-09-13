package shared

import (
	"net/http"
)

// SendJSON sends a JSON response with proper error handling
func SendJSON(w http.ResponseWriter, status int, obj any) error {
	return JSON(w).ContentType("application/json").Status(status).Send(obj)
}

// SendTokenJSON prevents token-bearing responses from being stored by HTTP caches.
func SendTokenJSON(w http.ResponseWriter, status int, obj any) error {
	SetTokenResponseHeaders(w)
	return SendJSON(w, status, obj)
}

func SetTokenResponseHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
}
