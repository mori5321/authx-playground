package handlers

import (
	"encoding/json"
	"net/http"
)

type rootResponse struct {
	Status serverStatus `json:"status"`
}

type serverStatus string
const (
  statusOK serverStatus = "ok"
	statusNG serverStatus = "ng"
)

func newRootResponse(status serverStatus) rootResponse {
	return rootResponse{
		Status: status,
	}
}

func RootHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := newRootResponse(statusOK) 
	
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(response)
}

