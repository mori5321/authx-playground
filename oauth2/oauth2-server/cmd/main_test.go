package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	
	api "pingdoms.co/oauth2-server/api"
)

func TestHandlers(t *testing.T) {
	handlers := Handlers()

	t.Run("GET / returns HTTP 200 { status: OK }", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/", nil)
		if err != nil {
			t.Fatal(err)
		}

		got := httptest.NewRecorder()
		handlers.ServeHTTP(got, req)

		httpOK := 200
		if got.Code != httpOK {
			t.Errorf("Expected status code %d, got %d", httpOK, got.Code)
		}

		applicationJSON := "application/json"
		if got := got.Header().Get("Content-Type"); got != applicationJSON {
			t.Errorf("Expected Content-Type '%s', got '%s'", applicationJSON, got)
		}

		var response api.Get200JSONResponse
		if err := json.NewDecoder(got.Body).Decode(&response); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if response.Status == nil || *response.Status != api.Ok {
			t.Errorf("Expected status 'OK', got '%v'", response.Status)
		}
	})
}
