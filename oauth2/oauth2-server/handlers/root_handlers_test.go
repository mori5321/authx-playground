package handlers

import (
	"testing"
	"encoding/json"
	"net/http"
	"net/http/httptest"
)

func TestRootHandlers(t *testing.T) {
	t.Run("GET / returns HTTP 200 { status: OK }", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/", nil)
		if err != nil {
			t.Fatal(err)
		}
		
		got := httptest.NewRecorder()
		RootHandler(got, req)

		httpOK := 200
		if got.Code != httpOK{
			t.Errorf("Expected status code %d, got %d",  httpOK, got.Code)
		}

		applicationJSON := "application/json"
		if got := got.Header().Get("Content-Type"); got != applicationJSON {
			t.Errorf("Expected Content-Type '%s', got '%s'", applicationJSON, got)
		}

		var response rootResponse
		if err := json.NewDecoder(got.Body).Decode(&response); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if response.Status != statusOK {
			t.Errorf("Expected status 'OK', got '%s'", response.Status)
		}
	})
}
