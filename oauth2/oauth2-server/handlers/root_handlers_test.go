package handlers

import (
	"context"
	"testing"

	"pingdoms.co/oauth2-server/api"
)

func TestRootHandler(t *testing.T) {
	t.Run("RootHandler should return", func(t *testing.T) {
		ctx := context.Background()
		req := api.GetRequestObject{}
		
		res, err:= RootHandler(ctx, req)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}

		response, ok := res.(api.Get200JSONResponse)
		if !ok {
			t.Errorf("Expected response of type Get200JSONResponse, got %T", res)
		}

		expectedStatus := api.Ok
		if response.Status == nil || *response.Status != expectedStatus {
			t.Errorf("Expected status '%s', got '%v'", expectedStatus, response.Status)
		}
	})
}
