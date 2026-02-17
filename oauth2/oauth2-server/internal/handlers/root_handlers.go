package handlers

import (
	"context"
	"pingdoms.co/oauth2-server/api"
)


func RootHandler(ctx context.Context, request api.GetRequestObject) (api.GetResponseObject, error) {
	status := api.Ok

	return api.Get200JSONResponse{
		Status: &status,
	}, nil
}

