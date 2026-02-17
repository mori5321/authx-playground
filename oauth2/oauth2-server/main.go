package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"context"

	"pingdoms.co/oauth2-server/api"
	"pingdoms.co/oauth2-server/handlers"
)

func main() {
	if err := run(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

const port = "9123"

type StrictServer struct {}

var _ api.StrictServerInterface = (*StrictServer)(nil)

func run(w io.Writer) error {	
	handlers := Handlers()

	fmt.Fprintf(w, "Starting server on port %s ...\n", port)
	return http.ListenAndServe(
		fmt.Sprintf(":%s", port),
		handlers,
	)
}

func Handlers() http.Handler {
	mux := http.NewServeMux()
	serverImpl := &StrictServer{}
	server := api.NewStrictHandler(
		serverImpl,
		[]api.StrictMiddlewareFunc{},
	)
	handlers := api.HandlerFromMux(server, mux)

	return handlers
}

func (s *StrictServer) Get(ctx context.Context, request api.GetRequestObject) (api.GetResponseObject, error) {

	return handlers.RootHandler(ctx, request)
}
