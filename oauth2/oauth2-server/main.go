package main

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"pingdoms.co/m/handlers"
)


func main() {
	if err := run(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

const port = "9123"

func run(w io.Writer) error {
	fmt.Fprintf(w, "Starting server on port %s\n", port)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", handlers.RootHandler) 

	return http.ListenAndServe(
		fmt.Sprintf(":%s", port),
		mux,
	)
}

