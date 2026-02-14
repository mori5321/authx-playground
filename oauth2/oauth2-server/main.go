package main

import "fmt"
import "io"
import "os"

func main() {
	if err := run(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(w io.Writer) error {
	_, err := fmt.Fprintln(w, "Hello, World")
	if err != nil {
		return err
	}
	return nil
}
