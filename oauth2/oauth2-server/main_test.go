package main

import "testing"
import "bytes"

func TestMain(t *testing.T) {
	t.Run("Main", func(t *testing.T) {
		var buf bytes.Buffer

		if err := run(&buf); err != nil {
			t.Fatalf("run() error = %v", err)
		}

		expected := "Hello, World\n"
		actual := buf.String()

		if actual != expected {
			t.Errorf("expected %q, but got %q", expected, actual)
		}
	})
}
