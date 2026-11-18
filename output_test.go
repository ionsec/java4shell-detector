package main

import "testing"

func TestSanitizeTerminal(t *testing.T) {
	in := "title \x1b[2J\x1b]0;pwn\x07 ok\tx\n\u009b31m"
	got := sanitizeTerminal(in)
	want := "title ?[2J?]0;pwn? ok\tx\n?31m"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestCSVRowFormulaInjection(t *testing.T) {
	got := csvRow("10.0.0.1", `=HYPERLINK("http://x","y")`, "-1+1", "plain")
	want := "10.0.0.1,\"'=HYPERLINK(\"\"http://x\"\",\"\"y\"\")\",'-1+1,plain\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
