package cliargs

import (
	"flag"
	"slices"
	"testing"
)

func newSet() (*flag.FlagSet, *string, *bool) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	config := fs.String("c", "default.json", "config file")
	quiet := fs.Bool("q", false, "quiet")
	return fs, config, quiet
}

func TestFlagsAreFoundAfterPositionals(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"flags first", []string{"-c", "server.json", "-q", "ali"}},
		{"flags last", []string{"ali", "-c", "server.json", "-q"}},
		{"flags around", []string{"-c", "server.json", "ali", "-q"}},
		{"equals form", []string{"ali", "-c=server.json", "-q"}},
		{"double dash flag", []string{"ali", "--c", "server.json", "--q"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs, config, quiet := newSet()
			positional, err := Parse(fs, c.args)
			if err != nil {
				t.Fatal(err)
			}
			if *config != "server.json" {
				t.Errorf("config = %q, want server.json", *config)
			}
			if !*quiet {
				t.Error("quiet flag was not set")
			}
			if !slices.Equal(positional, []string{"ali"}) {
				t.Errorf("positional = %v, want [ali]", positional)
			}
		})
	}
}

func TestSeveralPositionalsKeepOrder(t *testing.T) {
	fs, config, _ := newSet()
	positional, err := Parse(fs, []string{"add", "ali", "-c", "server.json"})
	if err != nil {
		t.Fatal(err)
	}
	if *config != "server.json" {
		t.Errorf("config = %q", *config)
	}
	if !slices.Equal(positional, []string{"add", "ali"}) {
		t.Errorf("positional = %v, want [add ali]", positional)
	}
}

func TestDoubleDashEndsFlagParsing(t *testing.T) {
	fs, config, _ := newSet()
	positional, err := Parse(fs, []string{"-c", "server.json", "--", "-q", "literal"})
	if err != nil {
		t.Fatal(err)
	}
	if *config != "server.json" {
		t.Errorf("config = %q", *config)
	}
	if !slices.Equal(positional, []string{"-q", "literal"}) {
		t.Errorf("positional = %v, want [-q literal]", positional)
	}
}

func TestBoolFlagDoesNotSwallowTheNextArgument(t *testing.T) {
	fs, _, quiet := newSet()
	positional, err := Parse(fs, []string{"-q", "ali"})
	if err != nil {
		t.Fatal(err)
	}
	if !*quiet {
		t.Error("quiet flag was not set")
	}
	if !slices.Equal(positional, []string{"ali"}) {
		t.Errorf("positional = %v, want [ali]: a bool flag consumed its neighbour", positional)
	}
}
