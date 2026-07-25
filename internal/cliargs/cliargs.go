// Package cliargs parses command-line flags that may appear anywhere in the
// argument list.
//
// Go's flag package stops at the first non-flag argument, so
// `prxd user add ali -c /etc/prx/server.json` parses no flags at all and
// silently uses the default config. Writing the name before the flags is at
// least as natural as writing it after, and neither ordering should quietly
// do the wrong thing.
package cliargs

import (
	"flag"
	"strings"
)

// Parse parses the flags defined on fs from anywhere in args and returns the
// positional arguments in the order they appeared.
//
// Everything after a bare "--" is positional, as usual.
func Parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var flagArgs, positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]

		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}

		// "-" on its own is a conventional filename, not a flag.
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positional = append(positional, arg)
			continue
		}

		flagArgs = append(flagArgs, arg)

		// "-name=value" carries its value; "-name value" takes the next
		// argument unless the flag is boolean.
		name := strings.TrimLeft(arg, "-")
		if strings.ContainsRune(name, '=') {
			continue
		}
		if !isBool(fs, name) && i+1 < len(args) {
			i++
			flagArgs = append(flagArgs, args[i])
		}
	}

	if err := fs.Parse(flagArgs); err != nil {
		return nil, err
	}
	return positional, nil
}

// isBool reports whether a flag is a boolean, which is the one case where a
// following argument is not its value.
func isBool(fs *flag.FlagSet, name string) bool {
	f := fs.Lookup(name)
	if f == nil {
		return false
	}
	boolFlag, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && boolFlag.IsBoolFlag()
}
