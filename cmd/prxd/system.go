package main

import (
	"os/exec"
	"os/user"
)

// Indirection points for the few places the installer touches the system,
// kept in one spot so they are easy to find and to stub out in tests.
var (
	osUserLookup = user.Lookup
	execCommand  = exec.Command
)
