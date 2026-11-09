package digicredentials

import (
	"fmt"
	"os"
)

var debugEnabled bool

// debugf intentionally accepts only operational metadata. Do not pass request
// bodies, response bodies, cookies, tokens, credentials, or decrypted data.
func debugf(format string, args ...any) {
	if debugEnabled {
		fmt.Fprintf(os.Stderr, "debug: "+format+"\n", args...)
	}
}
