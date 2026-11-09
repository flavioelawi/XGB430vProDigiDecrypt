package main

import (
	"os"

	"github.com/sta-c0000/xgb430v-pro-digi-decrypt/pkg/digicredentials"
)

func main() {
	os.Exit(digicredentials.Run())
}
