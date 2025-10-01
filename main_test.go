package main

import (
	"os"
	"strconv"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"tofu-age-encryption": main,
	})
}

func TestScript(t *testing.T) {
	updateScripts, _ := strconv.ParseBool(os.Getenv("UPDATE_SCRIPTS"))
	testscript.Run(t, testscript.Params{
		Dir:             "testdata",
		ContinueOnError: true,
		UpdateScripts:   updateScripts,
	})
}
