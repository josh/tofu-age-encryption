package main

import (
	"encoding/hex"
	"log"
	"os"
	"strconv"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"tofu-age-encryption": main,
		"age-plugin-test":     testPluginMain,
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

func TestAgeEncryptPayloadDoesNotEchoInvalidRecipient(t *testing.T) {
	const sensitive = "AGE-SECRET-KEY-1SENSITIVE-MATERIAL"
	cfg := Config{ageRecipients: map[string]bool{sensitive: true}}

	_, err := ageEncryptPayload(&cfg, nil)
	if err == nil {
		t.Fatal("expected invalid recipient error")
	}
	if strings.Contains(err.Error(), sensitive) {
		t.Fatalf("error contains recipient value: %v", err)
	}
}

func testPluginMain() {
	p, err := plugin.New("test")
	if err != nil {
		log.Fatal(err)
	}
	p.HandleRecipient(func(data []byte) (age.Recipient, error) {
		return &testRecipient{tag: hex.EncodeToString(data)}, nil
	})
	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		return &testIdentity{tag: hex.EncodeToString(data)}, nil
	})
	os.Exit(p.Main())
}

type testRecipient struct{ tag string }

func (r *testRecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	return []*age.Stanza{{Type: "test", Args: []string{r.tag}, Body: fileKey}}, nil
}

type testIdentity struct{ tag string }

func (i *testIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	for _, s := range stanzas {
		if s.Type == "test" && len(s.Args) == 1 && s.Args[0] == i.tag {
			return s.Body, nil
		}
	}
	return nil, age.ErrIncorrectIdentity
}
