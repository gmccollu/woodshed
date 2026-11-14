package trap

import (
	"errors"
	"strings"
	"testing"

	"github.com/gmccollu/woodshed/internal/api"
)

// key_ext "draft" is the default and what GET returns for every user, so it must be accepted with any priv (the
// documented POST example is sha-256/aes-128 with "key_ext": "draft", and a GET → PUT round trip sends it back).
// Only "alt" is limited to AES-192/256. Found in the 1.2.0-rc1 lab run.
func TestKeyExtDraftWithAnyPriv(t *testing.T) {
	c, err := openCreds(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	self := []byte{0x80, 0, 0, 0, 5, 1, 2, 3, 4}
	for _, in := range []api.SNMPUserInput{
		{Name: "doc", Auth: "sha-256", AuthPass: "auth-pass-for-test", Priv: "aes-128", PrivPass: "priv-pass-for-test", KeyExt: "draft"},
		{Name: "noauth", Auth: "none", Priv: "none", KeyExt: "draft"},
		{Name: "authonly", Auth: "sha", AuthPass: "auth-pass-for-test", Priv: "none", KeyExt: "draft"},
		{Name: "des", Auth: "md5", AuthPass: "auth-pass-for-test", Priv: "des", PrivPass: "priv-pass-for-test", KeyExt: "draft"},
		{Name: "aes256alt", Auth: "sha-512", AuthPass: "auth-pass-for-test", Priv: "aes-256", PrivPass: "priv-pass-for-test", KeyExt: "alt"},
	} {
		u, err := c.put(in, "", self)
		if err != nil {
			t.Fatalf("%s: %v", in.Name, err)
		}
		// GET → PUT round trip: send back what GET shows, without passphrases.
		back := api.SNMPUserInput{Name: u.Name, Auth: u.Auth, Priv: u.Priv, KeyExt: u.KeyExt, EngineIDs: u.EngineIDs}
		if _, err := c.put(back, u.Name, self); err != nil {
			t.Errorf("%s: round trip with key_ext %q: %v", in.Name, u.KeyExt, err)
		}
	}
	_, err = c.put(api.SNMPUserInput{Name: "bad", Auth: "sha", AuthPass: "auth-pass-for-test", Priv: "aes-128",
		PrivPass: "priv-pass-for-test", KeyExt: "alt"}, "", self)
	var ve *api.ValidationError
	if !errors.As(err, &ve) || !strings.Contains(ve.Fields["key_ext"], "alt") {
		t.Errorf(`"alt" with aes-128 should be a key_ext field error naming alt: %v`, err)
	}
}
