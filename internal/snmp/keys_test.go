package snmp

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestKeyLocalization checks password-to-key and localization: the RFC 3414
// Appendix A.3 vectors for MD5 and SHA-1 (password "maplesyrup", engine ID
// 000000000000000000000002), and the same inputs for SHA-2 (RFC 7860 uses the
// same algorithms with the SHA-2 hash and publishes no vectors; these were
// computed independently with Python's hashlib).
func TestKeyLocalization(t *testing.T) {
	engine := mustHex(t, "000000000000000000000002")
	for _, tc := range []struct {
		a       AuthProtocol
		ku, kul string
	}{
		{AuthMD5, "9faf3283884e92834ebc9847d8edd963", "526f5eed9fcce26f8964c2930787d82b"},
		{AuthSHA1, "9fb5cc0381497b3793528939ff788d5d79145211", "6695febc9288e36282235fc7151f128497b38f3f"},
		{AuthSHA224, "282a5867ee9aac639ad59df9572c7d3ac0fbc13a905b6df07dbbf00b", "0bd8827c6e29f8065e08e09237f177e410f69b90e1782be682075674"},
		{AuthSHA256, "ab51014d1e077f6017df2b12bee5f5aa72993177e9bb569c4dff5a4ca0b4afac", "8982e0e549e866db361a6b625d84cccc11162d453ee8ce3a6445c2d6776f0f8b"},
		{AuthSHA384, "e06eccdf2c68a06ed034723c9c26e0db3b669e1e2efed49150b55377a2e98f383c86fb836857444654b287c93f51ff64",
			"3b298f16164a11184279d5432bf169e2d2a48307de02b3d3f7e2b4f36eb6f0455a53689a3937eea07319a633d2ccba78"},
		{AuthSHA512, "7e4396de5aadc77be853819b98c9406265b3a9c37cc3176569847a4e4f6fba63dd3a73d04924d31a63f95a601f9385af6be4ed1b37f87d040f7c6ed6f8d38a91",
			"22a5a36cedfcc085807a128d7bc6c2382167ad6c0dbc5fdff856740f3d84c099ad1ea87a8db096714d9788bd544047c9021e4229ce27e4c0a69250adfcffbb0b"},
	} {
		ku, err := PasswordToKey(tc.a, []byte("maplesyrup"))
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(ku) != tc.ku {
			t.Errorf("%s Ku = %x, want %s", tc.a, ku, tc.ku)
		}
		if kul := LocalizeKey(tc.a, ku, engine); hex.EncodeToString(kul) != tc.kul {
			t.Errorf("%s Kul = %x, want %s", tc.a, kul, tc.kul)
		}
	}
	if _, err := PasswordToKey(AuthMD5, nil); err == nil {
		t.Error("empty passphrase: no error")
	}
	if _, err := PasswordToKey(AuthNone, []byte("x")); err == nil {
		t.Error("no protocol: no error")
	}
}

// TestKeyExtension checks both AES-192/256 key-extension methods for the short
// keys (MD5, SHA-1), with the priv passphrase "maplesyrup" and the RFC 3414
// engine ID. Vectors computed independently with Python's hashlib from the two
// drafts' definitions; the CI interop run (interop_test.go) checks both methods
// against net-snmp where its build offers them.
func TestKeyExtension(t *testing.T) {
	engine := mustHex(t, "000000000000000000000002")
	for _, tc := range []struct {
		a    AuthProtocol
		p    PrivProtocol
		ext  KeyExt
		want string
	}{
		{AuthMD5, PrivAES256, KeyExtDraft, "526f5eed9fcce26f8964c2930787d82bfa24a92467426c2f4b09192be10dfaec"},
		{AuthMD5, PrivAES256, KeyExtAlt, "526f5eed9fcce26f8964c2930787d82b79eff44a90650ee0a3a40abfac5acc12"},
		{AuthMD5, PrivAES192, KeyExtDraft, "526f5eed9fcce26f8964c2930787d82bfa24a92467426c2f"},
		{AuthMD5, PrivAES192, KeyExtAlt, "526f5eed9fcce26f8964c2930787d82b79eff44a90650ee0"},
		{AuthSHA1, PrivAES256, KeyExtDraft, "6695febc9288e36282235fc7151f128497b38f3f505e07eb9af25568fa1f5dbe"},
		{AuthSHA1, PrivAES256, KeyExtAlt, "6695febc9288e36282235fc7151f128497b38f3f9b8b6d78936ba6e7d19dfd9c"},
		{AuthSHA1, PrivAES192, KeyExtDraft, "6695febc9288e36282235fc7151f128497b38f3f505e07eb"},
		{AuthSHA1, PrivAES192, KeyExtAlt, "6695febc9288e36282235fc7151f128497b38f3f9b8b6d78"},
		// No extension needed: both methods truncate the same key.
		{AuthSHA256, PrivAES256, KeyExtDraft, "8982e0e549e866db361a6b625d84cccc11162d453ee8ce3a6445c2d6776f0f8b"},
		{AuthSHA256, PrivAES256, KeyExtAlt, "8982e0e549e866db361a6b625d84cccc11162d453ee8ce3a6445c2d6776f0f8b"},
		{AuthSHA1, PrivAES128, KeyExtAlt, "6695febc9288e36282235fc7151f1284"},
		{AuthSHA1, PrivDES, KeyExtDraft, "6695febc9288e36282235fc7151f1284"},
	} {
		k, err := LocalizeKeys(tc.a, tc.p, tc.ext, []byte("maplesyrup"), []byte("maplesyrup"), engine)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(k.Priv); got != tc.want {
			t.Errorf("%s %s %s: %s, want %s", tc.a, tc.p, tc.ext, got, tc.want)
		}
	}
}

func TestMACLengths(t *testing.T) {
	want := map[AuthProtocol]int{AuthMD5: 12, AuthSHA1: 12, AuthSHA224: 16, AuthSHA256: 24, AuthSHA384: 32, AuthSHA512: 48, AuthNone: 0}
	for a, n := range want {
		if a.MACLen() != n {
			t.Errorf("%s MACLen %d, want %d", a, a.MACLen(), n)
		}
		if a == AuthNone {
			continue
		}
		key := bytes.Repeat([]byte{1}, 16)
		msg := make([]byte, 100)
		if m := mac(a, key, msg, 10); len(m) != n {
			t.Errorf("%s mac is %d bytes", a, len(m))
		}
	}
}

func TestCrypt(t *testing.T) {
	plain := []byte("a scoped PDU of some length, not a multiple of 8")
	for _, p := range []PrivProtocol{PrivDES, PrivAES128, PrivAES192, PrivAES256} {
		key := bytes.Repeat([]byte{0x42}, 32)
		ct, pp, err := encrypt(p, key, plain, 7, 1234, 0x0102030405060708)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(ct, plain[:8]) {
			t.Errorf("%s: plaintext visible", p)
		}
		back, err := decrypt(p, key, pp, ct, 7, 1234)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(back, plain) {
			t.Errorf("%s: round trip %q", p, back)
		}
		if p == PrivDES && (len(ct)%8 != 0 || !bytes.Equal(pp[:4], []byte{0, 0, 0, 7})) {
			t.Errorf("DES: ciphertext %d bytes, salt % x", len(ct), pp)
		}
		if _, err := decrypt(p, key, pp[:7], ct, 7, 1234); err == nil {
			t.Errorf("%s: short privacy parameters accepted", p)
		}
	}
	if _, err := decrypt(PrivDES, bytes.Repeat([]byte{1}, 16), make([]byte, 8), make([]byte, 7), 0, 0); err == nil {
		t.Error("DES: 7 bytes accepted")
	}
}

func TestProtocolNames(t *testing.T) {
	for _, s := range []string{"md5", "SHA", "sha1", "SHA-224", "sha256", "sha-384", "SHA512"} {
		if _, err := ParseAuthProtocol(s); err != nil {
			t.Error(err)
		}
	}
	for _, s := range []string{"DES", "aes", "AES-128", "aes192", "AES-256"} {
		if _, err := ParsePrivProtocol(s); err != nil {
			t.Error(err)
		}
	}
	if _, err := ParseAuthProtocol("sha-3"); err == nil {
		t.Error("sha-3 accepted")
	}
	if _, err := ParsePrivProtocol("3des"); err == nil {
		t.Error("3des accepted")
	}
	if e, err := ParseKeyExt(""); err != nil || e != KeyExtDraft {
		t.Error("the default key extension isn't draft")
	}
	if !AuthMD5.Weak() || !AuthSHA1.Weak() || AuthSHA256.Weak() || !PrivDES.Weak() || PrivAES128.Weak() {
		t.Error("Weak")
	}
}
