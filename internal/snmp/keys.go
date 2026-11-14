package snmp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"
)

// AuthProtocol is a USM authentication protocol.
type AuthProtocol uint8

// Authentication protocols: HMAC-MD5-96 and HMAC-SHA-96 (RFC 3414), and
// HMAC-SHA-2 (RFC 7860: usmHMAC128SHA224, 192SHA256, 256SHA384, 384SHA512).
const (
	AuthNone AuthProtocol = iota
	AuthMD5
	AuthSHA1
	AuthSHA224
	AuthSHA256
	AuthSHA384
	AuthSHA512
)

var authNames = [...]string{"none", "md5", "sha", "sha-224", "sha-256", "sha-384", "sha-512"}

func (a AuthProtocol) String() string {
	if int(a) < len(authNames) {
		return authNames[a]
	}
	return fmt.Sprintf("auth(%d)", a)
}

// ParseAuthProtocol parses none, md5, sha (or sha1, sha-1), sha-224, sha-256,
// sha-384 or sha-512 (any case; the hyphen is optional).
func ParseAuthProtocol(s string) (AuthProtocol, error) {
	k := strings.ReplaceAll(strings.ToLower(s), "-", "")
	switch k {
	case "", "none":
		return AuthNone, nil
	case "md5":
		return AuthMD5, nil
	case "sha", "sha1":
		return AuthSHA1, nil
	case "sha224":
		return AuthSHA224, nil
	case "sha256":
		return AuthSHA256, nil
	case "sha384":
		return AuthSHA384, nil
	case "sha512":
		return AuthSHA512, nil
	}
	return 0, fmt.Errorf("snmp: unknown authentication protocol %q (md5, sha, sha-224, sha-256, sha-384 or sha-512)", s)
}

// Weak reports whether the protocol is one Settings labels weak (MD5, SHA-1).
func (a AuthProtocol) Weak() bool { return a == AuthMD5 || a == AuthSHA1 }

func (a AuthProtocol) newHash() func() hash.Hash {
	switch a {
	case AuthMD5:
		return md5.New
	case AuthSHA1:
		return sha1.New
	case AuthSHA224:
		return sha256.New224
	case AuthSHA256:
		return sha256.New
	case AuthSHA384:
		return sha512.New384
	case AuthSHA512:
		return sha512.New
	}
	return nil
}

// MACLen is the length of msgAuthenticationParameters: 12 for MD5 and SHA-1,
// and 16, 24, 32 and 48 for SHA-224, -256, -384 and -512 (RFC 7860 §4.1).
func (a AuthProtocol) MACLen() int {
	switch a {
	case AuthMD5, AuthSHA1:
		return 12
	case AuthSHA224:
		return 16
	case AuthSHA256:
		return 24
	case AuthSHA384:
		return 32
	case AuthSHA512:
		return 48
	}
	return 0
}

// PrivProtocol is a USM privacy protocol.
type PrivProtocol uint8

// Privacy protocols: DES-CBC (RFC 3414), AES-128-CFB (RFC 3826), and
// AES-192-CFB and AES-256-CFB (the same construction with longer keys; see
// KeyExt for how their keys are made).
const (
	PrivNone PrivProtocol = iota
	PrivDES
	PrivAES128
	PrivAES192
	PrivAES256
)

var privNames = [...]string{"none", "des", "aes-128", "aes-192", "aes-256"}

func (p PrivProtocol) String() string {
	if int(p) < len(privNames) {
		return privNames[p]
	}
	return fmt.Sprintf("priv(%d)", p)
}

// ParsePrivProtocol parses none, des, aes (aes-128), aes-192 or aes-256 (any
// case; the hyphen is optional).
func ParsePrivProtocol(s string) (PrivProtocol, error) {
	k := strings.ReplaceAll(strings.ToLower(s), "-", "")
	switch k {
	case "", "none":
		return PrivNone, nil
	case "des":
		return PrivDES, nil
	case "aes", "aes128":
		return PrivAES128, nil
	case "aes192":
		return PrivAES192, nil
	case "aes256":
		return PrivAES256, nil
	}
	return 0, fmt.Errorf("snmp: unknown privacy protocol %q (des, aes-128, aes-192 or aes-256)", s)
}

// Weak reports whether the protocol is one Settings labels weak (DES).
func (p PrivProtocol) Weak() bool { return p == PrivDES }

// KeyLen is the localized privacy key length the protocol uses: 16 for DES (8
// key octets and 8 pre-IV octets) and AES-128, 24 for AES-192, 32 for AES-256.
func (p PrivProtocol) KeyLen() int {
	switch p {
	case PrivDES, PrivAES128:
		return 16
	case PrivAES192:
		return 24
	case PrivAES256:
		return 32
	}
	return 0
}

// KeyExt is how an AES-192/256 key is extended when the localized key is shorter
// than the cipher needs (MD5 and SHA-1 give 16 and 20 octets). Two incompatible
// methods are in use; SHA-256 and longer need no extension, so both agree there.
type KeyExt uint8

const (
	// KeyExtDraft (the default) is the AES-USM draft's (draft-blumenthal-aes-usm-04
	// §3.1.2.1): Kul' = Kul || H(Kul), repeated as needed.
	KeyExtDraft KeyExt = iota
	// KeyExtAlt is the other method some devices implement (from the 3DES-EDE USM
	// draft, draft-reeder-snmpv3-usm-3desede-00 §2.1): the next block is the key
	// localized again from Kul used as a passphrase, Kul' = Kul ||
	// localize(passwordToKey(Kul)). It costs a 1 MiB hash per engine.
	KeyExtAlt
)

func (k KeyExt) String() string {
	if k == KeyExtAlt {
		return "alt"
	}
	return "draft"
}

// ParseKeyExt parses draft (or "") or alt.
func ParseKeyExt(s string) (KeyExt, error) {
	switch strings.ToLower(s) {
	case "", "draft":
		return KeyExtDraft, nil
	case "alt":
		return KeyExtAlt, nil
	}
	return 0, fmt.Errorf("snmp: unknown key extension %q (draft or alt)", s)
}

var errEmptyPass = errors.New("snmp: empty passphrase")

// PasswordToKey is RFC 3414 §A.2's password-to-key (and RFC 7860's for SHA-2):
// the hash of 1,048,576 octets of the passphrase repeated.
func PasswordToKey(a AuthProtocol, pass []byte) ([]byte, error) {
	nh := a.newHash()
	if nh == nil {
		return nil, fmt.Errorf("snmp: no key for authentication protocol %s", a)
	}
	if len(pass) == 0 {
		return nil, errEmptyPass
	}
	h := nh()
	var buf [64]byte
	j := 0
	for n := 0; n < 1<<20; n += len(buf) {
		for i := range buf {
			buf[i] = pass[j]
			if j++; j == len(pass) {
				j = 0
			}
		}
		h.Write(buf[:])
	}
	return h.Sum(nil), nil
}

// LocalizeKey is RFC 3414 §A.2's key localization: H(Ku || engineID || Ku).
func LocalizeKey(a AuthProtocol, ku, engineID []byte) []byte {
	h := a.newHash()()
	h.Write(ku)
	h.Write(engineID)
	h.Write(ku)
	return h.Sum(nil)
}

// extendPrivKey lengthens a localized privacy key kul to n octets with the
// method ext (KeyExt), or truncates it to n.
func extendPrivKey(a AuthProtocol, ext KeyExt, kul, engineID []byte, n int) ([]byte, error) {
	k := append([]byte(nil), kul...)
	for len(k) < n {
		switch ext {
		case KeyExtAlt:
			ku, err := PasswordToKey(a, k)
			if err != nil {
				return nil, err
			}
			k = append(k, LocalizeKey(a, ku, engineID)...)
		default:
			h := a.newHash()()
			h.Write(k)
			k = h.Sum(k)
		}
	}
	return k[:n], nil
}

// Keys are a user's keys localized to one engine ID.
type Keys struct {
	Auth []byte // the localized authentication key (the HMAC key)
	Priv []byte // the localized privacy key, extended or cut to PrivProtocol.KeyLen
}

// LocalizeKeys returns the keys for the passphrases localized to engineID.
// privPass is ignored when priv is PrivNone.
func LocalizeKeys(a AuthProtocol, p PrivProtocol, ext KeyExt, authPass, privPass, engineID []byte) (Keys, error) {
	var k Keys
	if a == AuthNone {
		return k, nil
	}
	ku, err := PasswordToKey(a, authPass)
	if err != nil {
		return k, err
	}
	k.Auth = LocalizeKey(a, ku, engineID)
	if p != PrivNone {
		pku, err := PasswordToKey(a, privPass)
		if err != nil {
			return k, err
		}
		if k.Priv, err = extendPrivKey(a, ext, LocalizeKey(a, pku, engineID), engineID, p.KeyLen()); err != nil {
			return k, err
		}
	}
	return k, nil
}

// mac computes the truncated HMAC over whole with the authentication parameters
// (at authOff, MACLen octets) taken as zeros. whole isn't changed.
func mac(a AuthProtocol, key, whole []byte, authOff int) []byte {
	h := hmac.New(a.newHash(), key)
	n := a.MACLen()
	h.Write(whole[:authOff])
	var zero [48]byte
	h.Write(zero[:n])
	h.Write(whole[authOff+n:])
	return h.Sum(nil)[:n]
}

func checkMAC(a AuthProtocol, key, whole []byte, authOff int, got []byte) bool {
	return subtle.ConstantTimeCompare(mac(a, key, whole, authOff), got) == 1
}

// decrypt decrypts a scoped PDU. boots and engTime are the message's
// msgAuthoritativeEngineBoots and Time (AES's IV uses them).
func decrypt(p PrivProtocol, key, privParams, data []byte, boots, engTime int64) ([]byte, error) {
	if len(privParams) != 8 {
		return nil, fmt.Errorf("privacy parameters are %d bytes, want 8", len(privParams))
	}
	switch p {
	case PrivDES:
		if len(data) == 0 || len(data)%des.BlockSize != 0 {
			return nil, fmt.Errorf("DES data is %d bytes, not a non-zero multiple of 8", len(data))
		}
		c, err := des.NewCipher(key[:8])
		if err != nil {
			return nil, err
		}
		iv := make([]byte, 8)
		for i := range iv {
			iv[i] = key[8+i] ^ privParams[i]
		}
		out := make([]byte, len(data))
		cipher.NewCBCDecrypter(c, iv).CryptBlocks(out, data)
		return out, nil
	case PrivAES128, PrivAES192, PrivAES256:
		c, err := aes.NewCipher(key[:p.KeyLen()])
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(data))
		// CFB is what RFC 3826 specifies (crypto/cipher marks it deprecated for new designs).
		cipher.NewCFBDecrypter(c, aesIV(boots, engTime, privParams)).XORKeyStream(out, data)
		return out, nil
	}
	return nil, fmt.Errorf("no privacy protocol")
}

// encrypt encrypts a scoped PDU and returns it with the privacy parameters.
// salt is a counter the caller increments for every message (DES uses its low
// 32 bits after the boots, AES all 64).
func encrypt(p PrivProtocol, key, plain []byte, boots, engTime int64, salt uint64) (data, privParams []byte, err error) {
	privParams = make([]byte, 8)
	switch p {
	case PrivDES:
		binary.BigEndian.PutUint32(privParams, uint32(boots))
		binary.BigEndian.PutUint32(privParams[4:], uint32(salt))
		c, err := des.NewCipher(key[:8])
		if err != nil {
			return nil, nil, err
		}
		iv := make([]byte, 8)
		for i := range iv {
			iv[i] = key[8+i] ^ privParams[i]
		}
		n := (len(plain) + 7) / 8 * 8
		buf := make([]byte, n)
		copy(buf, plain)
		cipher.NewCBCEncrypter(c, iv).CryptBlocks(buf, buf)
		return buf, privParams, nil
	case PrivAES128, PrivAES192, PrivAES256:
		binary.BigEndian.PutUint64(privParams, salt)
		c, err := aes.NewCipher(key[:p.KeyLen()])
		if err != nil {
			return nil, nil, err
		}
		out := make([]byte, len(plain))
		cipher.NewCFBEncrypter(c, aesIV(boots, engTime, privParams)).XORKeyStream(out, plain)
		return out, privParams, nil
	}
	return nil, nil, fmt.Errorf("snmp: no privacy protocol")
}

// aesIV is RFC 3826 §3.1.2.1's IV: boots, time (32 bits each) and the 64-bit salt.
func aesIV(boots, engTime int64, salt []byte) []byte {
	iv := make([]byte, 16)
	binary.BigEndian.PutUint32(iv, uint32(boots))
	binary.BigEndian.PutUint32(iv[4:], uint32(engTime))
	copy(iv[8:], salt)
	return iv
}
