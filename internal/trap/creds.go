package trap

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/atomicfile"
	"github.com/gmccollu/woodshed/internal/snmp"
)

// The SNMP credentials store (SPEC §11.2.6): the v3 users and the v1/v2c
// community list. The file holds the users' names and protocols in the clear
// (so Settings can still list them after the secrets become unreadable) and
// every secret in one blob, protect()ed: DPAPI on Windows (snmp-users.dat, user
// scope of the account the server runs as), the file's 0600 mode elsewhere
// (snmp-users.json). It's written atomically. Nothing in it is ever logged,
// put in an event, returned by the API or exported.

// Credentials file names.
const (
	CredFileUnix    = "snmp-users.json"
	CredFileWindows = "snmp-users.dat"
)

// CredFileName is this OS's credentials file.
func CredFileName() string {
	if runtime.GOOS == "windows" {
		return CredFileWindows
	}
	return CredFileUnix
}

// Limits (docs/api.md "SNMP v3 users").
const (
	MaxUsers       = 100
	MaxUserName    = 32
	MinPass        = 8
	MaxPass        = 256
	MaxUserEngines = 32
)

// ErrUserExists and ErrNoUser are the users' CRUD errors.
var (
	ErrUserExists = api.ErrSNMPUserExists
	ErrNoUser     = api.ErrNotFound
)

type credFile struct {
	Version int        `json:"version"`
	Users   []credUser `json:"users"`
	Secrets string     `json:"secrets"` // base64 of protect(credSecrets as JSON)
}

// credUser is a user's public part.
type credUser struct {
	Name      string   `json:"name"`
	Auth      string   `json:"auth"`
	Priv      string   `json:"priv"`
	KeyExt    string   `json:"key_ext"`
	EngineIDs []string `json:"engine_ids"`
	Stored    string   `json:"stored"` // "passphrase" or "localized"
}

type credSecrets struct {
	Users       map[string]userSecret `json:"users"`
	Communities []string              `json:"communities"`
}

type userSecret struct {
	AuthPass []byte      `json:"auth_pass,omitempty"`
	PrivPass []byte      `json:"priv_pass,omitempty"`
	Keys     []engineKey `json:"keys,omitempty"`
}

type engineKey struct {
	EngineID []byte `json:"engine_id"`
	Auth     []byte `json:"auth,omitempty"`
	Priv     []byte `json:"priv,omitempty"`
}

// creds is the store in memory.
type creds struct {
	mu       sync.Mutex
	path     string
	users    []credUser
	secrets  credSecrets
	readable bool  // false: the secrets blob didn't decrypt here
	loadErr  error // why not
}

func openCreds(dataDir string) (*creds, error) {
	c := &creds{path: filepath.Join(dataDir, CredFileName()), readable: true, secrets: credSecrets{Users: map[string]userSecret{}}}
	b, err := atomicfile.ReadFile(c.path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, fmt.Errorf("trap: read %s: %w", filepath.Base(c.path), err)
	}
	var f credFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("trap: %s is malformed", filepath.Base(c.path))
	}
	c.users = f.Users
	if f.Secrets != "" {
		blob, err := base64.StdEncoding.DecodeString(f.Secrets)
		if err == nil {
			var plain []byte
			if plain, err = unprotect(blob); err == nil {
				err = json.Unmarshal(plain, &c.secrets)
				clear(plain)
			}
		}
		if err != nil {
			// Moved to another machine or account (DPAPI): keep the names and
			// protocols; the users need their passphrases again.
			c.readable, c.loadErr = false, err
			c.secrets = credSecrets{Users: map[string]userSecret{}}
		}
	}
	if c.secrets.Users == nil {
		c.secrets.Users = map[string]userSecret{}
	}
	return c, nil
}

// saveLocked writes the file atomically, mode 0600.
func (c *creds) saveLocked() error {
	plain, err := json.Marshal(c.secrets)
	if err != nil {
		return err
	}
	blob, err := protect(plain)
	clear(plain)
	if err != nil {
		return fmt.Errorf("trap: protect the SNMP credentials: %w", err)
	}
	users := c.users
	if users == nil {
		users = []credUser{}
	}
	b, err := json.MarshalIndent(credFile{Version: 1, Users: users, Secrets: base64.StdEncoding.EncodeToString(blob)}, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicfile.WriteFile(c.path, append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("trap: write %s: %w", filepath.Base(c.path), err)
	}
	c.readable, c.loadErr = true, nil
	return nil
}

// snmpUsers are the USM users: from the secrets that decrypted. A user whose
// secrets didn't is left out (it can't authenticate anything).
func (c *creds) snmpUsers(self []byte) []snmp.User {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []snmp.User
	for _, cu := range c.users {
		sec, ok := c.secrets.Users[cu.Name]
		if !ok {
			continue
		}
		u, err := cu.snmpUser()
		if err != nil {
			continue
		}
		u.AuthPass, u.PrivPass = sec.AuthPass, sec.PrivPass
		for _, k := range sec.Keys {
			u.EngineKeys = append(u.EngineKeys, snmp.EngineKeys{EngineID: k.EngineID, Keys: snmp.Keys{Auth: k.Auth, Priv: k.Priv}})
		}
		out = append(out, u)
	}
	return out
}

func (cu credUser) snmpUser() (snmp.User, error) {
	a, err := snmp.ParseAuthProtocol(cu.Auth)
	if err != nil {
		return snmp.User{}, err
	}
	p, err := snmp.ParsePrivProtocol(cu.Priv)
	if err != nil {
		return snmp.User{}, err
	}
	k, err := snmp.ParseKeyExt(cu.KeyExt)
	if err != nil {
		return snmp.User{}, err
	}
	u := snmp.User{Name: cu.Name, Auth: a, Priv: p, KeyExt: k}
	u.Level = u.MaxLevel()
	return u, nil
}

// apiUser is a user as GET /api/snmp/users shows it: no secrets.
func (c *creds) apiUserLocked(cu credUser) api.SNMPUser {
	sec, ok := c.secrets.Users[cu.Name]
	u := api.SNMPUser{Name: cu.Name, Auth: cu.Auth, Priv: cu.Priv, KeyExt: cu.KeyExt, EngineIDs: append([]string{}, cu.EngineIDs...),
		Stored: cu.Stored, Readable: ok}
	if su, err := cu.snmpUser(); err == nil {
		u.Level = su.MaxLevel().String()
		if su.Auth.Weak() {
			u.Weak = append(u.Weak, cu.Auth)
		}
		if su.Priv.Weak() {
			u.Weak = append(u.Weak, cu.Priv)
		}
	}
	if ok {
		u.AuthSet = cu.Auth != "none" && (len(sec.AuthPass) > 0 || len(sec.Keys) > 0)
		u.PrivSet = cu.Priv != "none" && (len(sec.PrivPass) > 0 || len(sec.Keys) > 0)
	}
	return u
}

func (c *creds) list() []api.SNMPUser {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]api.SNMPUser, 0, len(c.users))
	for _, cu := range c.users {
		out = append(out, c.apiUserLocked(cu))
	}
	return out
}

// unreadable counts the users whose secrets didn't decrypt here.
func (c *creds) unreadable() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, cu := range c.users {
		if _, ok := c.secrets.Users[cu.Name]; !ok {
			n++
		}
	}
	return n
}

// canonical protocol names.
func canonAuth(a snmp.AuthProtocol) string { return a.String() }

// put validates in and adds (create) or replaces (update, name = the path's)
// a user. self is Woodshed's own engine ID: users with engine IDs keep keys
// localized to those and to self (informs), never the passphrases.
func (c *creds) put(in api.SNMPUserInput, update string, self []byte) (api.SNMPUser, error) {
	errs := map[string]string{}
	name := in.Name
	if update != "" && name == "" {
		name = update
	}
	switch {
	case name == "":
		errs["name"] = "A name is required."
	case len(name) > MaxUserName:
		errs["name"] = fmt.Sprintf("Must be 1 to %d bytes.", MaxUserName)
	case strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f }):
		errs["name"] = "Must not contain control characters."
	}
	if update != "" && name != update {
		errs["name"] = "A user can't be renamed; delete it and add the new name."
	}
	ap, err := snmp.ParseAuthProtocol(defaultStr(in.Auth, "none"))
	if err != nil {
		errs["auth"] = "Must be none, md5, sha, sha-224, sha-256, sha-384 or sha-512."
	}
	pp, err := snmp.ParsePrivProtocol(defaultStr(in.Priv, "none"))
	if err != nil {
		errs["priv"] = "Must be none, des, aes-128, aes-192 or aes-256."
	}
	if pp != snmp.PrivNone && ap == snmp.AuthNone && errs["auth"] == "" && errs["priv"] == "" {
		errs["priv"] = "Privacy needs authentication: pick an auth protocol too."
	}
	ke, err := snmp.ParseKeyExt(in.KeyExt)
	if err != nil {
		errs["key_ext"] = `Must be "draft" (the default) or "alt".`
	}
	if in.KeyExt != "" && pp != snmp.PrivAES192 && pp != snmp.PrivAES256 && errs["key_ext"] == "" {
		errs["key_ext"] = "Only for aes-192 and aes-256."
	}
	var engines [][]byte
	var engineHex []string
	if len(in.EngineIDs) > MaxUserEngines {
		errs["engine_ids"] = fmt.Sprintf("At most %d engine IDs.", MaxUserEngines)
	}
	for i, s := range in.EngineIDs {
		id, err := snmp.ParseEngineID(strings.TrimSpace(s))
		if err != nil {
			errs[fmt.Sprintf("engine_ids[%d]", i)] = "Must be an engine ID in hex, 5 to 32 bytes."
			continue
		}
		h := hex.EncodeToString(id)
		if !contains(engineHex, h) {
			engines, engineHex = append(engines, id), append(engineHex, h)
		}
	}
	checkPass := func(key, p string) {
		if p != "" && (len(p) < MinPass || len(p) > MaxPass) {
			errs[key] = fmt.Sprintf("Must be %d to %d bytes.", MinPass, MaxPass)
		}
	}
	checkPass("auth_pass", in.AuthPass)
	checkPass("priv_pass", in.PrivPass)

	c.mu.Lock()
	defer c.mu.Unlock()
	idx := -1
	for i, cu := range c.users {
		if cu.Name == name {
			idx = i
		}
	}
	if update == "" && idx >= 0 {
		return api.SNMPUser{}, ErrUserExists
	}
	if update != "" && idx < 0 {
		return api.SNMPUser{}, ErrNoUser
	}
	if update == "" && len(c.users) >= MaxUsers {
		errs["name"] = fmt.Sprintf("There are already %d users; delete one first.", MaxUsers)
	}
	// A missing passphrase keeps the stored one, unless the protocol changed.
	var old credUser
	oldSec, hadSec := userSecret{}, false
	if idx >= 0 {
		old = c.users[idx]
		oldSec, hadSec = c.secrets.Users[name]
	}
	authPass, privPass := []byte(in.AuthPass), []byte(in.PrivPass)
	keepAuth := in.AuthPass == "" && idx >= 0 && hadSec && old.Auth == canonAuth(ap) && len(oldSec.AuthPass) > 0
	keepPriv := in.PrivPass == "" && idx >= 0 && hadSec && old.Priv == pp.String() && len(oldSec.PrivPass) > 0 && old.Auth == canonAuth(ap)
	if keepAuth {
		authPass = oldSec.AuthPass
	}
	if keepPriv {
		privPass = oldSec.PrivPass
	}
	sameKeys := idx >= 0 && hadSec && len(oldSec.Keys) > 0 && in.AuthPass == "" && in.PrivPass == "" && old.Auth == canonAuth(ap) &&
		old.Priv == pp.String() && old.KeyExt == ke.String() && strings.Join(old.EngineIDs, ",") == strings.Join(engineHex, ",")
	if !sameKeys {
		if ap != snmp.AuthNone && len(authPass) == 0 && errs["auth_pass"] == "" {
			errs["auth_pass"] = "Required (at least 8 characters)."
		}
		if pp != snmp.PrivNone && len(privPass) == 0 && errs["priv_pass"] == "" {
			errs["priv_pass"] = "Required (at least 8 characters)."
		}
	}
	if len(errs) > 0 {
		return api.SNMPUser{}, &api.ValidationError{Fields: errs}
	}
	cu := credUser{Name: name, Auth: canonAuth(ap), Priv: pp.String(), KeyExt: ke.String(), EngineIDs: engineHex, Stored: "passphrase"}
	if pp != snmp.PrivAES192 && pp != snmp.PrivAES256 {
		cu.KeyExt = "draft"
	}
	var sec userSecret
	switch {
	case sameKeys:
		sec = oldSec
		cu.Stored = "localized"
	case len(engines) > 0:
		// Engine-bound: keep only the keys localized to the engines and to
		// Woodshed's own (informs), and discard the passphrases (SPEC §11.2.6).
		u := snmp.User{Name: name, Auth: ap, Priv: pp, KeyExt: ke, AuthPass: authPass, PrivPass: privPass}
		u.Level = u.MaxLevel()
		ids := append([][]byte{}, engines...)
		if len(self) > 0 && !contains(engineHex, hex.EncodeToString(self)) {
			ids = append(ids, self)
		}
		eks, err := u.Localize(ids)
		if err != nil {
			return api.SNMPUser{}, &api.ValidationError{Fields: map[string]string{"auth_pass": "Can't make keys from it: " + sanitize(err)}}
		}
		for _, ek := range eks {
			sec.Keys = append(sec.Keys, engineKey{EngineID: ek.EngineID, Auth: ek.Keys.Auth, Priv: ek.Keys.Priv})
		}
		cu.Stored = "localized"
	default:
		if ap != snmp.AuthNone {
			sec.AuthPass = append([]byte{}, authPass...)
		}
		if pp != snmp.PrivNone {
			sec.PrivPass = append([]byte{}, privPass...)
		}
	}
	u, _ := cu.snmpUser()
	u.AuthPass, u.PrivPass = sec.AuthPass, sec.PrivPass
	for _, k := range sec.Keys {
		u.EngineKeys = append(u.EngineKeys, snmp.EngineKeys{EngineID: k.EngineID, Keys: snmp.Keys{Auth: k.Auth, Priv: k.Priv}})
	}
	if err := u.Validate(); err != nil {
		return api.SNMPUser{}, &api.ValidationError{Fields: map[string]string{"name": sanitize(err)}}
	}
	prevUsers, prevSec, prevHad := append([]credUser{}, c.users...), oldSec, hadSec
	if idx >= 0 {
		c.users[idx] = cu
	} else {
		c.users = append(c.users, cu)
		sort.Slice(c.users, func(i, j int) bool { return c.users[i].Name < c.users[j].Name })
	}
	c.secrets.Users[name] = sec
	if err := c.saveLocked(); err != nil {
		c.users = prevUsers
		if prevHad {
			c.secrets.Users[name] = prevSec
		} else {
			delete(c.secrets.Users, name)
		}
		return api.SNMPUser{}, err
	}
	return c.apiUserLocked(cu), nil
}

func (c *creds) remove(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, cu := range c.users {
		if cu.Name == name {
			prev := append([]credUser{}, c.users...)
			sec, had := c.secrets.Users[name]
			c.users = append(c.users[:i:i], c.users[i+1:]...)
			delete(c.secrets.Users, name)
			if err := c.saveLocked(); err != nil {
				c.users = prev
				if had {
					c.secrets.Users[name] = sec
				}
				return err
			}
			return nil
		}
	}
	return ErrNoUser
}

// ---- communities ----

// communityHashes are the communities as "#hash8" (what /api/settings shows).
func (c *creds) communityHashes() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.secrets.Communities))
	for _, s := range c.secrets.Communities {
		out = append(out, snmp.CommunityHash([]byte(s)))
	}
	return out
}

// setCommunities replaces the list from a settings save: a "#hash8" value
// keeps the stored community it stands for, a plain string is a new one.
// It reports whether anything changed. A "#…" value that matches no stored
// community is an error on its index.
func (c *creds) setCommunities(in []string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	errs := map[string]string{}
	for i, v := range in {
		if strings.HasPrefix(v, "#") && len(v) == 9 {
			found := false
			for _, s := range c.secrets.Communities {
				if snmp.CommunityHash([]byte(s)) == strings.ToLower(v) {
					out, found = appendUnique(out, s), true
					break
				}
			}
			if !found {
				errs[fmt.Sprintf("listeners.snmp.communities[%d]", i)] = "is a hash of no stored community; send the community itself"
			}
			continue
		}
		out = appendUnique(out, v)
	}
	if len(errs) > 0 {
		return false, &api.ValidationError{Fields: errs}
	}
	if equalSets(out, c.secrets.Communities) {
		return false, nil
	}
	prev := c.secrets.Communities
	c.secrets.Communities = out
	if err := c.saveLocked(); err != nil {
		c.secrets.Communities = prev
		return false, err
	}
	return true, nil
}

// communitySet is the accept list as hashes, for the receiver (empty: any).
type communitySet [][32]byte

func (c *creds) communitySet() communitySet {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out communitySet
	for _, s := range c.secrets.Communities {
		out = append(out, sha256.Sum256([]byte(s)))
	}
	return out
}

func (cs communitySet) allows(community []byte) bool {
	if len(cs) == 0 {
		return true
	}
	h := sha256.Sum256(community)
	ok := false
	for _, x := range cs {
		ok = subtle.ConstantTimeCompare(h[:], x[:]) == 1 || ok
	}
	return ok
}

// ---- helpers ----

func defaultStr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func appendUnique(s []string, v string) []string {
	if contains(s, v) {
		return s
	}
	return append(s, v)
}

func equalSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		if !contains(b, x) {
			return false
		}
	}
	return true
}

// sanitize is an error's text without the package prefix (the codec's errors
// never hold key material).
func sanitize(err error) string { return strings.TrimPrefix(err.Error(), "snmp: ") }
