package loadgen

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/snmp"
	"github.com/gmccollu/woodshed/internal/store"
	"github.com/gmccollu/woodshed/internal/store/logfile"
	"github.com/gmccollu/woodshed/internal/trap"
)

// benchReceiver is the trap receiver as the server wires it, writing into the
// bench's store (with the fake slow disk), and the sender's options: for v3,
// a user made up for the run with random passphrases, added to the receiver
// in memory and its 0600 credentials file in the bench's own data folder.
//
// The reply limits (100 a second per source, SPEC §11.2.3) would cap informs
// from the bench's one sender, so its receiver allows twice the bench rate:
// the bench measures the pipeline, and the limits have their own tests.
func benchReceiver(dir string, st *store.Store, stall *staller, stalls, writeErrs *atomic.Int64, log *slog.Logger,
	to TrapOptions, rate float64) (*trap.Receiver, TrapOptions, error) {
	limit := max(int(2*rate), trap.ReplyTotal)
	rcv, err := trap.Open(trap.Options{
		DataDir: dir, Logger: log, ReplyPerSource: limit, ReplyTotal: limit,
		Write: func(m model.Message) error {
			if stall.wait() {
				stalls.Add(1)
			}
			err := st.WriteType(logfile.TypeTrap, m)
			if err != nil {
				writeErrs.Add(1)
			}
			return err
		},
	}, trap.Settings{AnswerInforms: true})
	if err != nil {
		return nil, to, err
	}
	if to.Version == "" {
		to.Version = "2c"
	}
	if to.Version != "3" {
		return rcv, to, nil
	}
	if to.Auth == snmp.AuthNone && to.Priv != snmp.PrivNone {
		return nil, to, fmt.Errorf("loadgen: v3 privacy needs authentication")
	}
	secret := func() []byte {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		return []byte(hex.EncodeToString(b))
	}
	to.User = "bench"
	to.AuthPass, to.PrivPass = nil, nil
	in := api.SNMPUserInput{Name: to.User, Auth: to.Auth.String(), Priv: to.Priv.String(), KeyExt: to.KeyExt.String()}
	if to.Auth != snmp.AuthNone {
		to.AuthPass = secret()
		in.AuthPass = string(to.AuthPass)
	}
	if to.Priv != snmp.PrivNone {
		to.PrivPass = secret()
		in.PrivPass = string(to.PrivPass)
	}
	if to.Priv != snmp.PrivAES192 && to.Priv != snmp.PrivAES256 {
		in.KeyExt = ""
	}
	if _, err := rcv.PutUser(in, ""); err != nil {
		return nil, to, fmt.Errorf("loadgen: the bench's v3 user: %w", err)
	}
	return rcv, to, nil
}
