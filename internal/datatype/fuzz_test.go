package datatype

import (
	"strings"
	"testing"

	"github.com/gmccollu/woodshed/internal/snmp"
)

// FuzzTrapType: any stored line through the trap type's filter, fields,
// text and result, with any filter parameters, never panics (a hand-edited
// or damaged trap file is still searched).
func FuzzTrapType(f *testing.F) {
	f.Add([]byte(`v=2c pdu=trap id=1 cred=#efa1f375 status=ok uptime=5 trap=1.3.6.1.6.3.1.1.5.3(linkDown) vb=1.3.6.1.2.1.2.2.1.8.3(ifOperStatus.3):int:2(down) raw=MAA=`),
		"trap_oid", "linkDown,1.3.6.1.4.1.32473.*")
	f.Add([]byte(`v=1 pdu=v1trap cred="a b" status=ok enterprise=1.3.6.1.4.1.32473.1 generic=6 specific=17 vb=1.2:str:"x\"y" raw=`), "specific", "17")
	f.Add([]byte(`status=malformed error="BER: x"`), "status", "malformed,none")
	f.Fuzz(func(t *testing.T, rec []byte, param, value string) {
		ty := Get(Trap)
		ty.Text(rec)
		ty.FieldValues(rec, &Scratch{}, func(k, v string) { ty.ValueLabel(k, v) })
		ty.Summary([][]byte{rec})
		_ = Result(rec)
		flt, err := ParseTrapFilter(func(p string) string {
			if p == param {
				return value
			}
			return ""
		})
		if err != nil {
			if !strings.HasPrefix(err.Error(), param+":") {
				t.Fatalf("error %q doesn't name %s", err, param)
			}
			return
		}
		if flt.Pre(rec) {
			flt.Post(rec, &Scratch{})
		}
		_ = flt.Bind()
		_, _ = snmp.ParseRecordHeader(rec)
	})
}
