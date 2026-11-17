package flow

import (
	"encoding/binary"
	"errors"
)

// RedecodeOptions are what DecodeRawSet needs beyond the set and its
// template: the rule_id IEs in force, and the domain's system init time and
// sampling from the segment's metadata when known (0 otherwise).
type RedecodeOptions struct {
	RuleIDIEs []IEKey
	SysInitMs int64
	Sampling  uint32
}

// ErrMalformedSet is DecodeRawSet's error for a set that breaks off; the
// records before the break are returned with it.
var ErrMalformedSet = errors.New("flow: the set breaks off")

// DecodeRawSet decodes a stored raw set (SPEC §13.1.3: no_template) with a
// template from the segment's own table, for decode-on-read and `woodshed
// reindex --flows-redecode`. Records are StatusLate with the set's received
// time; interface names aren't resolved (the caller has no options data).
func DecodeRawSet(t *Template, rs *RawSet, o RedecodeOptions) ([]Record, error) {
	if t == nil || t.Options || rs == nil {
		return nil, errors.New("flow: no data template")
	}
	h := hdrCtx{uptimeMs: -1, received: rs.Received, sysInitMs: o.SysInitMs}
	switch rs.Version {
	case V9:
		if len(rs.Header) >= v9Header {
			h.uptimeMs = int64(binary.BigEndian.Uint32(rs.Header[4:]))
			h.exportMs = int64(binary.BigEndian.Uint32(rs.Header[8:])) * 1000
		}
	case IPFIX:
		if len(rs.Header) >= ipfixHeader {
			h.exportMs = int64(binary.BigEndian.Uint32(rs.Header[4:])) * 1000
		}
	default:
		return nil, errors.New("flow: raw sets are v9 or IPFIX")
	}
	if h.exportMs == 0 {
		h.exportMs = rs.Received
	}
	d := rs.Received - h.exportMs
	h.skewed = d > ClockSkewLimit.Milliseconds() || -d > ClockSkewLimit.Milliseconds()
	p := compile(t, o.RuleIDIEs, 0)
	var out []Record
	b := rs.Data
	for len(b) > 0 {
		if len(b) < p.minLen {
			if allZero(b) || p.fixed {
				return out, nil
			}
			return out, ErrMalformedSet
		}
		var r Record
		n, samp, err := p.decodeRecord(b, &r, &h)
		if err != nil {
			if allZero(b) {
				return out, nil
			}
			return out, ErrMalformedSet
		}
		b = b[n:]
		r.Received, r.Domain, r.ExporterPort, r.Version = rs.Received, rs.Domain, rs.ExporterPort, rs.Version
		r.TemplateID, r.Template, r.Status = t.ID, t, StatusLate
		r.Sampling = samp.rate()
		if r.Sampling == 0 {
			r.Sampling = o.Sampling
		}
		out = append(out, r)
	}
	return out, nil
}
