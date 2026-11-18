package index

import (
	"time"

	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// Checkpoint is a point in a file's uncompressed stream; see logfile.Checkpoint for
// the exact meaning of Received.
type Checkpoint = logfile.Checkpoint

// TypeSyslog is the data type of every 1.1 row, and the default.
const TypeSyslog = logfile.TypeSyslog

// File is one log file.
type File struct {
	ID       int64 // stable across a part rename and compression
	DeviceID string
	Type     string // the data type ("syslog", "trap"); "" means syslog
	Path     string // relative to the data dir, '/'-separated
	Day      string // YYYY-MM-DD (UTC) from the file name
	Part     int    // 0 for "<day>.log" (the day's newest part), else the part number
	// FirstReceived and LastReceived are the lowest and highest received time of any
	// line in the file. Order a device's files by FirstReceived.
	FirstReceived time.Time
	LastReceived  time.Time
	Size          int64 // bytes on disk (compressed size for .gz)
	RawSize       int64 // bytes of the uncompressed stream
	Lines         int64
	Compressed    bool
}

// FileSpan is a file overlapping a queried time range, with the checkpoint to start
// reading at for the range's start.
type FileSpan struct {
	File
	Start Checkpoint
}

// Device is a sender.
type Device struct {
	ID          string // model.DeviceID of the IP; also the logs/ directory name
	IP          string
	Name        string
	Group       string
	Hidden      bool
	FirstSeen   time.Time
	LastHeard   time.Time
	TotalMsgs   int64 // messages stored, all time
	TotalBytes  int64 // raw message bytes stored, all time
	BytesOnDisk int64 // sum of the device's file sizes now
	RecentMsgs  int64 // messages in DeviceQuery's rate window (QueryDevices only)
}

// DeviceUpdate changes a device's user-set fields; nil fields are left alone.
type DeviceUpdate struct {
	Name   *string
	Group  *string
	Hidden *bool
}

// Counts are message counters for a device or a time range.
type Counts struct {
	Msgs      int64 // messages stored
	Bytes     int64 // raw bytes stored
	Truncated int64 // messages cut at the max message size (still stored)
	Dropped   int64 // messages Woodshed received but could not store
	// Flow is the flow collector's counts (type_stats rows of type flow
	// only; zero for the other types).
	Flow FlowCounts
}

// Add adds o to c.
func (c *Counts) Add(o Counts) {
	c.Msgs += o.Msgs
	c.Bytes += o.Bytes
	c.Truncated += o.Truncated
	c.Dropped += o.Dropped
	c.Flow.Add(o.Flow)
}

// MinuteCounts are the counts for the minute starting at Minute.
type MinuteCounts struct {
	Minute time.Time
	Counts
}

// HourCounts are the counts for the hour starting at Hour.
type HourCounts struct {
	Hour time.Time
	Counts
}

// RefusedDeviceID is the stats id under which the store counts messages from new
// senders it refused (device cap or new-device rate), as Dropped. It has stats rows
// but no devices row; real device IDs never start with '_'. DeviceCounts includes it.
const RefusedDeviceID = "_refused"

// Activity is a counter delta for one device and one minute, as the store reports it.
type Activity struct {
	DeviceID   string
	Type       string // the data type; "" and "syslog" go to the stats tables, others to type_stats
	IP         string
	Minute     time.Time // start of the minute (truncated if not)
	FirstHeard time.Time // earliest message in the delta (for first_seen)
	LastHeard  time.Time // latest message in the delta (dropped ones count as heard)
	Counts
}

// Level is an event's level.
type Level string

// Event levels.
const (
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

// Kind classifies an event.
type Kind string

// Event kinds. The store records rotate, compress (failures), delete, drop, pause,
// resume and recover; the service and listeners record start, stop and bind; the
// HTTP layer records ui (UI server start, bind errors, mode changes, certificates)
// and auth (password changes, login lockouts); the export queue records export
// (queued, ready, failed, cancelled, deleted, expired); the store records clock
// (the received clock stepped back by more than logfile.MaxSkew); Open records
// migrate (one schema step on an existing index).
const (
	KindStart    Kind = "start"
	KindStop     Kind = "stop"
	KindBind     Kind = "bind"
	KindRotate   Kind = "rotate"
	KindCompress Kind = "compress"
	KindDelete   Kind = "delete"
	KindDrop     Kind = "drop"
	KindPause    Kind = "pause"
	KindResume   Kind = "resume"
	KindRecover  Kind = "recover"
	KindError    Kind = "error"
	KindUI       Kind = "ui"
	KindAuth     Kind = "auth"
	KindExport   Kind = "export"
	KindClock    Kind = "clock"
	KindDevice   Kind = "device" // the admin blocked or unblocked a device
	// KindDeviceLimit: new senders refused by the device cap or new-device rate.
	KindDeviceLimit Kind = "device_limit"
	// KindFlood: one device sent more than half of the last 24 h's bytes.
	KindFlood Kind = "flood"
	// KindRetentionCap: at the current rate the size cap keeps fewer days than
	// retention_days (at most once a day).
	KindRetentionCap Kind = "retention_cap"
	// KindTLS: the TLS syslog certificate was created, renewed or its CA
	// replaced (with the fingerprints).
	KindTLS Kind = "tls"
	// KindMigrate: Open migrated an existing index one schema step
	// ("index migrated from schema 8 to 9 in 12 ms").
	KindMigrate Kind = "migrate"
)

// Source says what an event is about, for readers that act on events (export
// gap detection) rather than show them. Empty for events nobody reads that way.
type Source string

// Event sources. The service records its start and stop with SourceService;
// each listener records its start, stop and bind errors with its own source.
const (
	SourceService      Source = "service"
	SourceListenerUDP  Source = "listener/udp"
	SourceListenerTCP  Source = "listener/tcp"
	SourceListenerTLS  Source = "listener/tls"
	SourceListenerSNMP Source = "listener/snmp"
)

// ListenerSource is the source of a listener's events, for proto "udp", "tcp" or
// "tls" ("" for anything else).
func ListenerSource(proto string) Source {
	switch proto {
	case "udp":
		return SourceListenerUDP
	case "tcp":
		return SourceListenerTCP
	case "tls":
		return SourceListenerTLS
	case "snmp":
		return SourceListenerSNMP
	}
	return ""
}

// Event is one of the service's own events.
type Event struct {
	ID       int64
	Time     time.Time
	Level    Level
	Kind     Kind
	DeviceID string // "" when not about one device
	Text     string
	Source   Source // what the event is about, for readers that act on it ("" if nothing)
}

// Reason is why a file was deleted.
type Reason string

// Deletion reasons.
const (
	ReasonAge     Reason = "age"
	ReasonCap     Reason = "cap"
	ReasonLowDisk Reason = "low_disk"
	// ReasonFlowBudget: a flow segment deleted while flows were over their own
	// budget (storage.flow_budget_bytes), not the storage cap. The deletions
	// table stores it as "cap" (its CHECK predates flows); flows are never
	// deleted for the cap itself, so Deletions reads a flow row's "cap" back as
	// ReasonFlowBudget.
	ReasonFlowBudget Reason = "flow_budget"
)

// Deletion is one entry of the storage history.
type Deletion struct {
	ID       int64
	Time     time.Time
	File     string // path relative to the data dir
	DeviceID string
	Type     string // the file's data type ("" means syslog)
	Bytes    int64  // bytes freed on disk
	Reason   Reason
}

// FileOpKind is the kind of a FileOp.
type FileOpKind int

// File operations.
const (
	// OpUpsert creates or updates the row for File.Path with File's fields (ID is
	// ignored) and adds Checkpoints (existing offsets are kept).
	OpUpsert FileOpKind = iota + 1
	// OpRename moves the row at OldPath to File.Path and sets File's fields, keeping
	// the row's ID and checkpoints (a part rename, or compression).
	OpRename
	// OpDelete removes the row for File.Path. With Deletion set, it also records
	// the deletion in the storage history and as an event.
	OpDelete
)

// FileOp is one change to the files table.
type FileOp struct {
	Kind        FileOpKind
	File        File
	OldPath     string
	Checkpoints []Checkpoint
	// ResetCheckpoints (OpUpsert) replaces the file's checkpoints with Checkpoints
	// instead of adding to them, after the store re-read a file.
	ResetCheckpoints bool
	Deletion         *Deletion
	// Flow (OpUpsert of a flow segment) sets the segment's flow_segments row.
	Flow *FlowSegment
}

// Batch is a set of changes applied in one transaction, file ops in order.
type Batch struct {
	Files    []FileOp
	Activity []Activity
	Events   []Event
	// FlowMinutes are deltas added to flow_minute, after Files (so a
	// segment's rows exist before its minutes).
	FlowMinutes []FlowMinute
}

// Empty reports whether the batch has nothing to apply.
func (b *Batch) Empty() bool {
	return len(b.Files) == 0 && len(b.Activity) == 0 && len(b.Events) == 0 && len(b.FlowMinutes) == 0
}
