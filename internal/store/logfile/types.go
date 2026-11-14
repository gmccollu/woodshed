package logfile

// Data types on disk (SPEC §11.1). Each type's files live in its own folder
// inside the device folder: syslog in the device folder itself (as in 1.0 and
// 1.1), traps in "traps/". The folder says the type, so no line has to be read
// to know it. internal/datatype is the semantic side of the same registry; its
// tests check that the two agree.

// Data type names.
const (
	TypeSyslog = "syslog"
	TypeTrap   = "trap"
	TypePoll   = "poll"
)

// DataType is one type's name and its folder inside a device folder ("" is the
// device folder itself).
type DataType struct {
	Name string
	Dir  string
}

// DataTypes lists every type, syslog first.
var DataTypes = []DataType{{Name: TypeSyslog, Dir: ""}, {Name: TypeTrap, Dir: "traps"}, {Name: TypePoll, Dir: "poll"}}

// TypeDir returns the folder of a type ("" for syslog and for an unknown
// type, which is read as syslog like every 1.1 row).
func TypeDir(typ string) string {
	for _, t := range DataTypes {
		if t.Name == typ {
			return t.Dir
		}
	}
	return ""
}

// TypeOfDir returns the type a device subfolder holds, or false for a folder
// no type claims.
func TypeOfDir(dir string) (string, bool) {
	if dir == "" {
		return "", false
	}
	for _, t := range DataTypes {
		if t.Dir == dir {
			return t.Name, true
		}
	}
	return "", false
}

// NormType returns typ, or TypeSyslog for "".
func NormType(typ string) string {
	if typ == "" {
		return TypeSyslog
	}
	return typ
}

// RelPathType returns the data-dir-relative path of a device's file of a type.
func RelPathType(typ, deviceID string, n Name) string {
	if d := TypeDir(typ); d != "" {
		return LogsDir + "/" + deviceID + "/" + d + "/" + n.String()
	}
	return RelPath(deviceID, n)
}
