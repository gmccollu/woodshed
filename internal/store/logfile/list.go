package logfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// LogsDir is the directory under the data dir holding one directory per device.
const LogsDir = "logs"

// TempSuffix ends the name of every temporary file the store writes (a gzip in
// progress). Leftovers are deleted at startup.
const TempSuffix = ".tmp"

// Entry is a log file found on disk.
type Entry struct {
	DeviceID string
	Type     string // TypeSyslog, TypeTrap, …: from the folder it's in
	Name     Name
	Rel      string // path relative to the data dir, '/'-separated
	Path     string // absolute (or data-dir-joined) OS path
	Size     int64
}

// RelPath returns the data-dir-relative path of a device's file.
func RelPath(deviceID string, n Name) string { return LogsDir + "/" + deviceID + "/" + n.String() }

// List walks <dataDir>/logs and returns every log file of every data type,
// ordered by device, then type folder ("" first), then name, plus the paths of
// leftover temp files. Other files are ignored, and so are subfolders of a
// device folder that no data type claims (ListAll reports them).
func List(dataDir string) (files []Entry, temps []string, err error) {
	files, temps, _, err = ListAll(dataDir)
	return files, temps, err
}

// ListAll is List, and also returns the device subfolders no data type claims
// (relative to the data dir), which List ignores.
func ListAll(dataDir string) (files []Entry, temps []string, unknown []string, err error) {
	root := filepath.Join(dataDir, LogsDir)
	devs, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil, nil
	}
	if err != nil {
		return nil, nil, nil, err
	}
	for _, dv := range devs {
		if !dv.IsDir() {
			continue
		}
		dir := filepath.Join(root, dv.Name())
		ents, err := os.ReadDir(dir)
		if err != nil {
			return nil, nil, nil, err
		}
		var subs []string
		if files, temps, err = listDir(files, temps, dir, dv.Name(), TypeSyslog, ents, &subs); err != nil {
			return nil, nil, nil, err
		}
		for _, sub := range subs {
			typ, ok := TypeOfDir(sub)
			if !ok {
				unknown = append(unknown, LogsDir+"/"+dv.Name()+"/"+sub)
				continue
			}
			sdir := filepath.Join(dir, sub)
			sents, err := os.ReadDir(sdir)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, nil, nil, err
			}
			if files, temps, err = listDir(files, temps, sdir, dv.Name(), typ, sents, nil); err != nil {
				return nil, nil, nil, err
			}
		}
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].DeviceID != files[j].DeviceID {
			return files[i].DeviceID < files[j].DeviceID
		}
		if di, dj := TypeDir(files[i].Type), TypeDir(files[j].Type); di != dj {
			return di < dj
		}
		return files[i].Name.String() < files[j].Name.String()
	})
	return files, temps, unknown, nil
}

// listDir adds one folder's log files (of type typ) and temp files. With subs
// set, it collects the subfolder names too.
func listDir(files []Entry, temps []string, dir, dev, typ string, ents []os.DirEntry, subs *[]string) ([]Entry, []string, error) {
	for _, e := range ents {
		if e.IsDir() {
			if subs != nil {
				*subs = append(*subs, e.Name())
			}
			continue
		}
		if !e.Type().IsRegular() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if strings.HasSuffix(e.Name(), TempSuffix) {
			temps = append(temps, p)
			continue
		}
		n, ok := ParseName(e.Name())
		if !ok {
			continue
		}
		size, err := entrySize(p, e)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		files = append(files, Entry{DeviceID: dev, Type: typ, Name: n, Rel: RelPathType(typ, dev, n), Path: p, Size: size})
	}
	return files, temps, nil
}
