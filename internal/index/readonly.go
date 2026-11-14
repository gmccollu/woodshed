package index

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// ErrNoIndex is returned by OpenReadOnly when there is no index file.
var ErrNoIndex = errors.New("index: no index")

// OpenReadOnly opens an existing index for reading only, for `woodshed search`
// (SPEC §11.4), which reads the data folder beside the running service. It
// never creates, migrates, chmods or chowns anything, so it may run as root on
// a folder the service account owns.
//
// While a writer has the index open, SQLite's -wal and -shm files exist and
// the index is opened with mode=ro: WAL lets it read while the service writes.
// Without them no writer has the index open (the last connection to close
// removes both), and a mode=ro open would create them, so the index is opened
// immutable instead, which reads the database file alone and never creates a
// file. A schema newer or older than this build's is refused: a read-only open
// can't migrate.
func OpenReadOnly(path string) (*DB, error) {
	if strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("index: unsupported character in path %q", path)
	}
	if err := checkReadable(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w at %s", ErrNoIndex, path)
		}
		return nil, fmt.Errorf("index: %w", err)
	}
	live := exists(path+"-wal") && exists(path+"-shm")
	q := url.Values{}
	q.Set("mode", "ro")
	if !live {
		q.Set("immutable", "1")
	}
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "query_only(1)")
	sdb, err := sql.Open("sqlite", fileURI(path)+"?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("index: open %s: %w", path, err)
	}
	sdb.SetMaxOpenConns(4)
	sdb.SetMaxIdleConns(4)
	d := &DB{db: sdb}
	v, err := d.SchemaVersion(context.Background())
	if err != nil {
		sdb.Close()
		return nil, fmt.Errorf("index: read %s: %w", path, err)
	}
	if v != CurrentSchema {
		sdb.Close()
		if v > CurrentSchema {
			return nil, fmt.Errorf("index: %s is from a newer Woodshed (schema %d, this build reads %d); use that version's woodshed",
				path, v, CurrentSchema)
		}
		return nil, fmt.Errorf("index: %s is from an older Woodshed (schema %d, this build reads %d); start the service once to upgrade it",
			path, v, CurrentSchema)
	}
	return d, nil
}

// fileURI is path as an SQLite file: URI ("file:///C:/x/index.db" on Windows).
func fileURI(path string) string {
	p := filepath.ToSlash(path)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // a drive letter
	}
	return "file://" + (&url.URL{Path: p}).EscapedPath()
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}
