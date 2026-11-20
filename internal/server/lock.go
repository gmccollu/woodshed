package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gmccollu/woodshed/internal/peer"
)

// LockFileName is the file in the data dir that a running Woodshed holds an
// exclusive lock on, so that two servers (or a server and `woodshed reindex`)
// never use one data dir at once. The lock is the OS's (flock, LockFileEx), so it
// goes away with the process, even after a crash.
const LockFileName = "woodshed.lock"

// errNotPlainFile is returned for a lock file that's a symlink, a hard link or not
// a regular file.
var errNotPlainFile = errors.New("is a link or not a regular file; refusing to use it (remove it if it shouldn't be there)")

// ErrLocked means another process holds the data dir's lock.
var ErrLocked = errors.New("another Woodshed process is using this data folder")

// DirLock is a held data-dir lock.
type DirLock struct {
	f *os.File
}

// LockDataDir takes the data dir's lock without waiting. It returns an error
// wrapping ErrLocked when another process holds it.
func LockDataDir(dataDir string) (*DirLock, error) {
	path := filepath.Join(dataDir, LockFileName)
	// Never through a symlink or a hard link: a root `woodshed reindex` on a folder
	// the service account controls must not truncate some other file.
	f, err := openLockFile(path, true)
	if err != nil {
		return nil, fmt.Errorf("open the lock file: %w", err)
	}
	if err := lockFile(f); err != nil {
		f.Close()
		if errors.Is(err, ErrLocked) {
			return nil, fmt.Errorf("%w (%s)", ErrLocked, dataDir)
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	// The PID is only a hint for people; the lock is what counts.
	_ = f.Truncate(0)
	_, _ = f.WriteAt([]byte(fmt.Sprintf("%d\n", os.Getpid())), 0)
	return &DirLock{f: f}, nil
}

// Unlock releases the lock.
func (l *DirLock) Unlock() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := unlockFile(l.f)
	if cerr := l.f.Close(); err == nil {
		err = cerr
	}
	l.f = nil
	return err
}

// DataDirInUse reports whether a running Woodshed holds dataDir's lock. It
// returns false when the lock file doesn't exist. An error means it couldn't
// tell (for example no permission to open the lock file).
func DataDirInUse(dataDir string) (bool, error) {
	path := filepath.Join(dataDir, LockFileName)
	f, err := openLockFile(path, false)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	if err := lockFile(f); err != nil {
		if errors.Is(err, ErrLocked) {
			return true, nil
		}
		return false, err
	}
	_ = unlockFile(f)
	return false, nil
}

// RunningState is the run-state file of the server that holds dataDir's lock
// now: ok only while the lock is held and the file's PID is the one the
// holder wrote into the lock file, so a file a crashed or older run left
// behind isn't taken for the running server's.
func RunningState(dataDir string) (RunState, bool) {
	if inUse, err := DataDirInUse(dataDir); err != nil || !inUse {
		return RunState{}, false
	}
	rs, err := ReadState(dataDir)
	if err != nil || rs.PID == 0 {
		return RunState{}, false
	}
	b, err := os.ReadFile(filepath.Join(dataDir, LockFileName))
	if err != nil {
		// Windows: the holder's LockFileEx covers the byte the PID starts at,
		// so another process can't read it. The state's PID must be alive.
		return rs, peer.ProcessAlive(rs.PID)
	}
	var pid int
	if _, err := fmt.Sscanf(string(b), "%d", &pid); err != nil || pid != rs.PID {
		return RunState{}, false
	}
	return rs, true
}
