package store

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/gmccollu/woodshed/internal/atomicfile"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

func (s *Store) kickCompress() {
	if s.opts.Manual {
		return
	}
	select {
	case s.compressCh <- struct{}{}:
	default:
	}
}

// compressLoop is the background gzip worker. It runs on its own OS thread at the
// lowest CPU (and, where the OS allows, I/O) priority. The thread stays locked, so
// it exits with the goroutine and the lowered priority never leaks to other work.
//
// The priority is lowered at the first file to compress, so a store with
// nothing to compress never has a low-priority thread at all. Close doesn't
// wait for this goroutine past compressorStopWait (see Store.compGate).
func (s *Store) compressLoop() {
	defer close(s.compDone)
	runtime.LockOSThread()
	lowered := false
	for {
		select {
		case <-s.stop:
			return
		case <-s.compressCh:
			if !lowered && s.hasCompressWork(s.clock()) {
				lowered = true
				if s.testHookLowerPrio != nil {
					s.testHookLowerPrio()
				}
				if !s.testKeepPrio {
					if err := lowerThreadPriority(); err != nil {
						s.log.Debug("store: couldn't lower the compressor's priority", "err", err)
					}
				}
			}
			s.compressPending(s.ctx)
		}
	}
}

// compressorStopWait is how long Close waits for the compressor to exit. A
// starved low-priority thread may take longer; it then changes nothing (the
// context is cancelled and compGate is taken), and its temp file is its own
// (tmpTag) and is deleted at the next Open if it's left.
const compressorStopWait = time.Second

// stopCompressor ends the compressor's changes: after it returns, no file is
// renamed or deleted and no catalog or index change is queued by it. It waits
// for the goroutine to exit for at most compressorStopWait.
func (s *Store) stopCompressor() {
	s.compGate.Lock() // a commit in progress finishes; later ones see the cancelled context
	s.compGate.Unlock()
	if s.opts.Manual {
		return
	}
	t := time.NewTimer(compressorStopWait)
	defer t.Stop()
	select {
	case <-s.compDone:
	case <-t.C:
		s.log.Debug("store: the compressor's thread hasn't been scheduled to stop yet; not waiting for it")
	}
}

// randomTag is a short random hex string.
func randomTag() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// commit runs f, a change to files, the catalog or the index queue, unless the
// store is closing (ctx cancelled).
func (s *Store) commit(ctx context.Context, f func() error) error {
	s.compGate.Lock()
	defer s.compGate.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return f()
}

func (s *Store) hasCompressWork(now time.Time) bool {
	s.catMu.Lock()
	defer s.catMu.Unlock()
	for _, e := range s.cat {
		if !e.name.Compressed && !e.busy && !e.syncing && !e.parked && !now.Before(e.nextTry) {
			return true
		}
	}
	return false
}

// nextToCompress picks the oldest closed uncompressed file that is due and marks it busy.
func (s *Store) nextToCompress(now time.Time) *catEntry {
	s.catMu.Lock()
	defer s.catMu.Unlock()
	var best *catEntry
	for _, e := range s.cat {
		if e.name.Compressed || e.busy || e.syncing || e.parked || now.Before(e.nextTry) {
			continue
		}
		if best == nil || e.last.Before(best.last) || (e.last.Equal(best.last) && e.rel < best.rel) {
			best = e
		}
	}
	if best != nil {
		best.busy = true
	}
	return best
}

// compressPending gzips every closed file that is due, oldest first.
func (s *Store) compressPending(ctx context.Context) {
	for ctx.Err() == nil {
		e := s.nextToCompress(s.clock())
		if e == nil {
			return
		}
		err := s.compressOne(ctx, e)
		s.catMu.Lock()
		e.busy = false
		if err != nil && ctx.Err() == nil {
			e.failures++
			e.nextTry = s.clock().Add(min(time.Duration(1<<min(e.failures, 6))*time.Minute, time.Hour))
		}
		s.catMu.Unlock()
		if err != nil && ctx.Err() == nil {
			s.event(index.LevelError, index.KindCompress, e.deviceID, fmt.Sprintf("compressing %s failed, original kept: %v", e.rel, err))
		}
	}
}

// compressOne gzips a closed file to a temp file, verifies the gzip by decompressing
// it and comparing length and SHA-256 with the original, then renames it into place,
// updates the index and deletes the original.
func (s *Store) compressOne(ctx context.Context, e *catEntry) error {
	s.catMu.Lock()
	src, name, dir := e.abs, e.name, filepath.Dir(e.abs)
	s.catMu.Unlock()
	gzName := name
	gzName.Compressed = true
	dst := filepath.Join(dir, gzName.String())
	if _, err := os.Stat(dst); err == nil {
		// A .gz of this name already exists (the clock went back, or files were copied
		// in). Never overwrite it: move the source to a fresh part number first.
		if err := s.commit(ctx, func() error {
			nn := logfile.Name{Day: name.Day, Part: nextPart(dir, name.Day)}
			nsrc := filepath.Join(dir, nn.String())
			if err := os.Rename(src, nsrc); err != nil {
				return err
			}
			s.catMu.Lock()
			oldRel := e.rel
			delete(s.cat, oldRel)
			e.name, e.abs, e.rel = nn, nsrc, s.rel(nsrc)
			s.cat[e.rel] = e
			row := e.row()
			s.catMu.Unlock()
			s.pushOps(index.FileOp{Kind: index.OpRename, OldPath: oldRel, File: row})
			src, name = nsrc, nn
			return nil
		}); err != nil {
			return err
		}
		gzName = name
		gzName.Compressed = true
		dst = filepath.Join(dir, gzName.String())
	}
	// The temp file is this Store's own (tmpTag), so a compressor left running
	// after Close never touches another Store's (a reopen in the same process).
	tmp := dst + "." + s.tmpTag + logfile.TempSuffix
	sum, n, err := gzipTo(ctx, src, tmp)
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if n != e.size {
		os.Remove(tmp)
		return fmt.Errorf("file changed while compressing (%d bytes, expected %d)", n, e.size)
	}
	if s.testHookGzip != nil {
		s.testHookGzip(tmp)
	}
	vsum, vn, err := hashGzip(tmp)
	if err != nil || vn != n || !bytes.Equal(vsum, sum) {
		os.Remove(tmp)
		if err == nil {
			err = fmt.Errorf("gzip verification failed (%d bytes back, expected %d, or the hash differs)", vn, n)
		}
		return err
	}
	err = s.commit(ctx, func() error {
		if err := atomicfile.Rename(tmp, dst); err != nil {
			os.Remove(tmp)
			return err
		}
		syncDir(dir)
		st, err := os.Stat(dst)
		if err != nil {
			return err
		}
		s.catMu.Lock()
		oldRel := e.rel
		delete(s.cat, oldRel)
		s.catBytes += st.Size() - e.size
		e.name, e.abs, e.rel, e.size = gzName, dst, s.rel(dst), st.Size()
		s.cat[e.rel] = e
		row := e.row()
		s.catMu.Unlock()
		s.pushOps(index.FileOp{Kind: index.OpRename, OldPath: oldRel, File: row})
		if err := os.Remove(src); err != nil && !errors.Is(err, fs.ErrNotExist) {
			// For example a reader on Windows holding it without delete sharing.
			s.catMu.Lock()
			s.orphans[src] = true
			s.catMu.Unlock()
		}
		return nil
	})
	if err != nil && ctx.Err() != nil {
		os.Remove(tmp) // closing: the original stays, and the next Open compresses it
	}
	return err
}

// gzipTo compresses src into dst (fsynced) and returns the SHA-256 and length of src.
func gzipTo(ctx context.Context, src, dst string) ([]byte, int64, error) {
	in, err := logfile.OpenFile(src)
	if err != nil {
		return nil, 0, err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, 0, err
	}
	h := sha256.New()
	zw, _ := gzip.NewWriterLevel(out, gzip.DefaultCompression)
	zw.Name = filepath.Base(src)
	var n int64
	buf := make([]byte, 256<<10)
	for {
		if err := ctx.Err(); err != nil {
			out.Close()
			return nil, 0, err
		}
		k, rerr := in.Read(buf)
		if k > 0 {
			h.Write(buf[:k])
			if _, err := zw.Write(buf[:k]); err != nil {
				out.Close()
				return nil, 0, err
			}
			n += int64(k)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			out.Close()
			return nil, 0, rerr
		}
	}
	if err := zw.Close(); err != nil {
		out.Close()
		return nil, 0, err
	}
	if err := syncFile(out); err != nil {
		out.Close()
		return nil, 0, err
	}
	if err := out.Close(); err != nil {
		return nil, 0, err
	}
	return h.Sum(nil), n, nil
}

// hashGzip decompresses path and returns the SHA-256 and length of its contents.
func hashGzip(path string) ([]byte, int64, error) {
	f, err := logfile.OpenFile(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, 0, err
	}
	h := sha256.New()
	n, err := io.Copy(h, zr)
	if err != nil {
		return nil, n, err
	}
	return h.Sum(nil), n, zr.Close()
}

// hashPlain returns the SHA-256 and length of a file.
func hashPlain(path string) ([]byte, int64, error) {
	f, err := logfile.OpenFile(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return h.Sum(nil), n, err
}

// cleanOrphans retries deleting originals whose .gz is already in place.
func (s *Store) cleanOrphans() {
	s.catMu.Lock()
	if len(s.orphans) == 0 {
		s.catMu.Unlock()
		return
	}
	paths := make([]string, 0, len(s.orphans))
	for p := range s.orphans {
		paths = append(paths, p)
	}
	s.catMu.Unlock()
	for _, p := range paths {
		if err := os.Remove(p); err == nil || errors.Is(err, fs.ErrNotExist) {
			s.catMu.Lock()
			delete(s.orphans, p)
			s.catMu.Unlock()
		}
	}
}
