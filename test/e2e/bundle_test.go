package e2e

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/loadgen"
)

// TestIncidentBundle (SPEC §11.3, §11.6) runs the real binary: syslog over
// UDP and TCP and SNMP traps (with a coldStart) from `woodshed send` in three
// phases, then a bundle around the middle phase built by the API and by
// `woodshed bundle` beside the running service. Unzipped, verifyseq finds
// every message of the middle phase exactly once and nothing of the other
// two; each file's SHA-256 is the manifest's; the README counts what was
// sent and names the coldStart; the community is nowhere in the zip; and the
// two zips hold the same files.
func TestIncidentBundle(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	dir := t.TempDir()
	syslogPort, uiPort := pickPorts(t)
	snmpPort := freeUDPPort(t, syslogPort, uiPort)
	cfgPath, dataDir := writeConfig(t, dir, syslogPort, uiPort)
	c, err := config.Read(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	c.Listeners.SNMP.Enabled, c.Listeners.SNMP.Addr, c.Listeners.SNMP.Port = true, "127.0.0.1", snmpPort
	if err := config.Save(cfgPath, c); err != nil {
		t.Fatal(err)
	}
	p := startWoodshed(t, cfgPath, dataDir, uiPort)
	defer p.stop()
	verifyseq := buildVerifyseq(t)
	community := filepath.Join(dir, "community")
	if err := os.WriteFile(community, []byte("e2e-bundle-community\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	send := func(args ...string) {
		t.Helper()
		out, err := exec.Command(binary, append([]string{"send", "--host", "127.0.0.1"}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("send %v: %v\n%s", args, err, out)
		}
	}
	const perProto, traps = 300, 40
	// Each phase is its own run, so verifyseq can say which phase a message is from.
	phase := func(name string) (syslogRun, trapRun string) {
		t.Helper()
		syslogRun, trapRun = loadgen.NewRunID(), loadgen.NewRunID()
		sp := fmt.Sprint(syslogPort)
		send("--proto", "udp", "--port", sp, "--count", fmt.Sprint(perProto), "--rate", "3000", "--run", syslogRun, "--message", name)
		send("--proto", "tcp", "--port", sp, "--count", fmt.Sprint(perProto), "--rate", "3000", "--run", syslogRun,
			"--first-seq", fmt.Sprint(perProto), "--message", name)
		tp := fmt.Sprint(snmpPort)
		send("--proto", "trap", "--port", tp, "--community-file", community, "--count", fmt.Sprint(traps), "--rate", "500", "--run", trapRun)
		// The device reboots in the middle phase only.
		if name == "middle" {
			send("--proto", "trap", "--port", tp, "--community-file", community, "--count", "1", "--run", trapRun,
				"--first-seq", fmt.Sprint(traps), "--trap-oid", "1.3.6.1.6.3.1.1.5.1")
		}
		n := traps
		if name == "middle" {
			n++
		}
		runVerify(t, verifyseq, dataDir, syslogRun, 2*perProto, 0, "-wait", "30s")
		runVerify(t, verifyseq, dataDir, trapRun, n, 0, "-wait", "30s")
		return syslogRun, trapRun
	}
	// [w0, w1) holds the middle phase only: each edge is taken a second clear of
	// the phase next to it, after its messages are on disk.
	beforeS, beforeT := phase("before")
	time.Sleep(1200 * time.Millisecond)
	w0 := time.Now().UTC().Truncate(time.Millisecond).Add(time.Millisecond)
	middleS, middleT := phase("middle")
	time.Sleep(1200 * time.Millisecond)
	w1 := time.Now().UTC().Truncate(time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	afterS, afterT := phase("after")
	waitFor(t, "the index to catch up", 20*time.Second, func() bool {
		var page struct{ Total int }
		p.getJSON("/api/devices?active_from="+w1.Format(time.RFC3339Nano)+"&active_to="+
			time.Now().UTC().Format(time.RFC3339Nano), &page)
		return page.Total == 1
	})

	// The window as at, before and after, in milliseconds.
	half := w1.Sub(w0) / 2
	at := w0.Add(half)
	before, after := fmt.Sprintf("%dms", half.Milliseconds()), fmt.Sprintf("%dms", (w1.Sub(w0)-half).Milliseconds())

	// The active devices of the window: the one sender.
	var active struct {
		Total   int
		Devices []struct{ ID string }
	}
	p.getJSON("/api/devices?hidden=exclude&active_from="+w0.Format(time.RFC3339Nano)+"&active_to="+w1.Format(time.RFC3339Nano), &active)
	if active.Total != 1 || active.Devices[0].ID != "127.0.0.1" {
		t.Fatalf("active devices %+v", active)
	}

	// The API's bundle.
	body := map[string]any{"kind": "bundle", "at": at.Format(time.RFC3339Nano), "before": before, "after": after, "active_devices": true}
	code, b := p.do("POST", "/api/exports", body)
	if code != 202 {
		t.Fatalf("create %d %s", code, b)
	}
	var created struct{ ID string }
	json.Unmarshal(b, &created)
	var info struct {
		State   string
		Lines   int64
		Filters struct {
			Kind  string
			Types []string
		}
	}
	waitFor(t, "the bundle", 30*time.Second, func() bool {
		p.getJSON("/api/exports/"+created.ID, &info)
		return info.State == "ready" || info.State == "failed"
	})
	if info.State != "ready" || info.Filters.Kind != "bundle" || strings.Join(info.Filters.Types, ",") != "syslog,trap" {
		t.Fatalf("bundle %+v", info)
	}
	resp, err := http.Get(p.base + "/api/exports/" + created.ID + "/download")
	if err != nil {
		t.Fatal(err)
	}
	apiZip, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(resp.Header.Get("Content-Disposition"), `filename="woodshed-bundle-`) {
		t.Errorf("download name %q", resp.Header.Get("Content-Disposition"))
	}
	apiPath := filepath.Join(dir, "api.zip")
	os.WriteFile(apiPath, apiZip, 0o600)

	// The CLI's bundle, beside the running service.
	cliPath := filepath.Join(dir, "cli.zip")
	out, err := exec.Command(binary, "bundle", "--data", dataDir, "--at", at.Format(time.RFC3339Nano), "--before", before,
		"--after", after, "--out", cliPath).CombinedOutput()
	if err != nil {
		t.Fatalf("woodshed bundle: %v\n%s", err, out)
	}
	if !strings.HasPrefix(string(out), cliPath+"\n") || !strings.Contains(string(out), "127.0.0.1: syslog 600, SNMP traps 41, reboots 1,") {
		t.Errorf("CLI output:\n%s", out)
	}

	apiFiles, apiNames := unzipAll(t, apiPath)
	cliFiles, cliNames := unzipAll(t, cliPath)
	if strings.Join(apiNames, ",") != strings.Join(cliNames, ",") {
		t.Fatalf("entries differ:\n api %v\n cli %v", apiNames, cliNames)
	}
	for _, n := range apiNames {
		a, c := apiFiles[n], cliFiles[n]
		if n == "manifest.json" {
			a, c = dropKeys(t, a, "id", "exported_at"), dropKeys(t, c, "id", "exported_at")
		}
		if !bytes.Equal(a, c) {
			t.Errorf("%s differs between the API's zip and the CLI's", n)
		}
	}

	for _, zf := range []struct {
		name  string
		files map[string][]byte
	}{{"api", apiFiles}, {"cli", cliFiles}} {
		files := zf.files
		// Every file's SHA-256 and line count is the manifest's.
		var man struct {
			Kind  string
			Files []struct {
				Path   string
				Lines  int64
				SHA256 string
			}
			Summary []struct {
				Types map[string]struct {
					Lines int64 `json:"lines"`
				}
				Reboots []struct{ Source string }
			}
		}
		if err := json.Unmarshal(files["manifest.json"], &man); err != nil {
			t.Fatal(err)
		}
		var trapFiles int
		for _, mf := range man.Files {
			sum := sha256.Sum256(files[mf.Path])
			if hex.EncodeToString(sum[:]) != mf.SHA256 || int64(bytes.Count(files[mf.Path], []byte("\n"))) != mf.Lines {
				t.Errorf("%s %s: doesn't match the manifest", zf.name, mf.Path)
			}
			if strings.HasPrefix(mf.Path, "traps/") {
				trapFiles++
				if !bytes.Contains(files[mf.Path], []byte(" pdu=trap ")) {
					t.Errorf("%s: no trap records", mf.Path)
				}
			}
		}
		if len(man.Files) != len(files)-3 || trapFiles == 0 {
			t.Errorf("%s: %d files in the manifest, %d in the zip, %d of traps", zf.name, len(man.Files), len(files), trapFiles)
		}
		if man.Kind != "bundle" || len(man.Summary) != 1 || man.Summary[0].Types["syslog"].Lines != 2*perProto ||
			man.Summary[0].Types["trap"].Lines != traps+1 || len(man.Summary[0].Reboots) != 1 || man.Summary[0].Reboots[0].Source != "coldStart trap" {
			t.Errorf("%s summary %+v", zf.name, man.Summary)
		}
		readme := string(files["README.txt"])
		for _, s := range []string{"\n127.0.0.1\n  Syslog       600 messages, first ", "\n  SNMP traps   41: ", "coldStart 1",
			"\n  Reboots      1: ", " (coldStart trap)\n", "\n  Gaps         none of 1 s or more (Woodshed and its listeners were up the whole window)\n"} {
			if !strings.Contains(readme, s) {
				t.Errorf("%s README lacks %q:\n%s", zf.name, s, readme)
			}
		}
		for n, b := range files {
			if bytes.Contains(b, []byte("e2e-bundle-community")) {
				t.Errorf("%s: %s holds the community", zf.name, n)
			}
		}
	}

	// Unzipped as a data folder (traps/<dev>/ back under logs/<dev>/traps/),
	// verifyseq finds the middle phase exactly once and nothing of the others.
	mirror := filepath.Join(dir, "unzipped")
	for n, b := range cliFiles {
		var dst string
		switch {
		case strings.HasPrefix(n, "logs/"):
			dst = filepath.Join(mirror, filepath.FromSlash(n))
		case strings.HasPrefix(n, "traps/"):
			parts := strings.SplitN(n, "/", 3)
			dst = filepath.Join(mirror, "logs", parts[1], "traps", parts[2])
		default:
			continue
		}
		os.MkdirAll(filepath.Dir(dst), 0o700)
		if err := os.WriteFile(dst, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("verifyseq on the unzipped bundle:")
	runVerify(t, verifyseq, mirror, middleS, 2*perProto, 0)
	runVerify(t, verifyseq, mirror, middleT, traps+1, 0)
	for _, r := range []struct {
		run string
		n   int
	}{{beforeS, 2 * perProto}, {afterS, 2 * perProto}, {beforeT, traps}, {afterT, traps}} {
		runVerify(t, verifyseq, mirror, r.run, r.n, r.n) // every one missing: nothing from outside the window
	}

	// A window with nothing in it: exit 1, no zip.
	empty := filepath.Join(dir, "empty.zip")
	cmd := exec.Command(binary, "bundle", "--data", dataDir, "--at", w0.Add(-time.Hour).Format(time.RFC3339), "--before", "1m",
		"--after", "1m", "--out", empty)
	if out, err := cmd.CombinedOutput(); cmd.ProcessState.ExitCode() != 1 || !strings.Contains(string(out), "No device stored anything") {
		t.Errorf("empty window: %v %s", err, out)
	}
	if _, err := os.Stat(empty); err == nil {
		t.Error("an empty window wrote a zip")
	}
}

func freeUDPPort(t *testing.T, avoid ...int) int {
	t.Helper()
	for range 100 {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := pc.LocalAddr().(*net.UDPAddr).Port
		pc.Close()
		ok := port != 162 && port != 514 && port != 8514
		for _, a := range avoid {
			ok = ok && port != a
		}
		if ok {
			return port
		}
	}
	t.Fatal("no free UDP port")
	return 0
}

// buildVerifyseq builds scripts/verifyseq once per test.
func buildVerifyseq(t *testing.T) string {
	t.Helper()
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "verifyseq"+exeSuffix())
	cmd := exec.Command(goTool(), "build", "-o", bin, "./scripts/verifyseq")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building verifyseq: %v\n%s", err, out)
	}
	return bin
}

func runVerify(t *testing.T, bin, data, run string, n, missing int, extra ...string) {
	t.Helper()
	args := append([]string{"-data", data, "-run", run, "-n", fmt.Sprint(n), "-missing-ok", fmt.Sprint(missing)}, extra...)
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("verifyseq %v: %v\n%s", args, err, out)
	}
	t.Logf("  %s", strings.TrimSpace(string(out)))
}

func unzipAll(t *testing.T, path string) (map[string][]byte, []string) {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	out := map[string][]byte{}
	var names []string
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		out[f.Name] = b
		names = append(names, f.Name)
	}
	return out, names
}

func dropKeys(t *testing.T, b []byte, keys ...string) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		delete(m, k)
	}
	out, _ := json.Marshal(m)
	return out
}
