//go:build linux

package updater

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type mockLinuxOps struct {
	root           bool
	active         bool
	restartCalls   int
	failFirstStart bool
	installedDeb   string
}

func (m *mockLinuxOps) isRoot() bool                         { return m.root }
func (m *mockLinuxOps) isServiceActive(context.Context) bool { return m.active }
func (m *mockLinuxOps) restartService(context.Context) error {
	m.restartCalls++
	if m.failFirstStart && m.restartCalls == 1 {
		return errors.New("systemd unit failed")
	}
	return nil
}
func (m *mockLinuxOps) installDeb(_ context.Context, debPath string) error {
	m.installedDeb = debPath
	return nil
}

func TestApplyLinuxBinaryAndRollback(t *testing.T) {
	installDir := t.TempDir()
	stageDir := t.TempDir()
	exePath := filepath.Join(installDir, "proxy")
	_ = os.WriteFile(exePath, []byte("old-linux-bin"), 0755)
	newBin := filepath.Join(stageDir, "proxy")
	_ = os.WriteFile(newBin, []byte("new-linux-bin"), 0755)

	ops := &mockLinuxOps{root: true, active: true}
	res, err := applyLinux(context.Background(), &StagedUpdate{Version: "v0.2.0", BinaryPath: newBin}, ApplyOptions{
		InstallDir:     installDir,
		ExecutablePath: exePath,
	}, ops)
	if err != nil {
		t.Fatalf("applyLinux failed: %v", err)
	}
	if !res.ServiceRestarted || res.Method != "binary" {
		t.Fatalf("unexpected linux result: %+v", res)
	}
	got, _ := os.ReadFile(exePath)
	if string(got) != "new-linux-bin" {
		t.Fatalf("expected new-linux-bin, got %q", got)
	}

	// Verify rollback on restart failure.
	badBin := filepath.Join(stageDir, "proxy-bad")
	_ = os.WriteFile(badBin, []byte("bad-linux-bin"), 0755)
	opsFail := &mockLinuxOps{root: true, active: true, failFirstStart: true}
	if _, err := applyLinux(context.Background(), &StagedUpdate{Version: "v0.3.0", BinaryPath: badBin}, ApplyOptions{
		InstallDir:     installDir,
		ExecutablePath: exePath,
	}, opsFail); err == nil {
		t.Fatal("expected rollback error on restart failure")
	}
	gotAfter, _ := os.ReadFile(exePath)
	if string(gotAfter) != "new-linux-bin" {
		t.Fatalf("expected rollback to new-linux-bin, got %q", gotAfter)
	}
}

func TestApplyLinuxDebMode(t *testing.T) {
	ops := &mockLinuxOps{root: true, active: true}
	res, err := applyLinux(context.Background(), &StagedUpdate{Version: "v0.2.0", DebPath: "/tmp/proxy_0.2.0_amd64.deb"}, ApplyOptions{
		InstallDir:     t.TempDir(),
		ExecutablePath: "/usr/bin/proxy",
	}, ops)
	if err != nil {
		t.Fatalf("applyLinux deb failed: %v", err)
	}
	if res.Method != "deb" || ops.installedDeb != "/tmp/proxy_0.2.0_amd64.deb" {
		t.Fatalf("unexpected deb apply result: %+v, ops=%+v", res, ops)
	}
}
