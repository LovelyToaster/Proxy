//go:build windows

package updater

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type mockWindowsOps struct {
	elevated       bool
	running        bool
	stopErr        error
	startErr       error
	startCalls     int
	failFirstStart bool
	unloadErr      error
	unloaded       bool
	regVersion     string
}

func (m *mockWindowsOps) isElevated() bool                { return m.elevated }
func (m *mockWindowsOps) isServiceRunning() (bool, error) { return m.running, nil }
func (m *mockWindowsOps) stopService(context.Context) error {
	return m.stopErr
}
func (m *mockWindowsOps) startService(context.Context) error {
	m.startCalls++
	if m.failFirstStart && m.startCalls == 1 {
		return errors.New("new service failed to start")
	}
	return m.startErr
}
func (m *mockWindowsOps) unloadWinDivert(context.Context) error {
	m.unloaded = true
	return m.unloadErr
}
func (m *mockWindowsOps) updateUninstallVersion(v string) {
	m.regVersion = v
}

func TestApplyWindowsSuccessWithDriverAndGeo(t *testing.T) {
	installDir := t.TempDir()
	cfgDir := t.TempDir()
	stageDir := t.TempDir()

	exePath := filepath.Join(installDir, "proxy.exe")
	_ = os.WriteFile(exePath, []byte("old-exe"), 0755)
	_ = os.WriteFile(filepath.Join(installDir, "WinDivert.dll"), []byte("old-dll"), 0644)
	_ = os.WriteFile(filepath.Join(installDir, "WinDivert64.sys"), []byte("old-sys"), 0644)

	newExe := filepath.Join(stageDir, "proxy.exe")
	newDLL := filepath.Join(stageDir, "WinDivert.dll")
	newSYS := filepath.Join(stageDir, "WinDivert64.sys")
	newGeo := filepath.Join(stageDir, "geoip.dat")
	_ = os.WriteFile(newExe, []byte("new-exe"), 0755)
	_ = os.WriteFile(newDLL, []byte("new-dll"), 0644)
	_ = os.WriteFile(newSYS, []byte("new-sys"), 0644)
	_ = os.WriteFile(newGeo, []byte("geoip-v2"), 0644)

	ops := &mockWindowsOps{elevated: true, running: true}
	staged := &StagedUpdate{
		Version:            "v0.2.0",
		BinaryPath:         newExe,
		DriverUpdateNeeded: true,
		DriverFiles: map[string]string{
			"WinDivert.dll":   newDLL,
			"WinDivert64.sys": newSYS,
		},
		GeoFiles: map[string]string{
			"geoip.dat": newGeo,
		},
	}

	res, err := applyWindows(context.Background(), staged, ApplyOptions{
		InstallDir:     installDir,
		ExecutablePath: exePath,
		ConfigPath:     filepath.Join(cfgDir, "proxy.yaml"),
	}, ops)
	if err != nil {
		t.Fatalf("applyWindows failed: %v", err)
	}
	if !res.DriverUpdated || !res.ServiceRestarted || !ops.unloaded || ops.regVersion != "v0.2.0" {
		t.Fatalf("unexpected apply result: %+v, ops=%+v", res, ops)
	}
	gotExe, _ := os.ReadFile(exePath)
	gotDLL, _ := os.ReadFile(filepath.Join(installDir, "WinDivert.dll"))
	gotGeo, _ := os.ReadFile(filepath.Join(cfgDir, "data", "geoip.dat"))
	if string(gotExe) != "new-exe" || string(gotDLL) != "new-dll" || string(gotGeo) != "geoip-v2" {
		t.Fatalf("unexpected replaced content: exe=%q dll=%q geo=%q", gotExe, gotDLL, gotGeo)
	}
}

func TestApplyWindowsRollbackOnStartFailure(t *testing.T) {
	installDir := t.TempDir()
	stageDir := t.TempDir()

	exePath := filepath.Join(installDir, "proxy.exe")
	_ = os.WriteFile(exePath, []byte("old-exe"), 0755)
	newExe := filepath.Join(stageDir, "proxy.exe")
	_ = os.WriteFile(newExe, []byte("broken-exe"), 0755)

	ops := &mockWindowsOps{elevated: true, running: true, failFirstStart: true}
	staged := &StagedUpdate{Version: "v0.2.0", BinaryPath: newExe}

	_, err := applyWindows(context.Background(), staged, ApplyOptions{
		InstallDir:     installDir,
		ExecutablePath: exePath,
	}, ops)
	if err == nil {
		t.Fatal("expected error when updated service fails to start")
	}
	gotExe, _ := os.ReadFile(exePath)
	if string(gotExe) != "old-exe" {
		t.Fatalf("expected rollback to old-exe, got %q", gotExe)
	}
	if ops.startCalls != 2 {
		t.Fatalf("expected second start call during rollback, got %d", ops.startCalls)
	}
}
