package servicehost

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedLinuxUnit(t *testing.T) {
	r := linuxRegistration{Binary: "/opt/proxy app/$binary%/proxy", Config: "/etc/proxy settings/proxy.yaml", Runtime: "/var/lib/proxyd"}
	data := renderLinuxUnit(r, true)
	for _, want := range []string{`User=proxyd`, `Type=notify`, `KillMode=mixed`, `AmbientCapabilities=CAP_NET_ADMIN`, `--service-run`, `$$binary%%`, `ExecStopPost=`} {
		if !strings.Contains(data, want) {
			t.Fatalf("missing %q:\n%s", want, data)
		}
	}
	got, err := parseLinuxRegistration([]byte(data))
	if err != nil || got != r {
		t.Fatalf("metadata: %+v %v", got, err)
	}
	if err := sameLinuxBinary(r, "/another/proxy"); err == nil {
		t.Fatal("another executable accepted")
	}
	if err := sameLinuxBinary(r, r.Binary); err != nil {
		t.Fatal(err)
	}
	plain := renderLinuxUnit(r, false)
	if strings.Contains(plain, "CAP_NET_ADMIN") {
		t.Fatal("capture-off service has network capabilities")
	}
	if unitQuote("/a$b%") != `"/a$b%%"` || execUnitQuote("/a$b%") != `"/a$$b%%"` {
		t.Fatal("unit/exec escaping mixed")
	}
}

func TestRefuseForeignLinuxRegistration(t *testing.T) {
	for _, data := range []string{"[Service]\nExecStart=/other/proxy\n", linuxOwner + `{}`, linuxOwner + `{"Binary":"relative","Config":"/a","Runtime":"/b"}`, linuxOwner + "broken"} {
		if _, err := parseLinuxRegistration([]byte(data)); err == nil {
			t.Fatalf("invalid registration accepted: %s", data)
		}
	}
	r := linuxRegistration{Binary: "/a\nb", Config: "/a", Runtime: "/b"}
	encoded, _ := json.Marshal(r)
	if _, err := parseLinuxRegistration(append([]byte(linuxOwner), encoded...)); err == nil {
		t.Fatal("newline path accepted")
	}
}

func TestLinuxRuntimeRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	link := filepath.Join(root, "link")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := prepareLinuxRuntime(link, os.Geteuid(), os.Getegid()); err == nil {
		t.Fatal("symlink runtime accepted")
	}
	if err := prepareLinuxRuntime(real, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
}
