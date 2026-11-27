package updater

import (
	"fmt"
	"strconv"
	"strings"
)

type SemVer struct {
	Major      int
	Minor      int
	Patch      int
	Prerelease string
}

func ParseVersion(raw string) (SemVer, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return SemVer{}, fmt.Errorf("empty version")
	}
	s = strings.TrimPrefix(s, "v")
	if idx := strings.IndexByte(s, '+'); idx >= 0 {
		s = s[:idx]
	}
	var pre string
	if idx := strings.IndexByte(s, '-'); idx >= 0 {
		pre = s[idx+1:]
		s = s[:idx]
		if pre == "" {
			return SemVer{}, fmt.Errorf("empty prerelease in %q", raw)
		}
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return SemVer{}, fmt.Errorf("invalid semver %q", raw)
	}
	nums := make([]int, 3)
	for i, p := range parts {
		if p == "" {
			return SemVer{}, fmt.Errorf("invalid semver %q", raw)
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return SemVer{}, fmt.Errorf("invalid semver %q", raw)
		}
		nums[i] = n
	}
	return SemVer{Major: nums[0], Minor: nums[1], Patch: nums[2], Prerelease: pre}, nil
}

func (v SemVer) IsPrerelease() bool {
	return v.Prerelease != ""
}

func IsDevVersion(raw string) bool {
	s := strings.ToLower(strings.TrimSpace(raw))
	return s == "" || s == "dev" || strings.HasSuffix(s, "-dev") || strings.Contains(s, "-m")
}

// CompareVersion returns -1 if a < b, 0 if a == b, and 1 if a > b.
func CompareVersion(a, b string) (int, error) {
	va, err := ParseVersion(a)
	if err != nil {
		return 0, err
	}
	vb, err := ParseVersion(b)
	if err != nil {
		return 0, err
	}
	if va.Major != vb.Major {
		return cmpInt(va.Major, vb.Major), nil
	}
	if va.Minor != vb.Minor {
		return cmpInt(va.Minor, vb.Minor), nil
	}
	if va.Patch != vb.Patch {
		return cmpInt(va.Patch, vb.Patch), nil
	}
	return comparePrerelease(va.Prerelease, vb.Prerelease), nil
}

// NeedsUpdate returns true if target is newer than current, or if current is a dev build.
func NeedsUpdate(current, target string, force bool) (bool, error) {
	if _, err := ParseVersion(target); err != nil {
		return false, err
	}
	if force || IsDevVersion(current) {
		return true, nil
	}
	cmp, err := CompareVersion(current, target)
	if err != nil {
		return true, nil
	}
	return cmp < 0, nil
}

func comparePrerelease(a, b string) int {
	if a == b {
		return 0
	}
	if a == "" {
		return 1
	}
	if b == "" {
		return -1
	}
	pa := strings.Split(a, ".")
	pb := strings.Split(b, ".")
	n := len(pa)
	if len(pb) < n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		if pa[i] == pb[i] {
			continue
		}
		na, errA := strconv.Atoi(pa[i])
		nb, errB := strconv.Atoi(pb[i])
		switch {
		case errA == nil && errB == nil:
			return cmpInt(na, nb)
		case errA == nil:
			return -1
		case errB == nil:
			return 1
		default:
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return cmpInt(len(pa), len(pb))
}

func cmpInt(a, b int) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
