package geosite

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

type Matcher struct {
	exact    map[string]struct{}
	suffix   map[string]struct{}
	keywords []string
	regex    []*regexp.Regexp
}

func (m *Matcher) Match(name string) bool {
	name = normalize(name)
	if _, ok := m.exact[name]; ok {
		return true
	}
	for suffix := name; suffix != ""; {
		if _, ok := m.suffix[suffix]; ok {
			return true
		}
		_, suffix, _ = strings.Cut(suffix, ".")
	}
	for _, value := range m.keywords {
		if strings.Contains(name, value) {
			return true
		}
	}
	for _, value := range m.regex {
		if value.MatchString(name) {
			return true
		}
	}
	return false
}

func normalize(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) }

func Load(path string, categories []string) (map[string]*Matcher, error) {
	if len(categories) == 0 {
		return nil, nil
	}
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	return parse(data, categories)
}

func Validate(path string) error {
	data, err := readFile(path)
	if err != nil {
		return err
	}
	_, err = parse(data, nil)
	return err
}

func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	const limit = 64 << 20
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("invalid GEOSITE DAT file size or type")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, errors.New("GEOSITE DAT exceeds size limit")
	}
	return data, nil
}

func parse(data []byte, categories []string) (map[string]*Matcher, error) {
	selected := make(map[string]*Matcher, len(categories))
	entries := 0
	for _, category := range categories {
		selected[strings.ToUpper(category)] = nil
	}
	err := walk(data, func(f field) error {
		if f.number != 1 {
			return nil
		}
		if f.kind != protowire.BytesType {
			return errors.New("invalid GEOSITE entry type")
		}
		var code string
		if err := walk(f.data, func(x field) error {
			if x.number == 1 && x.kind == protowire.BytesType {
				code = strings.ToUpper(string(x.data))
			}
			return nil
		}); err != nil {
			return err
		}
		if code == "" {
			return errors.New("GEOSITE entry has no category")
		}
		entries++
		current, ok := selected[code]
		if !ok {
			return nil
		}
		if current != nil {
			return fmt.Errorf("duplicate GEOSITE category %q", code)
		}
		matcher := &Matcher{exact: make(map[string]struct{}), suffix: make(map[string]struct{})}
		err := walk(f.data, func(x field) error {
			if x.number != 2 {
				return nil
			}
			if x.kind != protowire.BytesType {
				return errors.New("invalid GEOSITE domain type")
			}
			return matcher.add(x.data)
		})
		if err != nil {
			return fmt.Errorf("GEOSITE %s: %w", code, err)
		}
		selected[code] = matcher
		return nil
	})
	if err != nil {
		return nil, err
	}
	if entries == 0 {
		return nil, errors.New("GEOSITE DAT contains no categories")
	}
	for code, matcher := range selected {
		if matcher == nil {
			return nil, fmt.Errorf("GEOSITE category %q was not found", code)
		}
	}
	return selected, nil
}

func (m *Matcher) add(data []byte) error {
	var kind uint64
	var value string
	if err := walk(data, func(f field) error {
		switch {
		case f.number == 1 && f.kind == protowire.VarintType:
			kind = f.integer
		case f.number == 2 && f.kind == protowire.BytesType:
			value = string(f.data)
		}
		return nil
	}); err != nil {
		return err
	}
	if value == "" || len(value) > 4096 {
		return errors.New("invalid GEOSITE domain value")
	}
	switch kind {
	case 0:
		m.keywords = append(m.keywords, strings.ToLower(value))
	case 1:
		expression, err := regexp.Compile(value)
		if err != nil {
			return err
		}
		m.regex = append(m.regex, expression)
	case 2:
		m.suffix[normalize(value)] = struct{}{}
	case 3:
		m.exact[normalize(value)] = struct{}{}
	default:
		return fmt.Errorf("unsupported GEOSITE match type %d", kind)
	}
	return nil
}

type field struct {
	number  protowire.Number
	kind    protowire.Type
	data    []byte
	integer uint64
}

func walk(data []byte, visit func(field) error) error {
	for len(data) > 0 {
		num, kind, n := protowire.ConsumeTag(data)
		if n < 0 {
			return protowire.ParseError(n)
		}
		data = data[n:]
		f := field{number: num, kind: kind}
		switch kind {
		case protowire.VarintType:
			f.integer, n = protowire.ConsumeVarint(data)
		case protowire.BytesType:
			f.data, n = protowire.ConsumeBytes(data)
		default:
			n = protowire.ConsumeFieldValue(num, kind, data)
		}
		if n < 0 {
			return protowire.ParseError(n)
		}
		if err := visit(f); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}
