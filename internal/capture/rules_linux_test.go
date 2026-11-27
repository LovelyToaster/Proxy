package capture

import "testing"

func TestSelectRulePriority(t *testing.T) {
	tests := []struct {
		name     string
		ruleSets [][]map[string]any
		want     string
		wantErr  bool
	}{
		{
			name: "standard linux keeps default priority",
			ruleSets: [][]map[string]any{
				{
					{"priority": float64(0), "table": "255"},
					{"priority": float64(32766), "table": "254"},
					{"priority": float64(32767), "table": "253"},
				},
				{
					{"priority": float64(0), "table": "255"},
					{"priority": float64(32766), "table": "254"},
				},
			},
			want: "11000",
		},
		{
			name: "fnOS source routing at priority 10 selects priority 9",
			ruleSets: [][]map[string]any{
				{
					{"priority": float64(0), "table": "255"},
					{"priority": float64(10), "src": "10.0.0.13", "table": "10"},
					{"priority": float64(32766), "table": "254"},
					{"priority": float64(32767), "table": "253"},
				},
				{
					{"priority": float64(0), "table": "255"},
					{"priority": float64(10), "src": "2409:8a31::1", "table": "10"},
					{"priority": float64(32766), "table": "254"},
				},
			},
			want: "9",
		},
		{
			name: "dual stack picks priority before lowest non-local rule across families",
			ruleSets: [][]map[string]any{
				{
					{"priority": float64(0), "table": "local"},
					{"priority": float64(25), "src": "10.0.0.13", "table": "10"},
					{"priority": float64(32766), "table": "main"},
				},
				{
					{"priority": float64(0), "table": "local"},
					{"priority": float64(32766), "table": "main"},
				},
			},
			want: "24",
		},
		{
			name: "existing rule at default priority steps down",
			ruleSets: [][]map[string]any{
				{
					{"priority": float64(0), "table": "255"},
					{"priority": float64(11000), "src": "192.168.1.0/24", "table": "200"},
					{"priority": float64(32766), "table": "254"},
				},
			},
			want: "10999",
		},
		{
			name: "rejects occupied route table",
			ruleSets: [][]map[string]any{
				{
					{"priority": float64(0), "table": "255"},
					{"priority": float64(50), "table": "100"},
				},
			},
			wantErr: true,
		},
		{
			name: "rejects existing fwmark rule",
			ruleSets: [][]map[string]any{
				{
					{"priority": float64(0), "table": "255"},
					{"priority": float64(50), "fwmark": "0x1", "table": "200"},
				},
			},
			wantErr: true,
		},
		{
			name: "rejects when no priority available before priority 1",
			ruleSets: [][]map[string]any{
				{
					{"priority": float64(0), "table": "255"},
					{"priority": float64(1), "src": "10.0.0.13", "table": "10"},
				},
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectRulePriority(tc.ruleSets...)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got priority %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("selectRulePriority() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestJournalPriorityFallbackAndValidation(t *testing.T) {
	if got := (journal{}).priority(); got != rulePriority {
		t.Fatalf("empty journal priority = %q, want %q", got, rulePriority)
	}
	if got := (journal{RulePriority: "9"}).priority(); got != "9" {
		t.Fatalf("explicit journal priority = %q, want %q", got, "9")
	}
	for _, valid := range []string{"1", "9", "11000"} {
		if !validRulePriority(valid) {
			t.Fatalf("expected %q to be valid", valid)
		}
	}
	for _, invalid := range []string{"", "0", "-1", "abc", "9 --bad"} {
		if validRulePriority(invalid) {
			t.Fatalf("expected %q to be invalid", invalid)
		}
	}
}
