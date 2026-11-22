// 文件职责：覆盖静默时间窗口解析（同日、跨午夜、边界与畸形输入）的表驱动单元测试。
package notify_test

import (
	"testing"
	"time"

	"singctl/internal/notify"
)

func atHM(h, m int) time.Time {
	return time.Date(2026, 11, 23, h, m, 0, 0, time.Local)
}

func TestParseQuietHours(t *testing.T) {
	tests := []struct {
		name        string
		spec        string
		wantEnabled bool
		wantErr     bool
	}{
		{name: "empty_disabled", spec: "", wantEnabled: false, wantErr: false},
		{name: "whitespace_disabled", spec: "   ", wantEnabled: false, wantErr: false},
		{name: "cross_midnight", spec: "23:00-07:30", wantEnabled: true, wantErr: false},
		{name: "same_day", spec: "12:00-14:00", wantEnabled: true, wantErr: false},
		{name: "with_surrounding_spaces", spec: " 22:30 - 06:00 ", wantEnabled: true, wantErr: false},
		{name: "full_boundary_minutes", spec: "00:00-23:59", wantEnabled: true, wantErr: false},
		{name: "equal_start_end_rejected", spec: "12:00-12:00", wantErr: true},
		{name: "invalid_hour_24", spec: "24:00-07:00", wantErr: true},
		{name: "invalid_minute_60", spec: "23:60-07:00", wantErr: true},
		{name: "negative_hour", spec: "-1:00-07:00", wantErr: true},
		{name: "missing_dash", spec: "23:00", wantErr: true},
		{name: "extra_dash", spec: "23:00-01:00-07:00", wantErr: true},
		{name: "non_numeric", spec: "aa:bb-cc:dd", wantErr: true},
		{name: "control_chars", spec: "23:00-07:30\n", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, err := notify.ParseQuietHours(tc.spec)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseQuietHours(%q) expected error, got %+v", tc.spec, w)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseQuietHours(%q) unexpected error: %v", tc.spec, err)
			}
			if w.Enabled != tc.wantEnabled {
				t.Fatalf("ParseQuietHours(%q).Enabled = %v, want %v", tc.spec, w.Enabled, tc.wantEnabled)
			}
		})
	}
}

func TestQuietWindowIsInQuietHours(t *testing.T) {
	t.Run("disabled_always_false", func(t *testing.T) {
		w, err := notify.ParseQuietHours("")
		if err != nil {
			t.Fatal(err)
		}
		for _, ts := range []time.Time{atHM(0, 0), atHM(12, 30), atHM(23, 59)} {
			if w.IsInQuietHours(ts) {
				t.Fatalf("disabled window should return false at %v", ts)
			}
		}
	})

	t.Run("same_day_12_00_to_14_00", func(t *testing.T) {
		w, err := notify.ParseQuietHours("12:00-14:00")
		if err != nil {
			t.Fatal(err)
		}
		cases := []struct {
			h, m int
			want bool
		}{
			{11, 59, false},
			{12, 0, true},
			{13, 0, true},
			{13, 59, true},
			{14, 0, false},
			{23, 0, false},
		}
		for _, tc := range cases {
			if got := w.IsInQuietHours(atHM(tc.h, tc.m)); got != tc.want {
				t.Fatalf("12:00-14:00 at %02d:%02d = %v, want %v", tc.h, tc.m, got, tc.want)
			}
		}
	})

	t.Run("cross_midnight_23_00_to_07_30", func(t *testing.T) {
		w, err := notify.ParseQuietHours("23:00-07:30")
		if err != nil {
			t.Fatal(err)
		}
		cases := []struct {
			h, m int
			want bool
		}{
			{22, 59, false},
			{23, 0, true},
			{23, 59, true},
			{0, 0, true},
			{3, 15, true},
			{7, 29, true},
			{7, 30, false},
			{12, 0, false},
		}
		for _, tc := range cases {
			if got := w.IsInQuietHours(atHM(tc.h, tc.m)); got != tc.want {
				t.Fatalf("23:00-07:30 at %02d:%02d = %v, want %v", tc.h, tc.m, got, tc.want)
			}
		}
	})
}
