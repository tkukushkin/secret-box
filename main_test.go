package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/tkukushkin/secret-box/internal/secretbox"
)

func TestAuthDurationFlags(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    time.Duration
		wantErr bool
	}{
		{name: "default", args: nil, want: secretbox.DefaultAuthDuration},
		{name: "once", args: []string{"--once"}, want: 0},
		{name: "custom duration", args: []string{"--duration", "1h"}, want: time.Hour},
		{name: "zero duration", args: []string{"--duration", "0"}, want: 0},
		{name: "negative duration", args: []string{"--duration", "-1s"}, wantErr: true},
		{name: "sub-second duration", args: []string{"--duration", "500ms"}, wantErr: true},
		{name: "fractional seconds", args: []string{"--duration", "1500ms"}, wantErr: true},
		{name: "once and duration", args: []string{"--once", "--duration", "1m"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got time.Duration
			cmd := &cobra.Command{Use: "test", SilenceErrors: true, SilenceUsage: true}
			authDuration := authDurationFlags(cmd)
			cmd.RunE = func(cmd *cobra.Command, args []string) error {
				var err error
				got, err = authDuration()
				return err
			}
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got duration %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("duration = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPrintAccessLog(t *testing.T) {
	at := func(hour, min int) int64 { return time.Date(2026, 1, 2, hour, min, 0, 0, time.UTC).Unix() }
	terminal := secretbox.CallerIdentity{ID: "signed:TEAM:com.apple.Terminal", DisplayName: "Terminal"}
	entries := []secretbox.AccessLogEntry{
		{Timestamp: at(10, 5), SecretName: "api-key", Caller: terminal, Auth: secretbox.AuthTouchID},
		{Timestamp: at(10, 1), SecretName: "db-pass", Caller: terminal, Auth: secretbox.AuthCached, ExpiresAt: at(11, 0)},
		{Timestamp: at(10, 0), SecretName: "db-pass", Caller: terminal, Auth: secretbox.AuthTouchID, ExpiresAt: at(11, 0)},
	}

	var buf bytes.Buffer
	printAccessLog(&buf, entries, time.UTC)

	want := "" +
		"TIME                 SECRET   APP       AUTH      CACHED UNTIL         CALLER ID\n" +
		"2026-01-02 10:05:00  api-key  Terminal  Touch ID  not cached           signed:TEAM:com.apple.Terminal\n" +
		"2026-01-02 10:01:00  db-pass  Terminal  cached    2026-01-02 11:00:00  signed:TEAM:com.apple.Terminal\n" +
		"2026-01-02 10:00:00  db-pass  Terminal  Touch ID  2026-01-02 11:00:00  signed:TEAM:com.apple.Terminal\n"
	if buf.String() != want {
		t.Errorf("output:\n%s\nwant:\n%s", buf.String(), want)
	}
}

func TestPrintAccessLogEscapesNonPrintable(t *testing.T) {
	entries := []secretbox.AccessLogEntry{{
		SecretName: "a\nb\tc",
		Caller:     secretbox.CallerIdentity{ID: "path:‮abc", DisplayName: "evil\x1b[2J"},
		Auth:       secretbox.AuthTouchID,
	}}

	var buf bytes.Buffer
	printAccessLog(&buf, entries, time.UTC)

	want := "" +
		"TIME                 SECRET   APP          AUTH      CACHED UNTIL  CALLER ID\n" +
		"1970-01-01 00:00:00  a\\nb\\tc  evil\\x1b[2J  Touch ID  not cached    path:\\u202eabc\n"
	if buf.String() != want {
		t.Errorf("output:\n%s\nwant:\n%s", buf.String(), want)
	}
}

func TestPrintAccessLogEmpty(t *testing.T) {
	var buf bytes.Buffer
	printAccessLog(&buf, nil, time.UTC)
	if buf.String() != "No secret reads recorded.\n" {
		t.Errorf("output = %q", buf.String())
	}
}
