package main

import (
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
