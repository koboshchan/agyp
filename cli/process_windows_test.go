//go:build windows

package main

import (
	"errors"
	"golang.org/x/sys/windows"
	"testing"
)

func TestThreadOwnerFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		owner   uint32
		err     error
		wantErr bool
	}{
		{"same", 123, nil, false},
		{"recycled", 456, nil, true},
		{"zero", 0, nil, true},
		{"queryDenied", 0, errors.New("denied"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyThreadOwner(windows.Handle(7), 123, func(h windows.Handle) (uint32, error) {
				if h != 7 {
					t.Fatal("wrong handle")
				}
				return tc.owner, tc.err
			})
			if (err != nil) != tc.wantErr {
				t.Fatalf("got %v", err)
			}
		})
	}
}
