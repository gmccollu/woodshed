//go:build !windows

package fwrule

import "errors"

// listRules: there's no Windows firewall to read here.
func listRules(...string) ([]WinRule, error) {
	return nil, errors.New("fwrule: the Windows firewall can only be read on Windows")
}
