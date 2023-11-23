//go:build client_test
// +build client_test

package main

import "testing"

func TestResolveIpv4(t *testing.T) {
	t.Parallel()

	ResolveIpv4("127.0.0.1:53", "www.bilibili.com")
}
