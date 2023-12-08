//go:build client_test
// +build client_test

package main

import (
	"fmt"
	"strconv"
	"testing"
)

func TestResolveIpv4(t *testing.T) {
	t.Parallel()

	ResolveIpv4("127.0.0.1:53", "www.bilibili.com")
}

func TestLoadCsv(t *testing.T) {
	t.Parallel()

	records := readCsvFile("../prepared_list.csv")
	for _, record := range records[1:] {
		server := record[0]
		relay := record[1]
		sendTime, _ := strconv.ParseFloat(record[2], 64)
		arrivalTime, _ := strconv.ParseFloat(record[3], 64)
		fmt.Println(server, relay, sendTime, arrivalTime)
	}

}
