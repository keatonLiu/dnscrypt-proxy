//go:build client_test
// +build client_test

package main

import (
	"encoding/json"
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
		rtt, _ := strconv.ParseFloat(record[4], 64)
		variation, _ := strconv.ParseFloat(record[5], 64)
		fmt.Println(server, relay, sendTime, arrivalTime, rtt, variation)
	}

}

func TestParseJson(t *testing.T) {
	text := "{\"recvTime\": 1702262756258, \"recvIp\": \"149.28.101.119\"}"
	var unquoted string
	err := json.Unmarshal([]byte(text), &unquoted)
	if err != nil {
		panic(err)
	}
	fmt.Println(unquoted)
}
