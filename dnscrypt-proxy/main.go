package main

import (
	"bufio"
	crypto_rand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/jedisct1/dlog"
	"github.com/kardianos/service"
	"github.com/miekg/dns"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	AppVersion            = "2.1.5"
	DefaultConfigFileName = "dnscrypt-proxy.toml"
)

type App struct {
	wg    sync.WaitGroup
	quit  chan struct{}
	proxy *Proxy
	flags *ConfigFlags
}

func main() {
	tzErr := TimezoneSetup()
	dlog.Init("dnscrypt-proxy", dlog.SeverityNotice, "DAEMON")
	if tzErr != nil {
		dlog.Warnf("Timezone setup failed: [%v]", tzErr)
	}
	runtime.MemProfileRate = 0

	seed := make([]byte, 8)
	if _, err := crypto_rand.Read(seed); err != nil {
		dlog.Fatal(err)
	}
	rand.Seed(int64(binary.LittleEndian.Uint64(seed)))

	pwd, err := os.Getwd()
	if err != nil {
		dlog.Fatal("Unable to find the path to the current directory")
	}

	svcFlag := flag.String("service", "", fmt.Sprintf("Control the system service: %q", service.ControlAction))
	version := flag.Bool("version", false, "print current proxy version")
	flags := ConfigFlags{}
	flags.Resolve = flag.String("resolve", "", "resolve a DNS name (string can be <name> or <name>,<resolver address>)")
	flags.List = flag.Bool("list", false, "print the list of available resolvers for the enabled filters")
	flags.ListAll = flag.Bool("list-all", false, "print the complete list of available resolvers, ignoring filters")
	flags.IncludeRelays = flag.Bool("include-relays", false, "include the list of available relays in the output of -list and -list-all")
	flags.JSONOutput = flag.Bool("json", false, "output list as JSON")
	flags.Check = flag.Bool("check", false, "check the configuration file and exit")
	flags.ConfigFile = flag.String("config", DefaultConfigFileName, "Path to the configuration file")
	flags.Child = flag.Bool("child", false, "Invokes program as a child process")
	flags.NetprobeTimeoutOverride = flag.Int("netprobe-timeout", 60, "Override the netprobe timeout")
	flags.ShowCerts = flag.Bool("show-certs", false, "print DoH certificate chain hashes")

	flag.Parse()

	if *version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}

	app := &App{
		flags: &flags,
	}

	svcConfig := &service.Config{
		Name:             "dnscrypt-proxy",
		DisplayName:      "DNSCrypt client proxy",
		Description:      "Encrypted/authenticated DNS proxy",
		WorkingDirectory: pwd,
		Arguments:        []string{"-config", *flags.ConfigFile},
	}
	svc, err := service.New(app, svcConfig)
	if err != nil {
		svc = nil
		dlog.Debug(err)
	}

	app.proxy = NewProxy()
	_ = ServiceManagerStartNotify()
	if len(*svcFlag) != 0 {
		if svc == nil {
			dlog.Fatal("Built-in service installation is not supported on this platform")
		}
		if err := service.Control(svc, *svcFlag); err != nil {
			dlog.Fatal(err)
		}
		if *svcFlag == "install" {
			dlog.Notice("Installed as a service. Use `-service start` to start")
		} else if *svcFlag == "uninstall" {
			dlog.Notice("Service uninstalled")
		} else if *svcFlag == "start" {
			dlog.Notice("Service started")
		} else if *svcFlag == "stop" {
			dlog.Notice("Service stopped")
		} else if *svcFlag == "restart" {
			dlog.Notice("Service restarted")
		}
		return
	}

	go func() {
		r := gin.Default()
		// gin.H is a shortcut for map[string]any
		r.GET("/servers/list", func(c *gin.Context) {
			app.proxy.serversInfo.RLock()
			defer app.proxy.serversInfo.RUnlock()
			c.JSON(http.StatusOK, gin.H{
				"count": len(app.proxy.serversInfo.inner),
				"data":  app.proxy.serversInfo.inner,
			})
		})
		r.GET("/servers/refresh", func(c *gin.Context) {
			app.proxy.serversInfo.refresh(app.proxy)
			c.JSON(http.StatusOK, gin.H{
				"msg": "ok",
			})
		})

		r.GET("/relays/list", func(c *gin.Context) {
			app.proxy.serversInfo.RLock()
			defer app.proxy.serversInfo.RUnlock()
			c.JSON(http.StatusOK, gin.H{
				"count": len(app.proxy.registeredRelays),
				"data":  app.proxy.registeredRelays,
			})
		})

		r.POST("/resolve", func(c *gin.Context) {
			req := ResolveRequestBody{
				ServerProtocol: "udp",
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": err.Error(),
				})
				return
			}

			q := new(dns.Msg)
			qtype, exists := dns.StringToType[strings.ToUpper(req.QType)]
			if !exists {
				qtype = dns.TypeTXT
			}
			q.SetQuestion(dns.Fqdn(req.Name), qtype)

			sendTime := NowUnixMillion()
			resp, rtt, err := app.proxy.ResolveQuery(
				req.ServerProtocol, req.Server,
				req.RelayName, q)
			c.JSON(http.StatusOK, gin.H{
				"rtt":      rtt,
				"server":   req,
				"error":    err,
				"data":     resp,
				"sendTime": sendTime,
			})
		})

		r.POST("/dos", func(c *gin.Context) {
			qtypeStr, _ := c.GetQuery("qtype")
			qtype, exists := dns.StringToType[strings.ToUpper(qtypeStr)]
			if !exists {
				qtype = dns.TypeA
			}

			multiLevelStr, exists := c.GetQuery("multiLevel")
			var multiLevel bool
			if !exists {
				multiLevel = false
			} else {
				multiLevel = strings.ToLower(multiLevelStr) == "true"
			}

			app.dos(qtype, multiLevel)
			c.JSON(http.StatusOK, gin.H{
				"msg": "ok",
			})
		})

		r.GET("/probe", func(c *gin.Context) {
			limit, _ := c.GetQuery("limit")
			limitInt, err := strconv.Atoi(limit)
			concurrentStr, _ := c.GetQuery("concurrent")
			concurrentInt, err := strconv.Atoi(concurrentStr)
			multiLevelStr, _ := c.GetQuery("multiLevel")
			multiLevel := multiLevelStr == "true"

			if err != nil {
				limitInt = -1
				concurrentInt = -1
			}
			go app.probe(limitInt, concurrentInt, multiLevel)
			c.JSON(http.StatusOK, gin.H{
				"msg": "ok",
			})
		})

		r.GET("/rand-test", func(c *gin.Context) {
			num, _ := c.GetQuery("num")
			numInt, err := strconv.Atoi(num)
			if err != nil {
				numInt = 1
			}
			qtypeStr, _ := c.GetQuery("qtype")
			qtype, exists := dns.StringToType[strings.ToUpper(qtypeStr)]
			if !exists {
				qtype = dns.TypeA
			}
			go app.randomQueryTest(numInt, qtype)
			c.JSON(http.StatusOK, gin.H{
				"msg": "ok",
			})
		})

		r.Run(":8080")
		dlog.Noticef("API Server started at %s", ":8080")
	}()

	scanner := bufio.NewScanner(os.Stdin)
	// enable command interaction
	go func() {
		for {
			// get command input
			var cmd string
			if !scanner.Scan() {
				break
			}
			cmd = scanner.Text()
			cmd = strings.TrimSpace(cmd)
			cmds := strings.Split(cmd, " ")
			cmd = cmds[0]
			args := cmds[1:]
			// handle command
			switch cmd {
			case "list":
				app.proxy.ListAvailableServers()
			case "list-r":
				app.proxy.ListAvailableRelays()
			case "refresh":
				app.proxy.serversInfo.refresh(app.proxy)
			case "resolve":
				var name string
				if len(args) == 0 {
					name = "www.google.com"
				} else {
					name = args[0]
				}
				ResolveIpv4("127.0.0.1:53", name)
			case "test":
				var server string
				var name string
				var relayName string
				server = "myserver"
				name = "www.bilibili.com"
				relayName = "myrelay"

				if len(args) == 1 {
					name = args[0]
				} else if len(args) == 2 {
					name = args[0]
					server = args[1]
				} else if len(args) == 3 {
					name = args[0]
					server = args[1]
					relayName = args[2]
				}

				// make a query for www.google.com
				q := new(dns.Msg)
				q.SetQuestion(dns.Fqdn(name), dns.TypeA)

				res, rtt, err := app.proxy.ResolveQuery(
					"tcp", server,
					relayName, q)
				if err != nil {
					dlog.Warn(err)
					break
				}
				fmt.Println(res)
				fmt.Printf("rtt: %dms\n", rtt)
			case "dos":
				multiLevel := slices.Contains(args, "multi")
				if len(args) == 0 {
					app.dos(dns.TypeTXT, multiLevel)
				} else {
					qtype, exists := dns.StringToType[strings.ToUpper(args[0])]
					if !exists {
						qtype = dns.TypeTXT
					}
					app.dos(qtype, multiLevel)
				}
			}
		}
	}()

	if svc != nil {
		if err := svc.Run(); err != nil {
			dlog.Fatal(err)
		}
	} else {
		app.Start(nil)
	}
}

func (app *App) Start(service service.Service) error {
	if service != nil {
		go func() {
			app.AppMain()
		}()
	} else {
		app.AppMain()
	}
	return nil
}

func (app *App) AppMain() {
	if err := ConfigLoad(app.proxy, app.flags); err != nil {
		dlog.Fatal(err)
	}
	if err := PidFileCreate(); err != nil {
		dlog.Errorf("Unable to create the PID file: [%v]", err)
	}
	if err := app.proxy.InitPluginsGlobals(); err != nil {
		dlog.Fatal(err)
	}
	app.quit = make(chan struct{})
	app.wg.Add(1)
	app.proxy.StartProxy()
	runtime.GC()
	<-app.quit
	dlog.Notice("Quit signal received...")
	app.wg.Done()
}

func (app *App) Stop(service service.Service) error {
	if err := PidFileRemove(); err != nil {
		dlog.Warnf("Failed to remove the PID file: [%v]", err)
	}
	dlog.Notice("Stopped.")
	return nil
}

type ResolveRequestBody struct {
	Name           string `json:"name"`
	Server         string `json:"server"`
	RelayName      string `json:"relayName"`
	ServerProtocol string `json:"serverProtocol"`
	QType          string `json:"qType"`
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
			resp, realRtt, err := app.proxy.ResolveQuery("tcp", server, relay, q)

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
					resp, realRtt, err := app.proxy.ResolveQuery("tcp", server, relay, q)

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
			resp, realRtt, err := app.proxy.ResolveQuery("tcp", server, relay, q)
			if err != nil {
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
