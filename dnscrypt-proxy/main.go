package main

import (
	"bufio"
	crypto_rand "crypto/rand"
	"encoding/binary"
	"encoding/csv"
	"flag"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/jedisct1/dlog"
	"github.com/kardianos/service"
	"github.com/miekg/dns"
	"log"
	"math/rand"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
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
			q.SetQuestion(dns.Fqdn(req.Name), dns.TypeA)

			resp, rtt, err := app.proxy.ResolveQuery(
				"udp", req.ServerProtocol, req.Server,
				req.RelayName, q)
			c.JSON(http.StatusOK, gin.H{
				"rtt":    rtt,
				"server": req,
				"error":  err,
				"data":   resp,
			})
		})

		r.POST("/dos", func(c *gin.Context) {
			app.dos()
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

				res, rtt, _ := app.proxy.ResolveQuery(
					"udp", "tcp", server,
					relayName, q)
				fmt.Println(res)
				fmt.Printf("rtt: %dms\n", rtt)
			case "dos":
				app.dos()
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

type DosTimer struct {
	StartTime float64
	Offset    float64
}

func newDosTimer() *DosTimer {
	return &DosTimer{
		StartTime: float64(time.Now().UnixNano()) / 1e6,
		Offset:    -100,
	}
}

func (t *DosTimer) Now() float64 {
	return float64(time.Now().UnixNano())/1e6 - t.StartTime + t.Offset
}

func (app *App) dos() {
	// load prepared list
	// make a query for server-relay-randomStr-index.test.xxt.asia
	q := new(dns.Msg)
	fout, err := os.OpenFile("send_result.csv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal("Unable to read input file ", err)
	}
	path, err := os.Getwd()
	if err != nil {
		log.Println(err)
	}
	fmt.Println(path) // for example /home/user
	records := readCsvFile("./prepared_list.csv")
	lock := sync.Mutex{}

	wg := sync.WaitGroup{}
	wg.Add(len(records) - 1)
	// StartTime + offset(delay)
	timer := newDosTimer()
	for i, record := range records[1:] {
		recordCopy := make([]string, len(record))
		copy(recordCopy, record)

		go func(record []string, index int) {
			defer wg.Done()
			server := record[0]
			relay := record[1]
			sendTime, _ := strconv.ParseFloat(record[2], 64)
			arrivalTime, _ := strconv.ParseFloat(record[3], 64)
			domain := fmt.Sprintf("%s-%s-%s-%d.test.xxt.asia", server, relay, RandStringRunes(8), index)
			q.SetQuestion(dns.Fqdn(domain), dns.TypeA)

			// Sleep until sendTime
			timeNow := timer.Now()
			if sendTime > timeNow {
				time.Sleep(time.Duration(sendTime-timeNow) * time.Millisecond)
			}

			realSendTime := timer.Now()
			resp, rtt, err := app.proxy.ResolveQuery(
				"udp", "tcp", server,
				relay, q)
			if err != nil {
				dlog.Warn(err)
				return
			}
			sendTimeDiff := realSendTime - sendTime
			lock.Lock()
			fout.WriteString(fmt.Sprintf("%s,%s,%f,%f,%f,%f,%d\n",
				server, relay, sendTime, realSendTime, sendTimeDiff, arrivalTime, rtt))
			fout.Sync()
			lock.Unlock()
			fmt.Println(server, relay, rtt, resp.Answer)
		}(recordCopy, i)
	}
	wg.Wait()
	log.Println("DOS finished, total: ", len(records)-1)
	fout.Close()
}
