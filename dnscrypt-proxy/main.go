package main

import (
	"bufio"
	"context"
	crypto_rand "crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/jedisct1/dlog"
	"github.com/kardianos/service"
	"github.com/miekg/dns"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"math/rand"
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
	wg          sync.WaitGroup
	quit        chan struct{}
	proxy       *Proxy
	flags       *ConfigFlags
	mongoClient *mongo.Client
	StatsMap    map[string]*Stats // probe_id -> Stats
}

type Stats struct {
	ProbeId      string       `json:"probe_id"`
	TotalCount   atomic.Int32 `json:"total_count"`
	CurrentCount atomic.Int32 `json:"current_count"`
	SuccessCount atomic.Int32 `json:"success_count"`
	FailCount    atomic.Int32 `json:"fail_count"`
	MultiLevel   bool         `json:"multi_level"`
	Running      bool         `json:"running"`
	Concurrent   int          `json:"concurrent"`
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
		flags:    &flags,
		StatsMap: make(map[string]*Stats),
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

	app.startApi()

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

	var err error
	app.mongoClient, err = mongo.Connect(context.Background(), options.Client().ApplyURI(app.proxy.MongoUri))
	if err != nil {
		dlog.Errorf("Failed to connect to MongoDB: [%v]", err)
		return
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

func (app *App) startApi() {
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
				ServerProtocol: "tcp",
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
				req.RelayName, q, time.Duration(req.TimeWait)*time.Millisecond)
			c.JSON(http.StatusOK, gin.H{
				"rtt":      rtt,
				"server":   req,
				"error":    err,
				"data":     resp,
				"sendTime": sendTime,
			})
		})

		r.GET("/dos", func(c *gin.Context) {
			qtypeStr := c.Query("qtype")
			qtype, exists := dns.StringToType[strings.ToUpper(qtypeStr)]
			if !exists {
				qtype = dns.TypeA
			}

			multiLevelStr, exists := c.GetQuery("multiLevel")
			multiLevel := strings.ToLower(multiLevelStr) == "true"
			pendingStr, exists := c.GetQuery("multiLevel")
			pending := strings.ToLower(pendingStr) == "true"

			limit := c.Query("limit")

			limitInt, _ := strconv.Atoi(limit)
			result := app.dos(qtype, multiLevel, pending, limitInt)
			c.JSON(http.StatusOK, gin.H{
				"msg":   "ok",
				"stats": result,
			})
		})

		r.GET("/dos/pending", func(c *gin.Context) {
			app.dosPending(dns.TypeTXT, false)
			c.JSON(http.StatusOK, gin.H{
				"msg": "ok",
			})
		})

		r.GET("/probe", func(c *gin.Context) {
			limit := c.Query("limit")
			limitInt, _ := strconv.Atoi(limit)
			concurrentStr := c.Query("concurrent")
			concurrentInt, _ := strconv.Atoi(concurrentStr)
			multiLevelStr := c.Query("multiLevel")
			multiLevel := multiLevelStr == "true"

			probeId := timeNow().Format("20060102150405")
			stats := &Stats{
				ProbeId: probeId,
			}
			app.StatsMap[probeId] = stats
			stats.MultiLevel = multiLevel
			stats.Running = true
			go app.probe(probeId, limitInt, concurrentInt, multiLevel)
			c.JSON(http.StatusOK, gin.H{
				"probe_id": probeId,
				"msg":      "ok",
			})
		})

		r.GET("/probe/stop", func(c *gin.Context) {
			probeId := c.Query("probe_id")
			if probeId == "" {
				c.JSON(http.StatusBadRequest, gin.H{
					"status": 1,
					"error":  "probe_id is required",
				})
				return
			}

			if stats, exists := app.StatsMap[probeId]; exists {
				stats.Running = false
			} else {
				c.JSON(http.StatusOK, gin.H{
					"status": 2,
					"error":  "probe_id not found",
				})
			}

			c.JSON(http.StatusOK, gin.H{
				"status": 0,
				"msg":    "ok",
			})
		})

		r.GET("/probe/list", func(c *gin.Context) {
			probeId := c.Query("probe_id")
			if probeId == "" {
				c.JSON(http.StatusOK, gin.H{
					"status": 0,
					"msg":    "ok",
					"data":   app.StatsMap,
				})
			} else {
				if stats, exists := app.StatsMap[probeId]; exists {
					var successRate float64
					if stats.CurrentCount.Load() > 0 {
						successRate = float64(stats.SuccessCount.Load()) / float64(stats.CurrentCount.Load()) * 100
						// 保留两位小数
						successRate, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", successRate), 64)
					}
					c.JSON(http.StatusOK, gin.H{
						"status": 0,
						"msg":    "ok",
						"data": gin.H{
							"probe_id":      probeId,
							"total_count":   stats.TotalCount.Load(),
							"current_count": stats.CurrentCount.Load(),
							"success_count": stats.SuccessCount.Load(),
							"multi_level":   stats.MultiLevel,
							"running":       stats.Running,
							"success_rate":  successRate,
							"concurrent":    stats.Concurrent,
						},
					})
				} else {
					c.JSON(http.StatusBadRequest, gin.H{
						"status": 1,
						"error":  "probe_id not found",
					})
				}
			}
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

		_ = r.Run(":8080")
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
				_, err := app.proxy.serversInfo.refresh(app.proxy)
				if err != nil {
					dlog.Warn(err)
				}
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
					relayName, q, 0)
				if err != nil {
					dlog.Warn(err)
					break
				}
				fmt.Println(res)
				fmt.Printf("rtt: %dms\n", rtt)
			case "dos":
				multiLevel := slices.Contains(args, "multi")
				pending := slices.Contains(args, "pending")
				if len(args) == 0 {
					app.dos(dns.TypeTXT, multiLevel, pending, 0)
				} else {
					qtype, exists := dns.StringToType[strings.ToUpper(args[0])]
					if !exists {
						qtype = dns.TypeTXT
					}

					if len(args) == 2 {
						limit, _ := strconv.Atoi(args[1])
						app.dos(qtype, multiLevel, pending, limit)
					} else {
						app.dos(qtype, multiLevel, pending, 0)
					}
				}
			}
		}
	}()
}
