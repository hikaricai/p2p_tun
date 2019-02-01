package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/hikaricai/p2p_tun/kcp-go"
	"log"
	"math/rand"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/pbkdf2"

	"path/filepath"

	"github.com/urfave/cli"
)

var (
	// VERSION is injected by buildflags
	VERSION = "SELFBUILD"
	// SALT is use for pbkdf2 key expansion
	SALT = "kcp-go"
)

func checkError(err error) {
	if err != nil {
		log.Printf("%+v\n", err)
		os.Exit(-1)
	}
}

func main() {
	rand.Seed(int64(time.Now().Nanosecond()))
	if VERSION == "SELFBUILD" {
		// add more log flags for debugging
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}
	myApp := cli.NewApp()
	myApp.Name = "p2pserver"
	myApp.Usage = "server(with kcptun)"
	myApp.Version = VERSION
	myApp.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "listen,l",
			Value: ":4000",
			Usage: "kcp server listen address",
		},
		cli.StringFlag{
			Name:   "passwd",
			Value:  "1234",
			Usage:  "pre-shared secret between client and server",
			EnvVar: "KCPTUN_KEY",
		},
		cli.StringFlag{
			Name:  "crypt",
			Value: "aes",
			Usage: "aes, aes-128, aes-192, salsa20, blowfish, twofish, cast5, 3des, tea, xtea, xor, sm4, none",
		},
		cli.StringFlag{
			Name:  "mode",
			Value: "fast",
			Usage: "profiles: fast3, fast2, fast, normal, manual",
		},
		cli.IntFlag{
			Name:  "mtu",
			Value: 1350,
			Usage: "set maximum transmission unit for UDP packets",
		},
		cli.IntFlag{
			Name:  "sndwnd",
			Value: 1024,
			Usage: "set send window size(num of packets)",
		},
		cli.IntFlag{
			Name:  "rcvwnd",
			Value: 1024,
			Usage: "set receive window size(num of packets)",
		},
		cli.IntFlag{
			Name:  "datashard,ds",
			Value: 10,
			Usage: "set reed-solomon erasure coding - datashard",
		},
		cli.IntFlag{
			Name:  "parityshard,ps",
			Value: 3,
			Usage: "set reed-solomon erasure coding - parityshard",
		},
		cli.IntFlag{
			Name:  "dscp",
			Value: 0,
			Usage: "set DSCP(6bit)",
		},
		cli.BoolFlag{
			Name:  "nocomp",
			Usage: "disable compression",
		},
		cli.BoolFlag{
			Name:   "acknodelay",
			Usage:  "flush ack immediately when a packet is received",
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "nodelay",
			Value:  0,
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "interval",
			Value:  50,
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "resend",
			Value:  0,
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "nc",
			Value:  0,
			Hidden: true,
		},
		cli.IntFlag{
			Name:  "sockbuf",
			Value: 4194304, // socket buffer size in bytes
			Usage: "per-socket buffer in bytes",
		},
		cli.IntFlag{
			Name:  "keepalive",
			Value: 10, // nat keepalive interval in seconds
			Usage: "seconds between heartbeats",
		},
		cli.StringFlag{
			Name:  "snmplog",
			Value: "",
			Usage: "collect snmp to file, aware of timeformat in golang, like: ./snmp-20060102.log",
		},
		cli.IntFlag{
			Name:  "snmpperiod",
			Value: 60,
			Usage: "snmp collect period, in seconds",
		},
		cli.BoolFlag{
			Name:  "pprof",
			Usage: "start profiling server on :6060",
		},
		cli.StringFlag{
			Name:  "log",
			Value: "",
			Usage: "specify a log file to output, default goes to stderr",
		},
		cli.BoolFlag{
			Name:  "quiet",
			Usage: "to suppress the 'stream open/close' messages",
		},
		cli.StringFlag{
			Name:  "c",
			Value: "", // when the value is not empty, the config path must exists
			Usage: "config from json file, which will override the command from shell",
		},
	}
	myApp.Action = func(c *cli.Context) error {
		config := Config{}
		config.Listen = c.String("listen")
		config.Passwd = c.String("passwd")
		config.Crypt = c.String("crypt")
		config.Mode = c.String("mode")
		config.MTU = c.Int("mtu")
		config.SndWnd = c.Int("sndwnd")
		config.RcvWnd = c.Int("rcvwnd")
		config.DataShard = c.Int("datashard")
		config.ParityShard = c.Int("parityshard")
		config.DSCP = c.Int("dscp")
		config.NoComp = c.Bool("nocomp")
		config.AckNodelay = c.Bool("acknodelay")
		config.NoDelay = c.Int("nodelay")
		config.Interval = c.Int("interval")
		config.Resend = c.Int("resend")
		config.NoCongestion = c.Int("nc")
		config.SockBuf = c.Int("sockbuf")
		config.KeepAlive = c.Int("keepalive")
		config.Log = c.String("log")
		config.SnmpLog = c.String("snmplog")
		config.SnmpPeriod = c.Int("snmpperiod")
		config.Pprof = c.Bool("pprof")
		config.Quiet = c.Bool("quiet")

		if c.String("c") != "" {
			//Now only support json config file
			err := parseJSONConfig(&config, c.String("c"))
			checkError(err)
		}

		// log redirect
		if config.Log != "" {
			f, err := os.OpenFile(config.Log, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
			checkError(err)
			defer f.Close()
			log.SetOutput(f)
		}

		switch config.Mode {
		case "normal":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 40, 2, 1
		case "fast":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 30, 2, 1
		case "fast2":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 20, 2, 1
		case "fast3":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 10, 2, 1
		}

		log.Println("version:", VERSION)
		log.Println("initiating key derivation")
		pass := pbkdf2.Key([]byte(config.Passwd), []byte(SALT), 4096, 32, sha1.New)
		var block kcp.BlockCrypt
		switch config.Crypt {
		case "sm4":
			block, _ = kcp.NewSM4BlockCrypt(pass[:16])
		case "tea":
			block, _ = kcp.NewTEABlockCrypt(pass[:16])
		case "xor":
			block, _ = kcp.NewSimpleXORBlockCrypt(pass)
		case "none":
			block, _ = kcp.NewNoneBlockCrypt(pass)
		case "aes-128":
			block, _ = kcp.NewAESBlockCrypt(pass[:16])
		case "aes-192":
			block, _ = kcp.NewAESBlockCrypt(pass[:24])
		case "blowfish":
			block, _ = kcp.NewBlowfishBlockCrypt(pass)
		case "twofish":
			block, _ = kcp.NewTwofishBlockCrypt(pass)
		case "cast5":
			block, _ = kcp.NewCast5BlockCrypt(pass[:16])
		case "3des":
			block, _ = kcp.NewTripleDESBlockCrypt(pass[:24])
		case "xtea":
			block, _ = kcp.NewXTEABlockCrypt(pass[:16])
		case "salsa20":
			block, _ = kcp.NewSalsa20BlockCrypt(pass)
		default:
			config.Crypt = "aes"
			block, _ = kcp.NewAESBlockCrypt(pass)
		}

		lis, err := kcp.ListenWithOptions(config.Listen, block, config.DataShard, config.ParityShard)
		checkError(err)
		log.Println("listening on:", lis.Addr())
		log.Println("encryption:", config.Crypt)
		log.Println("nodelay parameters:", config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
		log.Println("sndwnd:", config.SndWnd, "rcvwnd:", config.RcvWnd)
		log.Println("compression:", !config.NoComp)
		log.Println("mtu:", config.MTU)
		log.Println("datashard:", config.DataShard, "parityshard:", config.ParityShard)
		log.Println("acknodelay:", config.AckNodelay)
		log.Println("dscp:", config.DSCP)
		log.Println("sockbuf:", config.SockBuf)
		log.Println("keepalive:", config.KeepAlive)
		log.Println("snmplog:", config.SnmpLog)
		log.Println("snmpperiod:", config.SnmpPeriod)
		log.Println("pprof:", config.Pprof)
		log.Println("quiet:", config.Quiet)

		if err := lis.SetDSCP(config.DSCP); err != nil {
			log.Println("SetDSCP:", err)
		}
		if err := lis.SetReadBuffer(config.SockBuf); err != nil {
			log.Println("SetReadBuffer:", err)
		}
		if err := lis.SetWriteBuffer(config.SockBuf); err != nil {
			log.Println("SetWriteBuffer:", err)
		}

		go snmpLogger(config.SnmpLog, config.SnmpPeriod)

		for {
			log.Println("listening new kcp")
			if conn, err := lis.AcceptKCP(); err == nil {
				log.Println("remote address:", conn.RemoteAddr())
				conn.SetStreamMode(true)
				conn.SetWriteDelay(false)
				conn.SetNoDelay(config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
				conn.SetMtu(config.MTU)
				conn.SetWindowSize(config.SndWnd, config.RcvWnd)
				conn.SetACKNoDelay(config.AckNodelay)

				go handleClient(conn)
			} else {
				log.Printf("%+v", err)
			}
		}
	}
	myApp.Run(os.Args)
}

type DigHoleMess struct {
	Cmd  string
	Data string
}

type P2PSession struct {
	addr   string
	chPair chan string
	conn1 *kcp.UDPSession
	conn2 *kcp.UDPSession
	chFin chan struct{}
}

var keymap = make(map[string]*P2PSession)

var keymu  sync.Mutex

var session *P2PSession;

func handleClient(conn *kcp.UDPSession) {
	reader := bufio.NewReader(conn)
	defer conn.Close()
	var dataReady int32
	var chThreadDie = make(chan struct{})
	var ok bool;
	defer close(chThreadDie)
	go timeout(conn, &dataReady, chThreadDie)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Println("reader.ReadString", err)
			return
		}
		var mess DigHoleMess
		err = json.Unmarshal([]byte(line), &mess)
		if err != nil{
			continue
		}
		switch mess.Cmd {
		case "login":
			remoteAddr := conn.RemoteAddr().String()
			log.Println("login from ", remoteAddr)
			key := mess.Data
			log.Println("key is ", key)

			keymu.Lock()
			session, ok = keymap[key]
			if ok {
				peerAddr := session.addr
				log.Println("find peer and addr is", peerAddr)
				delete(keymap, key)
				session.conn2 = conn
				session.chPair <- remoteAddr
				jsonPairMess := phaseJsonMess("pair_c", peerAddr)
				conn.Write(jsonPairMess)
			} else {
				log.Println("no peer, registed")
				session = &P2PSession{remoteAddr, make(chan string), conn, nil,make(chan struct{})}
				keymap[key] = session
				go p2pSessionHandler(session, chThreadDie)
			}
			keymu.Unlock()
		case "ping":
			atomic.StoreInt32(&dataReady, 1)
			jsonPingMess := phaseJsonMess("ping", "hello")
			conn.Write(jsonPingMess)
			log.Println("rcv ping from ", conn.RemoteAddr().String())
		case "fin":
			log.Println("fin from", conn.RemoteAddr().String())
			session.chFin <- struct{}{}
		}
	}
}

func timeout(conn *kcp.UDPSession, dataReady *int32, chThreadDie chan struct{}){
	tickerDie := time.NewTicker(30*time.Second)
	defer tickerDie.Stop()

	for {
		select {
		case <-tickerDie.C:
			if !atomic.CompareAndSwapInt32(dataReady, 1, 0) {
				log.Println("ping timeout")
				conn.Close()
				return
			}
		case <-chThreadDie:
			return
		}
	}
}

func p2pSessionHandler(session *P2PSession, chThreadDie chan struct{}){
	finCnt :=0
	for {
		select {
		case <-chThreadDie:
			return
		case peerAddr := <-session.chPair:
			jsonPairMess := phaseJsonMess("pair_s", peerAddr)
			session.conn1.Write(jsonPairMess)
		case <-session.chFin:
			finCnt++
			if finCnt == 2{
				jsonPairMess := phaseJsonMess("fin", "bye")
				session.conn1.Write(jsonPairMess)
				session.conn2.Write(jsonPairMess)
				time.Sleep(time.Second)
				session.conn1.Close()
				session.conn2.Close()
				return
			}
		}
	}
}

func phaseJsonMess(cmd string, data string) []byte {
	mess := DigHoleMess{cmd, data}
	jsonMess, err := json.Marshal(mess)
	if err != nil {
		log.Println(err)
	}
	return append(jsonMess, '\n')
}

func snmpLogger(path string, interval int) {
	if path == "" || interval == 0 {
		return
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			// split path into dirname and filename
			logdir, logfile := filepath.Split(path)
			// only format logfile
			f, err := os.OpenFile(logdir+time.Now().Format(logfile), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
			if err != nil {
				log.Println(err)
				return
			}
			w := csv.NewWriter(f)
			// write header in empty file
			if stat, err := f.Stat(); err == nil && stat.Size() == 0 {
				if err := w.Write(append([]string{"Unix"}, kcp.DefaultSnmp.Header()...)); err != nil {
					log.Println(err)
				}
			}
			if err := w.Write(append([]string{fmt.Sprint(time.Now().Unix())}, kcp.DefaultSnmp.ToSlice()...)); err != nil {
				log.Println(err)
			}
			kcp.DefaultSnmp.Reset()
			w.Flush()
			f.Close()
		}
	}
}
