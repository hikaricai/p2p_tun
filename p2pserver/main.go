package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/json"
	"github.com/hikaricai/p2p_tun/kcp-go"
	"log"
	"math/rand"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/pbkdf2"

	"github.com/urfave/cli"
)

var (
	// VERSION is injected by buildflags
	VERSION = "SELFBUILD"
	// SALT is use for pbkdf2 key expansion
	SALT = "kcp-go"
	pingInterval = 10
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
			Value: "0.0.0.0:4000",
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
			Value: "none",
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
			Value: 0,
			Usage: "set reed-solomon erasure coding - datashard",
		},
		cli.IntFlag{
			Name:  "parityshard,ps",
			Value: 0,
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
		config.SnmpLog = c.String("snmplog")
		config.SnmpPeriod = c.Int("snmpperiod")
		config.Pprof = c.Bool("pprof")
		config.Quiet = c.Bool("quiet")

		if c.String("c") != "" {
			//Now only support json config file
			err := parseJSONConfig(&config, c.String("c"))
			checkError(err)
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

		if err := lis.SetDSCP(config.DSCP); err != nil {
			log.Println("SetDSCP:", err)
		}
		if err := lis.SetReadBuffer(config.SockBuf); err != nil {
			log.Println("SetReadBuffer:", err)
		}
		if err := lis.SetWriteBuffer(config.SockBuf); err != nil {
			log.Println("SetWriteBuffer:", err)
		}

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

type UdpSess struct {
	conn *kcp.UDPSession
	pingFlag int32
	isFin bool
}
type P2PSession struct {
	key string
	sess1 *UdpSess
	sess2 *UdpSess
	chFin chan struct{}
	mu  sync.Mutex
}

var keymap = make(map[string]*P2PSession)

var keymu  sync.Mutex
func registSession(session *P2PSession, sess *UdpSess) (ret bool){
	ret = true
	session.mu.Lock()
	if session.sess1 == nil{
		session.sess1 = sess
	}else if session.sess2 == nil{
		session.sess2 = sess
	}else{
		ret = false
	}
	if  ret == true && session.sess1 != nil && session.sess2 != nil{
		conn1 := session.sess1.conn
		conn2 := session.sess2.conn
		addr1 := conn1.RemoteAddr().String()
		addr2 := conn2.RemoteAddr().String()
		jsonPair1Mess := phaseJsonMess("pair_s", addr2)
		jsonPair2Mess := phaseJsonMess("pair_c", addr1)
		log.Println("pairing ", addr1,addr2)
		conn1.Write(jsonPair1Mess)
		conn2.Write(jsonPair2Mess)
	}
	session.mu.Unlock()
	return ret
}
func handleClient(conn *kcp.UDPSession) {
	var session *P2PSession;
	key := ""
	reader := bufio.NewReader(conn)
	defer conn.Close()
	var ok bool
	var registed  = false
	sess := &UdpSess{conn,1,false}
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
			key = mess.Data
			log.Println("key is ", key)
			keymu.Lock()
			session, ok = keymap[key]
			if ok {
				registed = registSession(session,sess)
			} else {
				log.Println("make new P2PSession")
				session = new(P2PSession)
				session.key = key
				session.sess1 = sess
				session.chFin = make(chan struct{})
				keymap[key] = session
				registed = true
				go p2pSessionHandler(session)
			}
			keymu.Unlock()
			jsonPingMess := phaseJsonMess("ping", "hello")
			conn.Write(jsonPingMess)
		case "ping":
			log.Println("rcv ping from ", conn.RemoteAddr().String())
			if registed == false{
				keymu.Lock()
				session, ok = keymap[key]
				if ok {
					registed = registSession(session,sess)
				} else {
					log.Println("make new P2PSession")
					session = new(P2PSession)
					session.key = key
					session.sess1 = sess
					session.chFin = make(chan struct{})
					keymap[key] = session
					registed = true
					go p2pSessionHandler(session)
				}
				keymu.Unlock()
			}
			atomic.StoreInt32(&sess.pingFlag, 1)
			jsonPingMess := phaseJsonMess("ping", "hello")
			conn.Write(jsonPingMess)
		case "fin":
			log.Println("fin from", conn.RemoteAddr().String())
			sess.isFin = true
			session.chFin <- struct{}{}
		}
	}
}


func p2pSessionHandler(session *P2PSession){
	tickerPing := time.NewTicker(time.Duration(pingInterval)*time.Second)
	defer tickerPing.Stop()
	for {
		select {
		case <-tickerPing.C:
			if session.sess1 != nil && !atomic.CompareAndSwapInt32(&session.sess1.pingFlag, 1, 0) {
				session.mu.Lock()
				session.sess1.conn.Close()
				session.sess1 = nil
				log.Println("sess1 ping timeout")
				session.mu.Unlock()
			}
			if session.sess2 != nil && !atomic.CompareAndSwapInt32(&session.sess2.pingFlag, 1, 0) {
				session.mu.Lock()
				session.sess2.conn.Close()
				session.sess2 = nil
				log.Println("sess2 ping timeout")
				session.mu.Unlock()
			}
		case <-session.chFin:
			if session.sess1 == nil || session.sess2 == nil{
				continue
			}
			if session.sess1.isFin == true && session.sess2.isFin == true{
				jsonFinMess := phaseJsonMess("fin", "bye")
				session.sess1.conn.Write(jsonFinMess)
				session.sess2.conn.Write(jsonFinMess)
				time.Sleep(time.Second)
				session.sess1.conn.Close()
				session.sess2.conn.Close()
				keymu.Lock()
				delete(keymap,session.key)
				keymu.Unlock()
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
