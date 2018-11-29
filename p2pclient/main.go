package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/pbkdf2"

	"github.com/hikaricai/p2p_tun/kcp-go"
	"github.com/urfave/cli"
	"github.com/xtaci/smux"

	"path/filepath"
)

var (
	// VERSION is injected by buildflags
	VERSION = "SELFBUILD"
	// SALT is use for pbkdf2 key expansion
	SALT = "kcp-go"
	isServer = false
)

func handleLocalTcp(sess *smux.Session, p1 io.ReadWriteCloser, quiet bool) {
	if !quiet {
		log.Println("stream opened")
		defer log.Println("stream closed")
	}

	defer p1.Close()
	p2, err := sess.OpenStream()
	if err != nil {
		return
	}
	defer p2.Close()

	// start tunnel
	p1die := make(chan struct{})
	buf1 := make([]byte, 65535)
	go func() { io.CopyBuffer(p1, p2, buf1); close(p1die) }()

	p2die := make(chan struct{})
	buf2 := make([]byte, 65535)
	go func() { io.CopyBuffer(p2, p1, buf2); close(p2die) }()

	// wait for tunnel termination
	select {
	case <-p1die:
	case <-p2die:
	}
}

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
	myApp.Name = "p2pclient"
	myApp.Usage = "client(with kcptun)"
	myApp.Version = VERSION
	myApp.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "targettcp, t",
			Value: "127.0.0.1:22",
			Usage: "target server address",
		},
		cli.StringFlag{
			Name:  "listentcp,l",
			Value: ":12948",
			Usage: "local listen address",
		},
		cli.StringFlag{
			Name:  "remoteudp, r",
			Value: "vps:29900",
			Usage: "kcp server address",
		},
		cli.StringFlag{
			Name:  "bindudp, b",
			Value: ":29900",
			Usage: "bind local udp",
		},
		cli.StringFlag{
			Name:  "key, k",
			Value: "1234",
			Usage: "p2p pair key",
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
			Value: "fast1",
			Usage: "profiles: fast3, fast2, fast, normal, manual",
		},
		cli.IntFlag{
			Name:  "conn",
			Value: 1,
			Usage: "set num of UDP connections to server",
		},
		cli.IntFlag{
			Name:  "autoexpire",
			Value: 0,
			Usage: "set auto expiration time(in seconds) for a single UDP connection, 0 to disable",
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
		config.ListenTcp = c.String("listentcp")
		config.RemoteUdp = c.String("remoteudp")
		config.TargetTcp = c.String("targettcp")
		config.BindUdp = c.String("bindudp")
		config.Key		= c.String("key")
		config.Passwd = c.String("passwd")
		config.Crypt = c.String("crypt")
		config.Mode = c.String("mode")
		config.AutoExpire = c.Int("autoexpire")
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
		config.Quiet = c.Bool("quiet")

		if c.String("c") != "" {
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

		log.Println("encryption:", config.Crypt)
		log.Println("nodelay parameters:", config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
		log.Println("remote udp  address:", config.RemoteUdp)
		log.Println("sndwnd:", config.SndWnd, "rcvwnd:", config.RcvWnd)
		log.Println("compression:", !config.NoComp)
		log.Println("mtu:", config.MTU)
		log.Println("datashard:", config.DataShard, "parityshard:", config.ParityShard)
		log.Println("acknodelay:", config.AckNodelay)
		log.Println("dscp:", config.DSCP)
		log.Println("sockbuf:", config.SockBuf)
		log.Println("keepalive:", config.KeepAlive)
		log.Println("autoexpire:", config.AutoExpire)
		log.Println("snmplog:", config.SnmpLog)
		log.Println("snmpperiod:", config.SnmpPeriod)
		log.Println("quiet:", config.Quiet)
		go snmpLogger(config.SnmpLog, config.SnmpPeriod)

		chTCPConn := make(chan *net.TCPConn, 16)

		go tcpListener(chTCPConn, &config)
		for{
			peerAddr, err := getPeerAddr(&config)
			if err == nil{
				p2pHandle(&config, peerAddr, chTCPConn)
			}
		}
	}
	myApp.Run(os.Args)
}

func p2pHandle(config *Config, peerAddr string, chTCPConn chan *net.TCPConn){
	udpAddr, err := net.ResolveUDPAddr("udp", config.BindUdp)
	checkError(err)
	udpconn, err := net.ListenUDP("udp", udpAddr)
	checkError(err)
	defer udpconn.Close()

	smuxSession, err := newSmuxSession(udpconn, config, peerAddr)
	checkError(err)

	go handleTargetTcp(config.TargetTcp, smuxSession, config.Quiet)
	tickerCheck := time.NewTicker(10*time.Second)
	defer tickerCheck.Stop()
	for {
		select {
		case p1 := <-chTCPConn:
			go handleLocalTcp(smuxSession, p1, config.Quiet)
		case <-tickerCheck.C:
			if smuxSession.IsClosed(){
				log.Println("p2p session closed")
				return
			}
		}
	}
}

func tcpListener(chTCPConn chan *net.TCPConn, config *Config){
	listenTcpAddr, err := net.ResolveTCPAddr("tcp", config.ListenTcp)
	checkError(err)
	listener, err := net.ListenTCP("tcp", listenTcpAddr)
	checkError(err)
	log.Println("listening on:", listener.Addr())
	for{
		p1, err := listener.AcceptTCP()
		if err != nil {
			log.Fatalln(err)
			checkError(err)
		}
		chTCPConn <- p1
	}
}

func getPeerAddr(config *Config)(string, error){

	udpAddr, err := net.ResolveUDPAddr("udp", config.BindUdp)
	checkError(err)
	udpconn, err := net.ListenUDP("udp", udpAddr)
	checkError(err)
	defer udpconn.Close()

	kcpConn, err := newKcpConn(udpconn, config, config.RemoteUdp)
	defer kcpConn.Close()

	var dataReady int32
	var chPing = make(chan struct{})
	defer close(chPing)

	go pingCheck(kcpConn, &dataReady, chPing)
	reader := bufio.NewReader(kcpConn)
	pairMess := phaseJsonMess("login", config.Key)
	finMess := phaseJsonMess("fin", "good bye")
	var peerAddr string
	log.Println("writing mess")
	n, err := kcpConn.Write(pairMess)
	if err != nil {
		log.Println("kcpConn.Write", err)
		return "", err
	}
	log.Println("writen ", n)
	for {
		pair_s := false
		log.Println("waiting for server")
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Println("reader.ReadString", err)
			return "", err
		}
		var mess DigHoleMess
		json.Unmarshal([]byte(line), &mess)
		log.Println("rcv Cmd", mess.Cmd)
		switch mess.Cmd {
		case "ping":
			atomic.StoreInt32(&dataReady, 1)
			log.Println("rcv ping")
		case "pair_s":
			pair_s = true
			fallthrough
		case "pair_c":
			isServer = pair_s
			peerAddr = mess.Data
			log.Println("peer addr is ", peerAddr)
			n, err := kcpConn.Write(finMess)
			if err != nil {
				log.Println("kcpConn.Write", err)
				return "", err
			}
			log.Println("writen ", n)
			time.Sleep(1*time.Second)
			return peerAddr, nil
		}
	}
}

func pingCheck(conn *kcp.UDPSession, dataReady *int32, chPing chan struct {}){
	tickerDie := time.NewTicker(30*time.Second)
	defer tickerDie.Stop()
	jsonPingMess := phaseJsonMess("ping", "hello")
	tickerPing := time.NewTicker(10 * time.Second)
	defer tickerPing.Stop()
	defer 	log.Println("pingCheck return")
	for {
		select {
		case <-tickerDie.C:
			if !atomic.CompareAndSwapInt32(dataReady, 1, 0) {
				log.Println("ping timeout")
				conn.Close()
				return
			}
		case <-tickerPing.C:
			conn.Write(jsonPingMess)
		case <- chPing:
			return
		}
	}
}

type DigHoleMess struct {
	Cmd  string
	Data string
}

func phaseJsonMess(cmd string, data string) []byte {
	mess := DigHoleMess{cmd, data}
	jsonMess, err := json.Marshal(mess)
	if err != nil {
		log.Println(err)
	}
	return append(jsonMess, '\n')
}

func newSmuxSession(udpconn net.PacketConn, config *Config, remoteAddr string) (*smux.Session, error) {

	kcpconn, err := newKcpConn(udpconn, config, remoteAddr)
	if err != nil {
		return nil, err
	}
	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = config.SockBuf
	smuxConfig.KeepAliveInterval = time.Duration(config.KeepAlive) * time.Second
	// stream multiplex
	var smuxSession *smux.Session

	if isServer {
		smuxSession, err = smux.Server(kcpconn, smuxConfig)
	} else {
		smuxSession, err = smux.Client(kcpconn, smuxConfig)
	}
	if err == nil {
		log.Println("connection:", kcpconn.LocalAddr(), "->", kcpconn.RemoteAddr())
	}
	return smuxSession, err
}

func newKcpConn(udpconn net.PacketConn, config *Config, remoteAddr string) (*kcp.UDPSession, error) {
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

	kcpconn, err := kcp.NewP2pConn(udpconn, remoteAddr, block, config.DataShard, config.ParityShard)
	if err != nil {
		return nil, err
	}

	kcpconn.SetStreamMode(true)
	kcpconn.SetWriteDelay(false)
	kcpconn.SetNoDelay(config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
	kcpconn.SetWindowSize(config.SndWnd, config.RcvWnd)
	kcpconn.SetMtu(config.MTU)
	kcpconn.SetACKNoDelay(config.AckNodelay)

	if err := kcpconn.SetDSCP(config.DSCP); err != nil {
		log.Println("SetDSCP:", err)
	}
	if err := kcpconn.SetReadBuffer(config.SockBuf); err != nil {
		log.Println("SetReadBuffer:", err)
	}
	if err := kcpconn.SetWriteBuffer(config.SockBuf); err != nil {
		log.Println("SetWriteBuffer:", err)
	}
	return kcpconn, err
}

func handleTargetTcp(addr string, session *smux.Session, quiet bool) {
	for {
		p1, err := session.AcceptStream()
		if err != nil {
			log.Println(err)
			return
		}
		p2, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			p1.Close()
			log.Println(err)
			continue
		}
		go func() {
			if !quiet {
				log.Println("tcp client opened")
				defer log.Println("tcp client closed")
			}
			defer p1.Close()
			defer p2.Close()

			// start tunnel
			p1die := make(chan struct{})
			buf1 := make([]byte, 65535)
			go func() { io.CopyBuffer(p1, p2, buf1); close(p1die) }()

			p2die := make(chan struct{})
			buf2 := make([]byte, 65535)
			go func() { io.CopyBuffer(p2, p1, buf2); close(p2die) }()

			// wait for tunnel termination
			select {
			case <-p1die:
			case <-p2die:
			}
		}()
	}
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
