package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/json"
	"github.com/hikaricai/p2p_tun/kcp-go"
	"github.com/xtaci/kcptun/generic"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"golang.org/x/crypto/pbkdf2"
	"github.com/urfave/cli"
	"github.com/xtaci/smux"
)

var (
	// VERSION is injected by buildflags
	VERSION = "SELFBUILD"
	// SALT is use for pbkdf2 key expansion
	SALT = "kcp-go"
	isServer = false
	pingInterval = 10
	xmitBuf sync.Pool
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

	streamCopy := func(dst io.Writer, src io.ReadCloser) chan struct{} {
		die := make(chan struct{})
		go func() {
			buf := xmitBuf.Get().([]byte)
			generic.CopyBuffer(dst, src, buf)
			xmitBuf.Put(buf)
			close(die)
		}()
		return die
	}

	select {
	case <-streamCopy(p1, p2):
	case <-streamCopy(p2, p1):
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
	xmitBuf.New = func() interface{} {
		return make([]byte, 32768)
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
			Value: ":2022",
			Usage: "local listen address",
		},
		cli.StringFlag{
			Name:  "remoteudp, r",
			Value: "127.0.0.1:4000",
			Usage: "kcp server address",
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
			Value: "none",
			Usage: "aes, aes-128, aes-192, salsa20, blowfish, twofish, cast5, 3des, tea, xtea, xor, sm4, none",
		},
		cli.StringFlag{
			Name:  "mode",
			Value: "fast",
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
		config.Key		= c.String("key")
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
		config.Quiet = c.Bool("quiet")

		if c.String("c") != "" {
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

		chTCPConn := make(chan *net.TCPConn, 16)

		go tcpListener(chTCPConn, &config)
		for{
			peerAddr, err := getPeerAddr(&config)
			time.Sleep(2*time.Second)
			if err == nil{
				p2pHandle(&config, peerAddr, chTCPConn)
			}else{
				time.Sleep(time.Duration(pingInterval)*time.Second)
			}
		}
	}
	myApp.Run(os.Args)
}

func p2pHandle(config *Config, peerAddr string, chTCPConn chan *net.TCPConn){
	udpAddr, err := net.ResolveUDPAddr("udp4", config.BindUdp)
	checkError(err)
	udpconn, err := net.ListenUDP("udp4", udpAddr)
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
	listenTcpAddr, err := net.ResolveTCPAddr("tcp4", config.ListenTcp)
	checkError(err)
	listener, err := net.ListenTCP("tcp4", listenTcpAddr)
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
	udpAddr, err := net.ResolveUDPAddr("udp4", "0.0.0.0:0")
	checkError(err)
	udpconn, err := net.ListenUDP("udp4", udpAddr)
	checkError(err)
	config.BindUdp = udpconn.LocalAddr().String()
	log.Println("config.BindUdp is ", config.BindUdp)
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
	_, err = kcpConn.Write(pairMess)
	if err != nil {
		log.Println("kcpConn.Write", err)
		return "", err
	}
	for {
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
			isServer = true
			peerAddr = mess.Data
			log.Println("peer addr is ", peerAddr)
			kcpConn.Write(finMess)
		case "pair_c":
			isServer = false
			peerAddr = mess.Data
			log.Println("peer addr is ", peerAddr)
			kcpConn.Write(finMess)
		case "fin":
			return peerAddr, nil
		}
	}
}

func pingCheck(conn *kcp.UDPSession, dataReady *int32, chPing chan struct {}){
	jsonPingMess := phaseJsonMess("ping", "hello")
	tickerPing := time.NewTicker(time.Duration(pingInterval)*time.Second)
	defer tickerPing.Stop()
	defer 	log.Println("pingCheck return")
	for {
		select {
		case <-tickerPing.C:
			if !atomic.CompareAndSwapInt32(dataReady, 1, 0) {
				log.Println("ping timeout")
				conn.Close()
				return
			}
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
	smuxConfig.KeepAliveTimeout = time.Duration(config.KeepAlive) * time.Second*3
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

			streamCopy := func(dst io.Writer, src io.ReadCloser) chan struct{} {
				die := make(chan struct{})
				go func() {
					buf := xmitBuf.Get().([]byte)
					generic.CopyBuffer(dst, src, buf)
					xmitBuf.Put(buf)
					close(die)
				}()
				return die
			}

			select {
			case <-streamCopy(p1, p2):
			case <-streamCopy(p2, p1):
			}
		}()
	}
}

