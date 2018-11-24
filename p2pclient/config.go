package main

import (
	"encoding/json"
	"os"
)

// Config for client
type Config struct {
	ListenTcp    string `json:"listentcp"`
	TargetTcp    string `json:"targettcp"`
	BindUdp      string `json:"bindudp"`
	RemoteUdp    string `json:"remoteudp"`
	Key          string `json:"key"`
	Passwd		 string `json:"passwd"`
	Crypt        string `json:"crypt"`
	Mode         string `json:"mode"`
	AutoExpire   int    `json:"autoexpire"`
	MTU          int    `json:"mtu"`
	SndWnd       int    `json:"sndwnd"`
	RcvWnd       int    `json:"rcvwnd"`
	DataShard    int    `json:"datashard"`
	ParityShard  int    `json:"parityshard"`
	DSCP         int    `json:"dscp"`
	NoComp       bool   `json:"nocomp"`
	AckNodelay   bool   `json:"acknodelay"`
	NoDelay      int    `json:"nodelay"`
	Interval     int    `json:"interval"`
	Resend       int    `json:"resend"`
	NoCongestion int    `json:"nc"`
	SockBuf      int    `json:"sockbuf"`
	KeepAlive    int    `json:"keepalive"`
	Log          string `json:"log"`
	SnmpLog      string `json:"snmplog"`
	SnmpPeriod   int    `json:"snmpperiod"`
	Quiet        bool   `json:"quiet"`
}

func parseJSONConfig(config *Config, path string) error {
	file, err := os.Open(path) // For read access.
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewDecoder(file).Decode(config)
}
