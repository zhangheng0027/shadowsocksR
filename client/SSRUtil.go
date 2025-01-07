package client

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	shadowsocksr "github.com/zhangheng0027/shadowsocksR"
	"github.com/zhangheng0027/shadowsocksR/obfs"
	"github.com/zhangheng0027/shadowsocksR/protocol"
	"github.com/zhangheng0027/shadowsocksR/ssr"
	cipher "github.com/zhangheng0027/shadowsocksR/streamCipher"
	"github.com/zhangheng0027/shadowsocksR/tools/socks"
	"golang.org/x/net/proxy"
	"net"
	url2 "net/url"
	"strings"
)

//// 解析 url
//func DecodeUrl(url string) {
//	// 如果是 ssr 开头
//	if url[:6] == "ssr://" {
//		decodeSSRUrl(url[6:])
//	}
//}

func NewSSR1(s string) (*SSR, error) {
	return NewSSR2(s, proxy.Direct)
}

func NewSSR2(url string, d proxy.Dialer) (*SSR, error) {
	return NewSSR3(url, d, logrus.New())
}

func NewSSR3(url string, d proxy.Dialer, log *logrus.Logger) (*SSR, error) {
	if url[:6] == "ssr://" {
		url = url[6:]
	}

	// 解析 ssr url
	url = strings.TrimRight(url, "\n")
	url = strings.TrimRight(url, "\r")
	url = strings.TrimRight(url, " ")
	url = DecodeBase64ToStr(url)

	split := strings.Split(url, "?")
	query, err := url2.ParseQuery(split[1])
	if err != nil {
		return nil, err
	}

	i := strings.Split(split[0], ":")
	s := &SSR{
		EncryptMethod:   i[3],
		EncryptPassword: DecodeBase64ToStr(i[5]),
		addr:            i[0] + ":" + i[1],
		Protocol:        i[2],
		ProtocolParam:   DecodeBase64ToStr(query.Get("protoparam")),
		Obfs:            i[4],
		ObfsParam:       DecodeBase64ToStr(query.Get("obfsparam")),
		Remarks:         DecodeBase64ToStr(query.Get("remarks")),
		dialer:          d,
		log:             log,
	}

	if len(s.Protocol) == 0 {
		s.Protocol = "origin"
	} else {
		s.Protocol = strings.ReplaceAll(s.Protocol, "_compatible", "")
	}

	if len(s.Obfs) == 0 {
		s.Obfs = "plain"
	} else {
		s.Obfs = strings.ReplaceAll(s.Obfs, "_compatible", "")
	}

	return s, nil

}

func DecodeBase64ToStr(val string) string {
	// 补齐长度
	switch len(val) % 4 {
	case 1:
		val = val + "="
	case 2:
		val = val + "="
	case 3:
		val = val + "="
	}
	// 解码
	decodeString, _ := base64.URLEncoding.DecodeString(val)
	return string(decodeString)
}

func (s *SSR) DialProxy(network, addr string, d proxy.Dialer) (net.Conn, error) {
	target := socks.ParseAddr(addr)
	if target == nil {
		return nil, errors.New("[ssr] unable to parse address: " + addr)
	}

	cipher, err := cipher.NewStreamCipher(s.EncryptMethod, s.EncryptPassword)
	if err != nil {
		return nil, err
	}

	c, err := d.Dial("tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("[ssr] dial to %s error: %w", s.addr, err)
	}

	ssrconn := shadowsocksr.NewSSTCPConn(c, cipher)
	if ssrconn.Conn == nil || ssrconn.RemoteAddr() == nil {
		return nil, errors.New("[ssr] nil connection")
	}

	// should initialize obfs/protocol now
	tcpAddr := ssrconn.RemoteAddr().(*net.TCPAddr)
	port := tcpAddr.Port

	ssrconn.IObfs = obfs.NewObfs(s.Obfs)
	if ssrconn.IObfs == nil {
		return nil, errors.New("[ssr] unsupported obfs type: " + s.Obfs)
	}

	obfsServerInfo := &ssr.ServerInfo{
		Host:   tcpAddr.IP.String(),
		Port:   uint16(port),
		TcpMss: 1460,
		Param:  s.ObfsParam,
	}
	ssrconn.IObfs.SetServerInfo(obfsServerInfo)

	ssrconn.IProtocol = protocol.NewProtocol(s.Protocol)
	if ssrconn.IProtocol == nil {
		return nil, errors.New("[ssr] unsupported protocol type: " + s.Protocol)
	}

	protocolServerInfo := &ssr.ServerInfo{
		Host:   tcpAddr.IP.String(),
		Port:   uint16(port),
		TcpMss: 1460,
		Param:  s.ProtocolParam,
	}
	ssrconn.IProtocol.SetServerInfo(protocolServerInfo)

	if s.ObfsData == nil {
		s.ObfsData = ssrconn.IObfs.GetData()
	}
	ssrconn.IObfs.SetData(s.ObfsData)

	if s.ProtocolData == nil {
		s.ProtocolData = ssrconn.IProtocol.GetData()
	}
	ssrconn.IProtocol.SetData(s.ProtocolData)
	s.log.Printf("proxy %v <-> %v <-> %v\n", ssrconn.LocalAddr(), ssrconn.RemoteAddr(), target)
	if _, err := ssrconn.Write(target); err != nil {
		ssrconn.Close()
		return nil, err
	}
	return ssrconn, err
}
