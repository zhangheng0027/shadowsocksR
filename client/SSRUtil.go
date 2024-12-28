package client

import (
	"encoding/base64"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
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
	if url[6:] != "ssr://" {
		url = url[6:]
	}

	// 解析 ssr url
	url = strings.TrimRight(url, "\n")
	url = strings.TrimRight(url, "\r")
	url = strings.TrimRight(url, " ")
	url = decodeBase64ToStr(url)

	split := strings.Split(url, "?")
	query, err := url2.ParseQuery(split[1])
	if err != nil {
		return nil, err
	}

	i := strings.Split(split[0], ":")
	s := &SSR{
		EncryptMethod:   i[3],
		EncryptPassword: decodeBase64ToStr(i[5]),
		addr:            i[0] + ":" + i[1],
		Protocol:        i[2],
		ProtocolParam:   decodeBase64ToStr(query.Get("protoparam")),
		Obfs:            i[4],
		ObfsParam:       decodeBase64ToStr(query.Get("obfsparam")),
		Remarks:         decodeBase64ToStr(query.Get("remarks")),
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

func decodeBase64ToStr(val string) string {
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
