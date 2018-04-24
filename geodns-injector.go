/*
MIT License

Copyright (c) 2018 StarBrilliant <m13253@hotmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


This product includes GeoLite2 data created by MaxMind, available from
http://www.maxmind.com . The GeoLite2 databases are distributed under the
Creative Commons Attribution-ShareAlike 4.0 International License.
*/

package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/m13253/dns-over-https/json-dns"
	"github.com/miekg/dns"
	"github.com/oschwald/geoip2-golang"
)

type DNSHandler struct {
	upstreamAddr []string
	udpClient    *dns.Client
	tcpClient    *dns.Client
	geoip2DB     *geoip2.Reader
	passContry   string
	replaceIP    net.IP
}

func main() {
	listenAddr := flag.String("listen", "[::1]:16353", "Listen address")
	upstreamAddrStr := flag.String("upstream", "[::1]:5380", "Upstream addresses, separated with comma if multiple")
	geoip2DB := flag.String("geoip", "/usr/local/share/GeoIP/GeoLite2-Country.mmdb", "GeoIP2 country database")
	passCountry := flag.String("country", "CN", "Passthrough country")
	replaceStr := flag.String("replace", "223.5.5.0", "Replacement IP address")
	flag.Parse()

	upstreamAddr := strings.Split(*upstreamAddrStr, ",")
	replaceIP := net.ParseIP(*replaceStr)
	if replaceIP == nil {
		log.Fatalln("Invalid replacement IP")
	}
	handler, err := NewDNSHandler(upstreamAddr, *geoip2DB, *passCountry, replaceIP)
	if err != nil {
		log.Fatalln(err)
	}
	udpServer := &dns.Server{
		Addr:    *listenAddr,
		Net:     "udp",
		Handler: handler,
		UDPSize: dns.DefaultMsgSize,
	}
	tcpServer := &dns.Server{
		Addr:    *listenAddr,
		Net:     "tcp",
		Handler: handler,
	}
	results := make(chan error, 2)
	go func() {
		err := udpServer.ListenAndServe()
		results <- err
	}()
	go func() {
		err := tcpServer.ListenAndServe()
		results <- err
	}()
	err = <-results
	if err != nil {
		log.Fatalln(err)
	}
	err = <-results
	if err != nil {
		log.Fatalln(err)
	}
}

func NewDNSHandler(upstreamAddr []string, geoip2DBFile string, passCountry string, replaceIP net.IP) (*DNSHandler, error) {
	geoip2DB, err := geoip2.Open(geoip2DBFile)
	if err != nil {
		return nil, err
	}
	return &DNSHandler{
		upstreamAddr: upstreamAddr,
		udpClient: &dns.Client{
			Net:     "udp",
			UDPSize: dns.DefaultMsgSize,
			Timeout: 10 * time.Second,
		},
		tcpClient: &dns.Client{
			Net:     "tcp",
			Timeout: 10 * time.Second,
		},
		geoip2DB:   geoip2DB,
		passContry: passCountry,
		replaceIP:  replaceIP,
	}, nil
}

func (h *DNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) != 1 {
		log.Println("Number of questions is not 1")
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.Rcode = dns.RcodeFormatError
		w.WriteMsg(reply)
		return
	}

	question := &r.Question[0]
	// knot-resolver scrambles capitalization, I think it is unfriendly to cache
	questionName := strings.ToLower(question.Name)
	questionType := ""
	if qtype, ok := dns.TypeToString[question.Qtype]; ok {
		questionType = qtype
	} else {
		questionType = strconv.Itoa(int(question.Qtype))
	}

	fmt.Printf("%s - - [%s] \"%s IN %s\"\n", w.RemoteAddr(), time.Now().Format("02/Jan/2006:15:04:05 -0700"), questionName, questionType)

	question.Name = questionName
	opt := r.IsEdns0()
	if opt == nil {
		opt = new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetUDPSize(dns.DefaultMsgSize)
		opt.SetDo(false)
		r.Extra = append([]dns.RR{opt}, r.Extra...)
	}
	var edns0Subnet *dns.EDNS0_SUBNET
	for _, option := range opt.Option {
		if option.Option() == dns.EDNS0SUBNET {
			edns0Subnet = option.(*dns.EDNS0_SUBNET)
			break
		}
	}
	ednsClientAddress, ednsClientNetmask := h.findClientIP(w, r)
	if edns0Subnet == nil {
		ednsClientFamily := uint16(0)
		if ipv4 := ednsClientAddress.To4(); ipv4 != nil {
			ednsClientFamily = 1
			ednsClientAddress = ipv4
			ednsClientNetmask = 24
		} else {
			ednsClientFamily = 2
			ednsClientNetmask = 48
		}
		edns0Subnet = new(dns.EDNS0_SUBNET)
		edns0Subnet.Code = dns.EDNS0SUBNET
		edns0Subnet.Family = ednsClientFamily
		edns0Subnet.SourceNetmask = ednsClientNetmask
		edns0Subnet.SourceScope = 0
		edns0Subnet.Address = ednsClientAddress
		opt.Option = append(opt.Option, edns0Subnet)
	}
	oldEdns0Subnet := *edns0Subnet

	country, err := h.geoip2DB.Country(ednsClientAddress)
	if ednsClientAddress != nil {
		if err != nil {
			log.Println(err)
		}
		fmt.Printf("GeoIP: [%s] %s\n", country.Country.IsoCode, ednsClientAddress)
	} else {
		fmt.Println("GeoIP: [  ] nil")
	}
	isIPReplaced := false
	if country.Country.IsoCode != h.passContry {
		isIPReplaced = true
		if ipv4 := h.replaceIP.To4(); ipv4 != nil {
			edns0Subnet.Family = 1
			edns0Subnet.SourceNetmask = 24
			edns0Subnet.SourceScope = 0
			edns0Subnet.Address = ipv4
		} else {
			edns0Subnet.Family = 2
			edns0Subnet.SourceNetmask = 48
			edns0Subnet.SourceScope = 0
			edns0Subnet.Address = h.replaceIP
		}
	}

	resp, err := h.doDNSQuery(r)
	if err != nil {
		log.Println(err)
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.Rcode = dns.RcodeServerFailure
		w.WriteMsg(reply)
		return
	}

	respOPT := resp.IsEdns0()
	if respOPT == nil {
		respOPT = new(dns.OPT)
		respOPT.Hdr.Name = "."
		respOPT.Hdr.Rrtype = dns.TypeOPT
		respOPT.SetUDPSize(dns.DefaultMsgSize)
		respOPT.SetDo(false)
		resp.Extra = append([]dns.RR{respOPT}, resp.Extra...)
	}
	var respEdns0Subnet *dns.EDNS0_SUBNET
	for _, option := range respOPT.Option {
		if option.Option() == dns.EDNS0SUBNET {
			respEdns0Subnet = option.(*dns.EDNS0_SUBNET)
			break
		}
	}
	if respEdns0Subnet == nil {
		respEdns0Subnet = new(dns.EDNS0_SUBNET)
		*respEdns0Subnet = oldEdns0Subnet
		respOPT.Option = append(respOPT.Option, respEdns0Subnet)
	} else if isIPReplaced {
		*respEdns0Subnet = oldEdns0Subnet
	}
	if respEdns0Subnet.SourceScope == 0 {
		respEdns0Subnet.SourceScope = respEdns0Subnet.SourceNetmask
		if respEdns0Subnet.Family == 1 && respEdns0Subnet.SourceScope > 24 {
			respEdns0Subnet.SourceScope = 24
		} else if respEdns0Subnet.Family == 2 && respEdns0Subnet.SourceScope > 48 {
			respEdns0Subnet.SourceScope = 48
		}
	}

	err = w.WriteMsg(resp)
	if err != nil {
		log.Println(err)
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.Rcode = dns.RcodeServerFailure
		w.WriteMsg(reply)
		return
	}
}

func (h *DNSHandler) doDNSQuery(msg *dns.Msg) (resp *dns.Msg, err error) {
	numServers := len(h.upstreamAddr)
	server := h.upstreamAddr[rand.Intn(numServers)]
	resp, _, err = h.udpClient.Exchange(msg, server)
	if err == dns.ErrTruncated {
		log.Println(err)
		resp, _, err = h.tcpClient.Exchange(msg, server)
	}
	if err == nil {
		return
	}
	log.Println(err)
	return
}

var (
	ipv4Mask24 = net.IPMask{255, 255, 255, 0}
	ipv6Mask48 = net.CIDRMask(48, 128)
)

func (h *DNSHandler) findClientIP(w dns.ResponseWriter, r *dns.Msg) (ednsClientAddress net.IP, ednsClientNetmask uint8) {
	ednsClientNetmask = 255
	if opt := r.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			if option.Option() == dns.EDNS0SUBNET {
				edns0Subnet := option.(*dns.EDNS0_SUBNET)
				ednsClientAddress = edns0Subnet.Address
				ednsClientNetmask = edns0Subnet.SourceNetmask
				return
			}
		}
	}
	remoteAddr, err := net.ResolveUDPAddr("udp", w.RemoteAddr().String())
	if err != nil {
		return
	}
	if ip := remoteAddr.IP; jsonDNS.IsGlobalIP(ip) {
		if ipv4 := ip.To4(); ipv4 != nil {
			ednsClientAddress = ipv4.Mask(ipv4Mask24)
			ednsClientNetmask = 24
		} else {
			ednsClientAddress = ip.Mask(ipv6Mask48)
			ednsClientNetmask = 48
		}
	}
	return
}
