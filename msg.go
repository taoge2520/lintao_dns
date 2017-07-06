/*dns报文格式：
+---------------------+
    |        Header       | 报文头
    +---------------------+
    |       Question      | 查询的问题
    +---------------------+
    |        Answer       | 应答
    +---------------------+
    |      Authority      | 授权应答
    +---------------------+
    |      Additional     | 附加信息
    +---------------------+
报文头部
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
question格式：
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	// valid dnsRR_Header.Rrtype and dnsQuestion.qtype
	dnsTypeA     = 1
	dnsTypeNS    = 2
	dnsTypeMD    = 3
	dnsTypeMF    = 4
	dnsTypeCNAME = 5
	dnsTypeSOA   = 6
	dnsTypeMB    = 7
	dnsTypeMG    = 8
	dnsTypeMR    = 9
	dnsTypeNULL  = 10
	dnsTypeWKS   = 11
	dnsTypePTR   = 12
	dnsTypeHINFO = 13
	dnsTypeMINFO = 14
	dnsTypeMX    = 15
	dnsTypeTXT   = 16
	dnsTypeAAAA  = 28
	dnsTypeSRV   = 33

	// valid dnsQuestion.qtype only
	dnsTypeAXFR  = 252
	dnsTypeMAILB = 253
	dnsTypeMAILA = 254
	dnsTypeALL   = 255

	// valid dnsQuestion.qclass
	dnsClassINET   = 1
	dnsClassCSNET  = 2
	dnsClassCHAOS  = 3
	dnsClassHESIOD = 4
	dnsClassANY    = 255

	// dnsMsg.rcode
	dnsRcodeSuccess        = 0
	dnsRcodeFormatError    = 1
	dnsRcodeServerFailure  = 2
	dnsRcodeNameError      = 3
	dnsRcodeNotImplemented = 4
	dnsRcodeRefused        = 5
)

type DNSHeader struct {
	ID         uint16
	FlagHeader uint16 //报文头
	QDCOUNT    uint16
	ANCOUNT    uint16 //RRs is Resource Records
	NSCOUNT    uint16
	ARCOUNT    uint16
}

func (header *DNSHeader) SetFlag(QR uint16, OperationCode uint16, AuthoritativeAnswer uint16, Truncation uint16, RecursionDesired uint16, RecursionAvailable uint16, ResponseCode uint16) {
	header.FlagHeader = QR<<15 + OperationCode<<11 + AuthoritativeAnswer<<10 + Truncation<<9 + RecursionDesired<<8 + RecursionAvailable<<7 + ResponseCode
}

type DNSQuery struct {
	//Name          string `net:"domain-name"`
	QuestionType  uint16
	QuestionClass uint16
}

type dnsAnswer struct {
	Name   uint16
	Qtype  uint16
	Qclass uint16
	QLive  uint32
	QLen   uint16
	CName  string
}

func ParseDomainName(domain string) []byte {

	//"www.google.com"->"0x03www0x06google0x03com0x00"

	var (
		buffer   bytes.Buffer
		segments []string = strings.Split(domain, ".")
	)
	for _, seg := range segments {
		binary.Write(&buffer, binary.BigEndian, byte(len(seg)))
		binary.Write(&buffer, binary.BigEndian, []byte(seg))
	}
	binary.Write(&buffer, binary.BigEndian, byte(0x00))

	return buffer.Bytes()
}

func send(ns_server string, domain string, qtype uint16, time_set time.Duration) (dns Msg, err error) {
	var (
		dns_header   DNSHeader
		dns_question DNSQuery
	)

	dns_header.ID = 0xFFFF
	dns_header.SetFlag(0, 0, 0, 0, 1, 0, 0)
	dns_header.QDCOUNT = 1
	dns_header.ANCOUNT = 0
	dns_header.NSCOUNT = 0
	dns_header.ARCOUNT = 0

	//填充dns查询首部
	//dns_question.Name = "baidu.com."
	dns_question.QuestionType = qtype //ns
	dns_question.QuestionClass = 1

	var (
		conn net.Conn

		buffer bytes.Buffer
	)

	//DNS服务器的端口一般是53
	deadline := time.Now().Add(time_set)
	//conn, err = net.DialTimeout("udp", ns_server+":53", 10*time.Millisecond)
	//conn, err = Dial("udp", "10.10.100.51", ns_server+":53")
	conn, err = net.Dial("udp", ns_server+":53")
	if err != nil {
		//fmt.Println(err.Error())
		return
	}
	conn.SetDeadline(deadline)

	defer conn.Close()

	//buffer->DNS首部+查询内容+DNS查询首部
	binary.Write(&buffer, binary.BigEndian, dns_header)
	binary.Write(&buffer, binary.BigEndian, ParseDomainName(domain))
	binary.Write(&buffer, binary.BigEndian, dns_question)

	if _, err = conn.Write(buffer.Bytes()); err != nil {
		//fmt.Println(err.Error())
		return
	}

	msg := make([]byte, 512)
	if _, err = conn.Read(msg); err != nil {
		//fmt.Println(err.Error())
		return
	}

	if len(msg) == 0 {
		fmt.Println("no datas return")
		return
	}

	/*MsgHdr
	Compress bool
	Question []Question
	Answer   []RR // Holds the RR(s) of the answer section.
	Ns       []RR // Holds the RR(s) of the authority section.
	Extra    []RR // Holds the RR(s) of the additional section.*/

	dns.Unpack(msg)
	return
}
func Dial(network string, local string, remote string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   500 * time.Millisecond,
		KeepAlive: 1 * time.Second,
	}
	local = local + ":0" //端口0,系统会自动分配本机端口
	switch network {
	case "udp":
		addr, err := net.ResolveUDPAddr(network, local)
		if err != nil {
			return nil, err
		}
		dialer.LocalAddr = addr
	case "tcp":
		addr, err := net.ResolveTCPAddr(network, local)
		if err != nil {
			return nil, err
		}
		dialer.LocalAddr = addr
	}
	return dialer.Dial(network, remote)
}
