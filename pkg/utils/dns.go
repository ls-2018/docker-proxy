package utils

import (
	"encoding/binary"
	"net"
	"strings"
)

func ReplaceDotsWithLengthOctets(dnsName []byte) []uint8 {
	nameLen := len(dnsName)
	newDnsName := make([]byte, nameLen+1)
	cnt := 0
	for i := 0; i < nameLen; i++ {
		//If dot character or end of string is detected
		if dnsName[i] == 46 || dnsName[i] == 0 {
			//Put length octet with value [cnt] at location [i-cnt]
			newDnsName[i-cnt] = uint8(cnt)

			//Break loop if zero
			if dnsName[i] == 0 {
				cnt = i + 1
				break
			}

			//Reset counter
			cnt = -1
		}

		newDnsName[i+1] = dnsName[i]

		//Count number of characters until the dot character
		cnt++
	}

	newDnsName[cnt] = 0

	res := make([]uint8, len(newDnsName))
	for i, v := range newDnsName {
		res[i] = v
	}
	return res
}

func DecodeDNSName(data []uint8) string {
	var labels []string
	for i := 0; i < len(data); {
		l := int(data[i])
		if l == 0 {
			break // 结束
		}
		i++
		if i+l > len(data) {
			return ""
		}
		labels = append(labels, string(data[i:i+l]))
		i += l
	}
	return strings.Join(labels, ".")
}
func U32ToIP(ip uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, ip)
	return net.IP(b).String()
}

func Ip2Uint32(ip string) uint32 {
	ip = strings.TrimSpace(ip)
	return binary.BigEndian.Uint32(net.ParseIP(ip).To4())
}

func HumanIps(data []uint32) string {
	var res []string
	for _, v := range data {
		if v != 0 {
			res = append(res, U32ToIP(v))
		}
	}
	return strings.Join(res, ",")
}
