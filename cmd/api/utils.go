package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
)

//meme                      0x2add4c4b1f559973fef06acb253694d9d (valid until 2022-06-09 12:40:48 +0000 UTC)
func getExpiry(data []byte, err error) (string, string, string, error) {
	if err != nil {
		return "", "", "", err
	}

	bits := strings.Split(string(data), "(")
	cnFp := strings.Split(strings.TrimSpace(bits[0]), " ")

	cn := cnFp[0]
	fingerprint := cnFp[len(cnFp)-1]
	validUntil := strings.Split(bits[1], ")")[0]
	bits = strings.Split(validUntil, " ")
	date := fmt.Sprintf("%sT%sZ", bits[2], bits[3])
	return cn, fingerprint, date, nil
}

func cidrHosts(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	// remove network address, broadcast and gateway address
	return ips[2 : len(ips)-1], nil
}

func nextAvailableIP(available, taken []string) string {
	for _, newIP := range available {
		exists := false
		for _, ip := range taken {
			if ip == newIP {
				exists = true
			}
		}

		if !exists {
			return newIP
		}
	}

	return ""
}

//  http://play.golang.org/p/m8TNTtygK0
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

type CCD struct {
	path      string
	vpnSubnet string
	gatewayIP string
}

func (ccd CCD) delete(cn string) error {
	return os.Remove(filepath.Join(ccd.path, cn))
}

func (ccd CCD) readIP(cn string) (string, error) {
	data, err := ccd.read(cn)
	if err != nil {
		return "", err
	}

	return strings.Split(data, " ")[1], nil
}

func (ccd CCD) read(cn string) (string, error) {
	data, err := ioutil.ReadFile(filepath.Join(ccd.path, cn))
	return string(data), err
}

func (ccd CCD) writeNextStaticIP(cn string) error {
	return ccd.writeStaticIP(cn, ccd.nextAvailableIP())
}

func (ccd CCD) writeStaticIP(cn, ip string) error {
	_, ipv4Net, err := net.ParseCIDR(ccd.vpnSubnet)
	if err != nil {
		return err
	}

	subnet, err := ipv4MaskString(ipv4Net.Mask)
	if err != nil {
		return err
	}

	data := fmt.Sprintf("ifconfig-push %s %s", ip, subnet)
	return ioutil.WriteFile(filepath.Join(ccd.path, cn), []byte(data), 0600)
}

func (ccd CCD) currentIPMap() map[string]string {
	ips := map[string]string{}
	matches, _ := filepath.Glob(filepath.Join(ccd.path, "*"))
	for _, fn := range matches {
		ip, err := ccd.readIP(filepath.Base(fn))
		if err != nil {
			continue
		}
		ips[filepath.Base(fn)] = ip
	}

	return ips
}

func (ccd CCD) currentIPs() []string {
	ips := []string{}
	matches, _ := filepath.Glob(filepath.Join(ccd.path, "*"))
	for _, fn := range matches {
		ip, err := ccd.readIP(filepath.Base(fn))
		if err != nil {
			continue
		}
		ips = append(ips, ip)
	}

	return ips
}

func (ccd CCD) nextAvailableIP() string {
	hosts, _ := cidrHosts(ccd.vpnSubnet)
	ip := nextAvailableIP(hosts, ccd.currentIPs())
	return ip
}

func ipv4MaskString(m []byte) (string, error) {
	if len(m) != 4 {
		return "", errors.New("ipv4Mask: len must be 4 bytes")
	}

	return fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3]), nil
}
