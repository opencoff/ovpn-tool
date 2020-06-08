package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
)

func getExpiry(data []byte, err error) (string, error) {
	if err != nil {
		return "", err
	}
	bits := strings.Split(string(data), "(")
	validUntil := strings.Split(bits[3], ")")[0]
	bits = strings.Split(validUntil, " ")
	return fmt.Sprintf("%sT%sZ", bits[3], bits[4]), nil
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
	// remove network address and broadcast address
	return ips[1 : len(ips)-1], nil
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

func (ccd CCD) read(cn string) (string, error) {
	data, err := ioutil.ReadFile(filepath.Join(ccd.path, cn))
	return string(data), err
}

func (ccd CCD) writeNextStaticIP(cn string) error {
	return ccd.writeStaticIP(cn, ccd.nextAvailableIP())
}

func (ccd CCD) writeStaticIP(cn, ip string) error {
	data := fmt.Sprintf("ifconfig-push %s %s", ip, ccd.gatewayIP)
	return ioutil.WriteFile(filepath.Join(ccd.path, cn), []byte(data), 600)
}

func (ccd CCD) currentIPMap() map[string]string {
	ips := map[string]string{}
	matches, _ := filepath.Glob(filepath.Join(ccd.path, "*"))
	for _, fn := range matches {
		data, err := ioutil.ReadFile(fn)
		if err != nil {
			continue
		}
		ips[filepath.Base(fn)] = strings.Split(string(data), " ")[2]
	}

	return ips
}

func (ccd CCD) currentIPs() []string {
	ips := []string{}
	matches, _ := filepath.Glob(filepath.Join(ccd.path, "*"))
	for _, fn := range matches {
		data, err := ioutil.ReadFile(fn)
		if err != nil {
			continue
		}
		ips = append(ips, strings.Split(string(data), " ")[2])
	}

	return ips
}

func (ccd CCD) nextAvailableIP() string {
	hosts, _ := cidrHosts(ccd.vpnSubnet)
	ip := nextAvailableIP(hosts, ccd.currentIPs())
	return ip
}
