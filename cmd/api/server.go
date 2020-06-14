package main

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/gin-gonic/gin"
)

type server struct {
	toolPath      string // path to the ovpn-tool binary
	dbPath        string // path to the ovpn-tool database file
	domainName    string // the domain name of the VPN server
	serverCRLPath string // the path to the CRL file used by the openvpn process
	pwFile        string
	ccd           CCD
}

func (svr *server) buildCmd(args ...string) *exec.Cmd {
	args = append([]string{svr.dbPath}, args...)
	cmd := exec.Command(svr.toolPath, args...)
	cmd.Env = append(cmd.Env, "PASSWD_FILE="+svr.pwFile)
	log.Println(cmd.Env, svr.toolPath, args)
	return cmd
}

func (svr *server) setupRoutes(r gin.IRouter) {
	r.GET("/client_ips", svr.GetIPList)
	r.GET("/clients", svr.ListClients)
	r.GET("/client/:cn", svr.GetClient)
	r.GET("/client/:cn/config", svr.GetClientConf)
	r.POST("/client/:cn", svr.CreateClient)
	r.DELETE("/client/:cn", svr.DeleteClient)
}

func (svr *server) ListClients(c *gin.Context) {
	data, err := svr.buildCmd("list").Output()
	if err != nil {
		c.AbortWithError(500, err)
		return
	}

	ips := svr.ccd.currentIPMap()
	cls := map[string]interface{}{}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.Contains(line, "server 0x") {
			continue
		}

		cn, fp, vu, _ := getExpiry([]byte(line), nil)

		cls[cn] = map[string]string{
			"ip":          ips[cn],
			"fingerprint": fp,
			"valid_until": vu,
		}
	}

	c.JSON(200, cls)
}

func (svr *server) GetClientConf(c *gin.Context) {
	cn := c.Param("cn")
	cmd := svr.buildCmd("export", "-s", svr.domainName, cn)
	data, err := cmd.Output()
	if err != nil {
		c.AbortWithError(500, err)
		return
	}

	c.Data(200, "text/plain", data)
}

func (svr *server) GetClient(c *gin.Context) {
	cn := c.Param("cn")

	_cn, fingerprint, validUntil, err := getExpiry(svr.buildCmd("list", cn).Output())
	if err != nil {
		c.AbortWithError(500, err)
		return
	}

	if _cn != cn {
		c.AbortWithError(403, fmt.Errorf("common name did not match: requested %s but got %s", cn, _cn))
		return
	}

	ccd, err := svr.ccd.read(cn)
	if err != nil {
		c.AbortWithError(500, err)
		return
	}

	bits := strings.Split(ccd, " ")
	ip := bits[1]

	c.JSON(200, map[string]string{
		"ip":          ip,
		"fingerprint": fingerprint,
		"valid_until": validUntil,
	})
}

func (svr *server) GetIPList(c *gin.Context) {
	c.JSON(200, svr.ccd.currentIPMap())
}

func (svr *server) CreateClient(c *gin.Context) {
	cn := c.Param("cn")

	var ip string
	var err error

	// create IP in the CCD
	if ip, err = svr.ccd.readIP(cn); err != nil {
		if err := svr.ccd.writeNextStaticIP(cn); err != nil {
			c.AbortWithError(500, err)
			return
		}
		ip, _ = svr.ccd.readIP(cn)
	}

	// add cert
	cmd := svr.buildCmd("client", cn)
	buf := bytes.NewBufferString("")
	cmd.Stderr = buf
	err = cmd.Run()
	if err != nil {
		switch {
		case strings.Contains(buf.String(), "common name exists in DB"):
		default:
			c.AbortWithError(500, err)
			return
		}
	}

	_, fingerprint, validUntil, err := getExpiry(svr.buildCmd("list", cn).Output())
	if err != nil {
		c.AbortWithError(500, err)
		return
	}

	// return cert
	cmd = svr.buildCmd("export", "-s", svr.domainName, cn)
	data, err := cmd.Output()
	if err != nil {
		c.AbortWithError(500, err)
		return
	}

	data = append([]byte("# fingerprint="+fingerprint+"\n"), data...)

	c.JSON(200, map[string]string{
		"ip":          ip,
		"fingerprint": fingerprint,
		"valid_until": validUntil,
		"config":      string(data),
	})
}

func (svr *server) DeleteClient(c *gin.Context) {
	cn := c.Param("cn")

	// delete cert
	cmd := svr.buildCmd("delete", cn)
	if err := cmd.Run(); err != nil {
		c.AbortWithError(500, err)
		return
	}

	// regen CRL
	cmd = svr.buildCmd("crl", "-o", svr.serverCRLPath)
	if err := cmd.Run(); err != nil {
		c.AbortWithError(500, err)
		return
	}

	_ = svr.ccd.delete(cn)

	// restart server
	// cmd = exec.Command("systemctl", "restart", "openpvn")
	// if err := cmd.Run(); err != nil {
	// 	c.AbortWithError(500, err)
	// 	return
	// }

	c.Status(204)
}
