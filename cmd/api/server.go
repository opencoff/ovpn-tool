package main

import (
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
	cmd := exec.Command("ovpn-tool", args...)
	cmd.Env = append(cmd.Env, "PASSWD_FILE="+svr.pwFile)
	return cmd
}

func (svr *server) setupRoutes(r gin.IRouter) {
	r.GET("/client_ips", svr.GetIPList)
	r.GET("/client/:cn", svr.GetClient)
	r.POST("/client/:cn", svr.CreateClient)
	r.DELETE("/client/:cn", svr.DeleteClient)
}

func (svr *server) GetClient(c *gin.Context) {
	cn := c.Param("cn")

	validUntil, err := getExpiry(svr.buildCmd("list", cn).Output())
	if err != nil {
		c.AbortWithError(500, err)
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
		"valid_until": validUntil,
	})
}

func (svr *server) GetIPList(c *gin.Context) {
	c.JSON(200, svr.ccd.currentIPMap())
}

func (svr *server) CreateClient(c *gin.Context) {
	cn := c.Param("cn")

	// add cert
	cmd := svr.buildCmd("client", cn)
	err := cmd.Run()
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

	// create IP in the CCD
	if err := svr.ccd.writeNextStaticIP(cn); err != nil {
		c.AbortWithError(500, err)
		return
	}

	c.Data(200, "text/plain", data)
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
	cmd = exec.Command("systemctl", "restart", "openpvn")
	if err := cmd.Run(); err != nil {
		c.AbortWithError(500, err)
		return
	}
}
