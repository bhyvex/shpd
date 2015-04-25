package commands

import (
	log "github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	"github.com/shipyard/shpd/api"
	"github.com/shipyard/shpd/version"
)

var CmdServer = cli.Command{
	Name:   "server",
	Usage:  "run server",
	Action: cmdServer,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "listen, l",
			Usage: "listen address",
			Value: ":8080",
		},
		cli.StringFlag{
			Name:  "redis-addr, r",
			Usage: "Redis address",
			Value: "redis:6379",
		},
		cli.StringFlag{
			Name:  "redis-password, p",
			Usage: "Redis password",
			Value: "",
		},
	},
}

func cmdServer(c *cli.Context) {
	listenAddr := c.String("listen")
	redisAddr := c.String("redis-addr")
	redisPassword := c.String("redis-password")

	log.Infof("shpd version %s", version.Version)
	log.Infof("listening on %s", listenAddr)

	a, err := api.NewApi(listenAddr, redisAddr, redisPassword)
	if err != nil {
		log.Fatal(err)
	}

	if err := a.Run(); err != nil {
		log.Fatal(err)
	}
}
