package main

import (
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	"github.com/shipyard/shpd/commands"
	"github.com/shipyard/shpd/version"
)

func main() {
	app := cli.NewApp()
	app.Name = "shpd"
	app.Usage = "DNS access for Shipyard"
	app.Version = version.Version + " (" + version.GitCommit + ")"
	app.Author = ""
	app.Email = ""
	app.Before = func(c *cli.Context) error {
		if c.GlobalBool("debug") {
			log.SetLevel(log.DebugLevel)
		}
		return nil
	}
	app.Commands = []cli.Command{
		commands.CmdServer,
	}
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug, D",
			Usage: "enable debug",
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
