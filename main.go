package main

import (
	"os"

	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
)

func App() *cli.App {
	return &cli.App{
		Name:           "coffee-chain-api",
		HelpName:       "",
		Usage:          "",
		UsageText:      "",
		Args:           false,
		ArgsUsage:      "",
		Version:        "",
		Description:    "",
		DefaultCommand: "server",
		Commands: []*cli.Command{
			{
				Name: "server",
				Action: func(context *cli.Context) error {

				},
				Subcommands:            ,
				Flags:                  nil,
				SkipFlagParsing:        false,
				HideHelp:               false,
				HideHelpCommand:        false,
				Hidden:                 false,
				UseShortOptionHandling: false,
				HelpName:               "",
				CustomHelpTemplate:     "",
			},
		},
	}
}

func main() {
	err := App().Run(os.Args)
	if err != nil {
		log.Fatal().Err(err).Msg("running application")
	}
}
