package main

import (
	"os"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
)

func App() *cli.App {
	app := &cli.App{
		Name:                      "coffee-chain-api",
		HelpName:                  "",
		Usage:                     "",
		UsageText:                 "",
		Args:                      false,
		ArgsUsage:                 "",
		Version:                   "",
		Description:               "",
		DefaultCommand:            "",
		Commands:                  nil,
		Flags:                     nil,
		EnableBashCompletion:      false,
		HideHelp:                  false,
		HideHelpCommand:           false,
		HideVersion:               false,
		BashComplete:              nil,
		Before:                    nil,
		After:                     nil,
		Action:                    nil,
		CommandNotFound:           nil,
		OnUsageError:              nil,
		InvalidFlagAccessHandler:  nil,
		Compiled:                  time.Time{},
		Authors:                   nil,
		Copyright:                 "",
		Reader:                    nil,
		Writer:                    nil,
		ErrWriter:                 nil,
		ExitErrHandler:            nil,
		Metadata:                  nil,
		ExtraInfo:                 nil,
		CustomAppHelpTemplate:     "",
		SliceFlagSeparator:        "",
		DisableSliceFlagSeparator: false,
		UseShortOptionHandling:    false,
		Suggest:                   false,
		AllowExtFlags:             false,
		SkipFlagParsing:           false,
	}
}

func main() {
	err := App().Run(os.Args)
	if err != nil {
		log.Fatal().Err(err).Msg("running application")
	}
}
