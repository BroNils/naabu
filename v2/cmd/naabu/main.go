package main

import (
	"github.com/BroNils/naabu/v2/pkg/runner"
	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"os"
	"os/signal"
)

func main() {
	// Parse the command line flags and read config files
	options := runner.ParseOptions()

	naabuRunner, err := runner.NewRunner(options)
	if err != nil {
		//gologger.Fatal().Msgf("Could not create runner: %s\n", err)
		panic(err)
	}
	// Setup graceful exits
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			naabuRunner.ShowScanResultOnExit()
			//gologger.Info().Msgf("CTRL+C pressed: Exiting\n")
			if options.ResumeCfg.ShouldSaveResume() {
				//gologger.Info().Msgf("Creating resume file: %s\n", runner.DefaultResumeFilePath())
				err := options.ResumeCfg.SaveResumeConfig()
				if err != nil {
					//gologger.Error().Msgf("Couldn't create resume file: %s\n", err)
					panic(err)
				}
			}
			naabuRunner.Close()
			os.Exit(1)
		}
	}()

	err = naabuRunner.RunEnumeration()
	if err != nil {
		//gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
		panic(err)
	}
	// on successful execution remove the resume file in case it exists
	options.ResumeCfg.CleanupResumeConfig()
}
