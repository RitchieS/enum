package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

type Result struct {
	Domain string
	A      []string
}

var (
	Version   = "dev"
	Commit    = "none"
	BuildTime = "unknown"
	BuiltBy   = "unknown"
)

func main() {
	buf := bytes.Buffer{}
	domain := flag.String("domain", "", "target domain")
	showA := flag.Bool("a", false, "query for A records")
	output := flag.String("output", "", "file to write output")
	silent := flag.Bool("silent", false, "display only the results in the output")
	version := flag.Bool("version", false, "display version information")

	flag.Parse()

	if *version {
		fmt.Printf("Version: %s\n", Version)
		fmt.Printf("Commit: %s\n", Commit)
		fmt.Printf("BuildTime: %s\n", BuildTime)
		fmt.Printf("BuiltBy: %s\n", BuiltBy)
		os.Exit(0)
	}

	if *silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}

	if *domain == "" {
		flag.Usage()
		os.Exit(1)
	}

	subfinderRunner, err := runner.NewRunner(&runner.Options{
		Threads:            10,                              // Thread controls the number of threads to use for active enumerations
		Timeout:            30,                              // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 10,                              // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
		Resolvers:          resolve.DefaultResolvers,        // Use the default list of resolvers by marshaling it to the config
		Sources:            passive.DefaultSources,          // Use the default list of passive sources
		AllSources:         passive.DefaultAllSources,       // Use the default list of all passive sources
		Recursive:          passive.DefaultRecursiveSources, // Use the default list of recursive sources
		Providers:          &runner.Providers{},             // Use empty api keys for all providers
	})
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	err = subfinderRunner.EnumerateSingleDomain(context.Background(), strings.TrimSpace(*domain), []io.Writer{&buf})
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	data, err := io.ReadAll(&buf)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	dnsxOptions := dnsx.DefaultOptions
	d, err := dnsx.New(dnsxOptions)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	var domains []Result
	domainList := strings.Split(string(data), "\n")

	for i, line := range domainList {
		percentage := percentage(i+1, len(domainList))
		// every 5 percent, print a progress bar
		if int(percentage)%5 == 0 && !*silent {
			fmt.Printf("\r[%s] %.2f%%", percentageBar(percentage), percentage)
		}

		if line != "" {
			domain, err := d.QueryOne(line)
			if err == nil && domain.A != nil {
				domains = append(domains, Result{Domain: line, A: domain.A})
			} else {
				continue
			}
		}
	}

	if !*silent {
		fmt.Printf("\n")
	}

	for _, domain := range domains {
		if *showA {
			fmt.Printf("%s: %s\n", domain.Domain, domain.A)
		} else {
			fmt.Printf("%s\n", domain.Domain)
		}
	}

	gologger.Info().Msgf("Found %d active domains for %s", len(domains), *domain)

	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		for _, domain := range domains {
			if *showA {
				f.WriteString(fmt.Sprintf("%s: %s\n", domain.Domain, domain.A))
			} else {
				f.WriteString(fmt.Sprintf("%s\n", domain.Domain))
			}
		}

		gologger.Info().Msgf("Saved %d active domains for %s to %s", len(domains), *domain, *output)
	}
}

func percentage(current int, total int) float64 {
	return float64(current) / float64(total) * 100
}

func percentageBar(percentage float64) string {
	bar := strings.Repeat("#", (int(percentage)/10)*2)
	bar += strings.Repeat(" ", (int(100-percentage)/10)*2)
	return bar
}
