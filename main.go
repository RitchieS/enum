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
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

type Result struct {
	Domain string
	IP     []string
}

var (
	Version   = "dev"
	Commit    = "none"
	BuildTime = "unknown"
	BuiltBy   = "unknown"
)

func main() {
	runnerInstance, err := runner.NewRunner(&runner.Options{
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
		log.Fatal(err)
	}

	buf := bytes.Buffer{}
	domain := flag.String("domain", "", "Domain to enumerate subdomains for")
	version := flag.Bool("version", false, "Show version")

	flag.Parse()

	if *version {
		fmt.Printf("Version: %s\n", Version)
		fmt.Printf("Commit: %s\n", Commit)
		fmt.Printf("BuildTime: %s\n", BuildTime)
		fmt.Printf("BuiltBy: %s\n", BuiltBy)
		os.Exit(0)
	}

	if *domain == "" {
		flag.Usage()
		os.Exit(1)
	}

	err = runnerInstance.EnumerateSingleDomain(context.Background(), strings.TrimSpace(*domain), []io.Writer{&buf})
	if err != nil {
		log.Fatal(err)
	}

	data, err := io.ReadAll(&buf)
	if err != nil {
		log.Fatal(err)
	}

	dataString := string(data)

	for _, line := range strings.Split(dataString, "\n") {
		fmt.Println(line)
	}

	// count the lines using strings.
	lines := 0
	for _, line := range strings.Split(dataString, "\n") {
		if line != "" {
			lines++
		}
	}

	log.Printf("Found %d domains", lines)

	dnsxOptions := dnsx.DefaultOptions

	//use dnsx
	d, err := dnsx.New(dnsxOptions)
	if err != nil {
		log.Fatal(err)
	}

	// create an empty
	var domains []Result

	for _, line := range strings.Split(dataString, "\n") {
		if line != "" {
			domain, err := d.QueryOne(line)
			if err == nil && domain.A != nil {
				domains = append(domains, Result{Domain: line, IP: domain.A})
			} else {
				continue
			}
		}
	}

	for _, domain := range domains {
		fmt.Printf("%s: %s\n", domain.Domain, domain.IP)
	}

	log.Printf("Found %d active domains", len(domains))
}
