# Enum

[![Go Reference](https://pkg.go.dev/badge/github.com/ritchies/enum.svg)](https://pkg.go.dev/github.com/ritchies/enum)
[![Go Report Card](https://goreportcard.com/badge/github.com/ritchies/enum)](https://goreportcard.com/report/github.com/ritchies/enum)
[![](https://img.shields.io/github/workflow/status/ritchies/enum/Tests?longCache=tru&label=Tests&logo=github%20actions&logoColor=fff)](https://github.com/ritchies/enum/actions?query=workflow%3ATests)

This simple program will run [subfinder](https://github.com/projectdiscovery/subfinder) and then [dnsx](https://github.com/projectdiscovery/dnsx) against a target domain.

# Installing

Installing enum is easy, make sure you are on a recent version of Go and then run:

```bash
go install github.com/ritchies/enum@latest
```

# Usage

```plaintext
enum -domain example.com

Usage of enum:
  -a	query for A records
  -domain string
    	target domain
  -output string
    	file to write output
  -silent
    	display only the results in the output
  -version
    	display version information
```

# License

enum is released under the MIT license. See [LICENSE](https://github.com/ritchies/enum/blob/master/LICENSE) for more information.
