# tldv6stat
A tool used to collect IPv6 usage statistics for zones registered in a given TLD.

## How to use the tool
### Default operation
Running `tldv6stat` with no flags means it will use
[zonedata.iis.se](https://internetstiftelsen.se/en/zone-data/) to download the
`.se` zone into RAM and then start iterating over delegated zones with the default
number of workers while ratelimiting outgoing DNS requests with (very)
conservative defaults.

### Ratelimiting and worker count
The DNS request ratelimit is controlled using the `-ratelimit-*` flags. You
probably want to increase this (or set `-ratelimit-rate 0` to disable
ratelimiting entirely) if your resolver can handle it. If increasing the
ratelimit you probably want to set a custom resolver other than the default of
`8.8.8.8:53` as well. The number of workers probably should be increased as
well if operating on large zones.

### Output
The tool will output JSON both for the collected statistics as well as any operational logging.

Only statistics are written to `stdout` while any logging is written to
`stderr`. This is to easily separate them into different files.

### Local zone file
The tool allows you to operate on a local zone file rather than downloading
it into RAM on each run. To save on startup time (or just be able to operate on
the same instance of the zone multiple times) you can do something like this:
```
$ dig @zonedata.iis.se se AXFR > se.zone
$ tldv6stat -file se.zone
```

## Supported flags
```
$ tldv6stat -help
Usage of tldv6stat:
  -axfr-server string
    	server to transfer zone from (default "zonedata.iis.se:53")
  -burstlimit int
    	DNS request burst limit, must be at least 1 (default 1)
  -dial-timeout string
    	DNS client dial timeout, 0 means using the miekg/dns default (default "10s")
  -file string
    	zone file to parse
  -ratelimit float
    	DNS requests allowed per second, 0 means no limit (default 10)
  -read-timeout string
    	DNS client read timeout, 0 means using the miekg/dns default (default "10s")
  -resolver string
    	resolver to query (default "8.8.8.8:53")
  -verbose
    	enable verbose logging
  -workers int
    	number of workers to start (default 10)
  -write-timeout string
    	DNS client write timeout, 0 means using the miekg/dns default (default "0s")
  -zone string
    	zone to investigate (default "se")
  -zone-limit int
    	number of delegated zones to check, -1 means no limit (default -1)
```

## Development
When working on this code the following tools are expected to be used before
committing:
* `go fmt ./...`
* `go vet ./...`
* `staticcheck ./...` (see [staticcheck](https://staticcheck.io))
* `gosec ./...` (see [gosec](https://github.com/securego/gosec))
* `golangci-lint run` (see [golangci-lint](https://golangci-lint.run))
* `go test -race ./...`
