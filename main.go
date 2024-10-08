package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

type zoneData struct {
	startTime            time.Time
	udpClient            *dns.Client
	tcpClient            *dns.Client
	zones                map[string]struct{}
	wwwCounter           atomic.Uint64
	wwwOnlyV6Counter     atomic.Uint64
	nsCounter            atomic.Uint64
	mxCounter            atomic.Uint64
	udpCounter           atomic.Uint64
	tcpCounter           atomic.Uint64
	additionalCounter    atomic.Uint64
	aaaaCache            sync.Map
	limiter              *rate.Limiter
	resolver             string
	rcodeCounterMutex    sync.Mutex
	rcodeCounter         map[int]uint64
	timeoutCounter       atomic.Uint64
	zoneSerial           uint32
	verbose              bool
	zoneCounter          uint64
	zoneName             string
	lookupLock           sync.Map
	mxSuffixes           []string
	mxSuffixCounter      map[string]uint64
	mxSuffixCounterMutex sync.Mutex
}

type stats struct {
	ZoneName          string            `json:"zone_name"`
	ZoneSerial        uint32            `json:"zone_serial"`
	WWWPercent        roundedFloat      `json:"www_percent"`
	WWWNum            uint64            `json:"www_num"`
	WWWOnlyV6Num      uint64            `json:"www_onlyv6_num"`
	NSPercent         roundedFloat      `json:"ns_percent"`
	NSNum             uint64            `json:"ns_num"`
	MXPercent         roundedFloat      `json:"mx_percent"`
	MXNum             uint64            `json:"mx_num"`
	NumUDPQueries     uint64            `json:"num_udp_queries"`
	NumTCPQueries     uint64            `json:"num_tcp_queries"`
	RCodes            map[string]uint64 `json:"rcodes"`
	NumDelegatedZones uint64            `json:"num_delegated_zones"`
	QueryTimeouts     uint64            `json:"query_timeouts"`
	RunTime           stringDuration    `json:"runtime"`
	AdditionalFound   uint64            `json:"additional_found"`
	MXSuffixCounter   map[string]uint64 `json:"mx_suffix_counter"`
}

// Float suitable for the JSON statistics
type roundedFloat float64

func (r roundedFloat) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatFloat(float64(r), 'f', 2, 64)), nil
}

// JSON printable duration
type stringDuration struct {
	time.Duration
}

func (s stringDuration) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, s.Round(time.Millisecond).String())), nil
}

func zdToStats(zd *zoneData) stats {
	s := stats{
		ZoneName:          zd.zoneName,
		ZoneSerial:        zd.zoneSerial,
		WWWPercent:        roundedFloat((float64(zd.wwwCounter.Load()) / float64(zd.zoneCounter)) * 100),
		WWWNum:            zd.wwwCounter.Load(),
		WWWOnlyV6Num:      zd.wwwOnlyV6Counter.Load(),
		NSPercent:         roundedFloat((float64(zd.nsCounter.Load()) / float64(zd.zoneCounter)) * 100),
		NSNum:             zd.nsCounter.Load(),
		MXPercent:         roundedFloat((float64(zd.mxCounter.Load()) / float64(zd.zoneCounter)) * 100),
		MXNum:             zd.mxCounter.Load(),
		NumUDPQueries:     zd.udpCounter.Load(),
		NumTCPQueries:     zd.tcpCounter.Load(),
		NumDelegatedZones: zd.zoneCounter,
		QueryTimeouts:     zd.timeoutCounter.Load(),
		AdditionalFound:   zd.additionalCounter.Load(),
		MXSuffixCounter:   zd.mxSuffixCounter,
	}

	s.RunTime.Duration = time.Since(zd.startTime)

	rcodes := map[string]uint64{}
	for rcode, counter := range zd.rcodeCounter {
		rcodes[dns.RcodeToString[rcode]] = counter
	}

	s.RCodes = rcodes

	return s
}

func queryWorker(id int, zoneCh chan string, wg *sync.WaitGroup, zd *zoneData, logger *slog.Logger) {
	defer wg.Done()

	logger = logger.With("worker_id", id)

	queryTypes := []uint16{dns.TypeMX, dns.TypeNS, dns.TypeAAAA}

	for zone := range zoneCh {

		logger := logger.With("delegated_zone", zone)

		var zoneWg sync.WaitGroup

		if zd.verbose {
			logger.Info("inspecting zone", "zone", zone)
		}

		for _, queryType := range queryTypes {
			zoneWg.Add(1)
			go func(zone string) {
				defer zoneWg.Done()
				if queryType == dns.TypeAAAA {
					zone = "www." + zone
				}
				v6, err := isV6(queryType, zd, zone, logger)
				if err != nil {
					if errors.Is(err, os.ErrDeadlineExceeded) {
						logger.Error("isV6 query timed out")
						zd.timeoutCounter.Add(1)
					} else {
						logger.Error("isV6 failed", "error", err)
						os.Exit(1)
					}
				}

				if v6 {
					switch queryType {
					case dns.TypeMX:
						zd.mxCounter.Add(1)
					case dns.TypeNS:
						zd.nsCounter.Add(1)
					case dns.TypeAAAA:
						zd.wwwCounter.Add(1)
						wwwOnlyV6, err := isOnlyV6(queryType, zd, zone, logger)
						if err != nil {
							if errors.Is(err, os.ErrDeadlineExceeded) {
								logger.Error("isOnlyV6 query timed out")
								zd.timeoutCounter.Add(1)
							} else {
								logger.Error("isOnlyV6 failed", "error", err)
								os.Exit(1)
							}
						}

						if wwwOnlyV6 {
							zd.wwwOnlyV6Counter.Add(1)
						}
					default:
						logger.Error("unexpected querytype in isV6", "query_type", dns.TypeToString[queryType])
						os.Exit(1)

					}
				}
			}(zone) // Send in copy of zone since we modify it for AAAA lookups
		}

		zoneWg.Wait()
	}
}

func cachedAaaaQuery(zd *zoneData, name string, origQueryType uint16, origMsg *dns.Msg, logger *slog.Logger) (bool, error) {
	if v, ok := zd.aaaaCache.Load(name); ok {
		b := v.(bool)
		if b {
			if zd.verbose {
				logger.Info("cachedAaaaQuery: got positive cache hit", "name", name)
			}
			return b, nil
		}
		if zd.verbose {
			logger.Info("cachedAaaaQuery: got negative cache hit", "name", name)
		}
		return b, nil
	}
	if zd.verbose {
		logger.Info("cachedAaaaQuery: got cache miss", "name", name)
	}

	// Do locking around lookups so we do not fire off multiple queries for
	// the same name (can happen if concurrently working on NS or MX
	// records pointing to the same set of servers)
	var lookupLock *sync.Mutex

	newLock := &sync.Mutex{}
	existingLock, loaded := zd.lookupLock.LoadOrStore(name, newLock)
	if loaded {
		if zd.verbose {
			logger.Info("cachedAaaaQuery: using existing lookup lock", "name", name)
		}
		lookupLock = existingLock.(*sync.Mutex)
	} else {
		if zd.verbose {
			logger.Info("cachedAaaaQuery: using new lookup lock", "name", name)
		}
		lookupLock = newLock
	}

	lookupLock.Lock()
	if zd.verbose {
		logger.Info("cachedAaaaQuery: acquired lookup lock", "name", name)
	}
	defer lookupLock.Unlock()

	// Do second lookup now that we have the lock since another worker
	// might have filled in the data while we waited.
	if v, ok := zd.aaaaCache.Load(name); ok {
		b := v.(bool)
		if b {
			if zd.verbose {
				logger.Info("cachedAaaaQuery: got positive cache hit after aquiring lock", "name", name)
			}
			return b, nil
		}
		if zd.verbose {
			logger.Info("cachedAaaaQuery: got negative cache hit after aquiring lock", "name", name)
		}
		return b, nil
	}

	if zd.verbose {
		logger.Info("cachedAaaaQuery: got cache miss after aquiring lock", "name", name)
	}

	// First check if additional section already includes AAAA for the
	// requested name
	switch origQueryType {
	case dns.TypeMX, dns.TypeNS:
		for _, arr := range origMsg.Extra {
			if t, ok := arr.(*dns.AAAA); ok {
				if t.Hdr.Name == name {
					if zd.verbose {
						logger.Info("cached positive AAAA based on additional section", "name", name)
					}
					zd.additionalCounter.Add(1)
					zd.aaaaCache.Store(name, true)
					return true, nil
				}
			}
		}
	}

	msg, err := dnsQuery(zd, name, dns.TypeAAAA, logger)
	if err != nil {
		return false, fmt.Errorf("cachedAaaaQuery: dnsQuery failed for name: %w", err)
	}

	if msg.Rcode != dns.RcodeSuccess {
		if zd.verbose {
			logger.Info("cached negative AAAA for non-successful rcode", "name", name, "rcode", dns.RcodeToString[msg.Rcode])
		}
		zd.aaaaCache.Store(name, false)
		return false, nil
	}

	if validAnswer(msg, dns.TypeAAAA, origQueryType, logger) {
		if zd.verbose {
			logger.Info("cached positive AAAA", "name", name)
		}
		zd.aaaaCache.Store(name, true)
		return true, nil
	} else {
		if zd.verbose {
			logger.Info("cached negative AAAA", "name", name)
		}
		zd.aaaaCache.Store(name, false)
	}

	return false, nil
}

func isOnlyV6(queryType uint16, zd *zoneData, name string, logger *slog.Logger) (bool, error) {
	logger = logger.With("query_type", dns.TypeToString[dns.TypeA])

	msg, err := dnsQuery(zd, name, dns.TypeA, logger)
	if err != nil {
		return false, fmt.Errorf("isOnlyV6: dnsQuery failed for name: %w", err)
	}

	// If we received non-successful response dont bother with looking at answer section.
	if msg.Rcode != dns.RcodeSuccess {
		return false, nil
	}

	// If the answer section is not valid (empty or malformed rdata) this
	// is a v6-only name
	return !validAnswer(msg, dns.TypeA, queryType, logger), nil
}

func matchSuffix(domain string, domainSuffixes []string) (bool, string) {
	for _, suffix := range domainSuffixes {
		if strings.HasSuffix(domain, suffix) {
			return true, suffix
		}
	}

	return false, ""
}

func isV6(queryType uint16, zd *zoneData, name string, logger *slog.Logger) (bool, error) {
	logger = logger.With("query_type", dns.TypeToString[queryType])

	msg, err := dnsQuery(zd, name, queryType, logger)
	if err != nil {
		return false, fmt.Errorf("isV6: dnsQuery failed for name: %w", err)
	}

	// If we received non-successful response dont bother with looking at answer section.
	if msg.Rcode != dns.RcodeSuccess {
		return false, nil
	}

	// If we are are looking up AAAA there is nothing more to do
	if queryType == dns.TypeAAAA {
		if validAnswer(msg, queryType, queryType, logger) {
			return true, nil
		}
		return false, nil
	}

	mxSuffixTracker := map[string]struct{}{}

	var mxFound bool

	// ... for other types we need to do further lookups for AAAA
	for _, rr := range msg.Answer {
		switch queryType {
		case dns.TypeMX:
			if t, ok := rr.(*dns.MX); ok {
				if t.Mx == "." && t.Preference == 0 {
					if len(msg.Answer) == 1 {
						if zd.verbose {
							logger.Info("skipping null MX (RFC 7505) record", "name", name)
						}
						break
					}
					logger.Info("a domain that advertises a null MX MUST NOT advertise any other MX RR yet this one does", "name", name)
					continue
				}

				if len(zd.mxSuffixes) > 0 {
					match, suffix := matchSuffix(t.Mx, zd.mxSuffixes)
					if match {
						// We only want to count one
						// suffix match per domain, even
						// if there are multiple
						// records that match.
						if _, exists := mxSuffixTracker[suffix]; !exists {
							mxSuffixTracker[suffix] = struct{}{}
							zd.mxSuffixCounterMutex.Lock()
							zd.mxSuffixCounter[suffix]++
							zd.mxSuffixCounterMutex.Unlock()
						}

					}
				}

				// We only need to do further AAAA lookups if
				// we have not yet found one, otherwise we
				// are just iterating over the remaining answer
				// section for mxSuffix counters.
				if !mxFound {
					mxFound, err = cachedAaaaQuery(zd, t.Mx, queryType, msg, logger)
					if err != nil {
						return false, fmt.Errorf("isV6 cachedAaaaQuery: failed for MX name %s: %w", t.Mx, err)
					}
				}

				// If we found a match and are not looking for suffix matches in the RRSet we are done.
				// Also, if we have found a match, are looking for
				// suffixes, and have found all possible
				// suffixes we are also done.
				if (mxFound && len(zd.mxSuffixes) == 0) || (mxFound && len(zd.mxSuffixes) == len(mxSuffixTracker)) {
					return mxFound, nil
				}

				// No AAAA found and we keep trying, or we
				// found a match but we are looking for
				// additional hits against mxSuffixes
				continue
			}
		case dns.TypeNS:
			if t, ok := rr.(*dns.NS); ok {
				found, err := cachedAaaaQuery(zd, t.Ns, queryType, msg, logger)
				if err != nil {
					return false, fmt.Errorf("isV6 cachedAaaaQuery: failed for NS name %s: %w", t.Ns, err)
				}

				if found {
					return found, nil
				}

				// No AAAA found, keep trying
				continue
			}
		}
	}

	// If we got here and mxFound is true we actually found a match
	if mxFound && len(zd.mxSuffixes) > 0 {
		return mxFound, nil
	}

	// Guardrail, this should never happen
	if mxFound && len(zd.mxSuffixes) == 0 {
		panic("mxFound is true after loop but we are not looking for MX suffixes, why didnt we return earlier")
	}

	return false, nil
}

func dnsQuery(zd *zoneData, name string, rtype uint16, logger *slog.Logger) (*dns.Msg, error) {
	err := zd.limiter.Wait(context.Background())
	if err != nil {
		return nil, fmt.Errorf("retryingLookup: limiter.Wait failed: %w", err)
	}

	m := new(dns.Msg)
	m.SetQuestion(name, rtype)
	m.SetEdns0(4096, false)

	if zd.verbose {
		logger.Info("sending UDP query", "name", name)
	}

	zd.udpCounter.Add(1)
	in, _, err := zd.udpClient.Exchange(m, zd.resolver)
	if err != nil {
		return nil, fmt.Errorf("error looking up %s for '%s' over UDP: %w", dns.TypeToString[rtype], name, err)
	}

	// Retry over TCP if the response was truncated
	if in.Truncated {
		logger.Info("UDP query was truncated, retrying over TCP", "name", name)
		zd.tcpCounter.Add(1)
		in, _, err = zd.tcpClient.Exchange(m, zd.resolver)
		if err != nil {
			return nil, fmt.Errorf("error looking up %s for '%s' over TCP: %w", dns.TypeToString[rtype], name, err)
		}
	}

	if in.Rcode != dns.RcodeSuccess {
		logger.Info("unsuccessful query rcode", "name", name, "rcode", dns.RcodeToString[in.Rcode], "actual_query_type", dns.TypeToString[rtype])
	}

	zd.rcodeCounterMutex.Lock()
	zd.rcodeCounter[in.Rcode]++
	zd.rcodeCounterMutex.Unlock()

	return in, nil
}

func parseTransfer(axfrServer string, transferZone string, zd *zoneData) error {
	t := new(dns.Transfer)
	m := new(dns.Msg)
	m.SetAxfr(transferZone)
	// Do zone transfer
	c, err := t.In(m, axfrServer)
	if err != nil {
		return fmt.Errorf("doTransfer: unable to do transfer: %w", err)
	}

	// Summarize zone names
	for r := range c {
		if r.Error != nil {
			return fmt.Errorf("parseTransfer: zone transfer failed: %w", r.Error)
		}

		for _, rr := range r.RR {
			// Note current zone serial
			if rr.Header().Name == transferZone && rr.Header().Rrtype == dns.TypeSOA {
				if soa, ok := rr.(*dns.SOA); ok {
					zd.zoneSerial = soa.Serial
				} else {
					return errors.New("parseTransfer: unable to parse out zone serial")
				}
			}

			// Only care about zone delegations
			if rr.Header().Rrtype != dns.TypeNS {
				continue
			}

			// Ignore transfer zone records
			if rr.Header().Name == transferZone {
				continue
			}

			zd.zones[rr.Header().Name] = struct{}{}
		}
	}

	return nil
}

func parseZonefile(zoneName string, zoneFile string, zd *zoneData) error {
	// Make gosec happy
	// G304 (CWE-22): Potential file inclusion via variable (Confidence: HIGH, Severity: MEDIUM)
	zoneFile = filepath.Clean(zoneFile)
	fh, err := os.Open(zoneFile)
	if err != nil {
		return fmt.Errorf("parseZoneFile: unable to open %s: %w", zoneFile, err)
	}
	zp := dns.NewZoneParser(fh, "", "")

	// Summarize zone names
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		// Note zone serial
		if rr.Header().Name == zoneName && rr.Header().Rrtype == dns.TypeSOA {
			if soa, ok := rr.(*dns.SOA); ok {
				zd.zoneSerial = soa.Serial
			} else {
				return errors.New("parseZonefile: unable to parse out zone serial")
			}
		}

		// Only care about zone delegations
		if rr.Header().Rrtype != dns.TypeNS {
			continue
		}

		// Ignore zone file records
		if rr.Header().Name == zoneName {
			continue
		}

		zd.zones[rr.Header().Name] = struct{}{}
	}
	if err := zp.Err(); err != nil {
		return fmt.Errorf("parseZoneFile: parser failed: %w", err)
	}

	return nil
}

func validAnswer(msg *dns.Msg, queryType uint16, origQueryType uint16, logger *slog.Logger) bool {
	if len(msg.Answer) == 0 {
		return false
	}

	for _, record := range msg.Answer {
		switch record.(type) {
		case *dns.CNAME:
			switch origQueryType {
			case dns.TypeNS, dns.TypeMX:
				// https://datatracker.ietf.org/doc/html/rfc2181#section-10.3
				// MX or NS rdata is not allowed to point to CNAME
				logger.Error("validAnswer: record in response is invalid CNAME", "sub_query_type", dns.TypeToString[queryType])
				return false
			}
		case *dns.A:
			if queryType == dns.TypeA {
				return true
			}
		case *dns.AAAA:
			if queryType == dns.TypeAAAA {
				return true
			}
		default:
			typeString, ok := dns.TypeToString[record.Header().Rrtype]
			if ok {
				logger.Error("validAnswer: record in answer section is unexpected type", "sub_query_type", dns.TypeToString[queryType], "actual_rtype", typeString)
			} else {
				logger.Error("validAnswer: record in  answer section is unknown type", "sub_query_type", dns.TypeToString[queryType], "actual_rtype_int", record.Header().Rrtype)
			}
		}
	}

	// If we got this far we did not find at least one valid record in
	// the answer section
	return false
}

func run(axfrServer string, resolver string, zoneName string, zoneFile string, workers int, zoneLimit int, verbose bool, dialTimeout time.Duration, readTimeout time.Duration, writeTimeout time.Duration, ratelimit rate.Limit, burstlimit int, mxSuffixes []string, logger *slog.Logger) (stats, error) {
	zoneCh := make(chan string)

	zoneName = dns.Fqdn(zoneName)

	if burstlimit < 1 {
		return stats{}, fmt.Errorf("run: invalid burst limit: %d", burstlimit)
	}

	if ratelimit == 0 {
		logger.Info("allowing infinite DNS request rate")
		ratelimit = rate.Inf
	}

	zd := &zoneData{
		startTime:       time.Now(),
		zoneName:        zoneName,
		zones:           map[string]struct{}{},
		limiter:         rate.NewLimiter(ratelimit, burstlimit),
		resolver:        resolver,
		udpClient:       &dns.Client{},
		tcpClient:       &dns.Client{Net: "tcp"},
		rcodeCounter:    map[int]uint64{},
		verbose:         verbose,
		mxSuffixes:      mxSuffixes,
		mxSuffixCounter: map[string]uint64{},
	}

	if dialTimeout != 0 {
		zd.udpClient.DialTimeout = dialTimeout
		zd.tcpClient.DialTimeout = dialTimeout
	}

	if readTimeout != 0 {
		zd.udpClient.ReadTimeout = readTimeout
		zd.tcpClient.ReadTimeout = readTimeout
	}

	if writeTimeout != 0 {
		zd.udpClient.WriteTimeout = writeTimeout
		zd.tcpClient.WriteTimeout = writeTimeout
	}

	var wg sync.WaitGroup

	if zoneFile == "" {
		logger.Info("fetching zone via AXFR", "zone", zoneName, "axfr_server", axfrServer)

		err := parseTransfer(axfrServer, zoneName, zd)
		if err != nil {
			return stats{}, fmt.Errorf("parseTransfer failed: %w", err)
		}
	} else {
		logger.Info("reading zone", "zone", zoneName, "zone_file", zoneFile)
		err := parseZonefile(zoneName, zoneFile, zd)
		if err != nil {
			return stats{}, fmt.Errorf("parseZonefile failed: %w", err)
		}
	}

	logger = logger.With("resolver", resolver)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go queryWorker(i, zoneCh, &wg, zd, logger)
	}

	logger.Info("starting zone queries", "zone", zoneName)
	for zone := range zd.zones {
		if zoneLimit == 0 {
			break
		}
		zoneCh <- zone
		zd.zoneCounter++
		if zoneLimit > 0 {
			zoneLimit -= 1
		}
	}

	close(zoneCh)
	wg.Wait()

	s := zdToStats(zd)

	return s, nil
}

func statsToJson(s stats) ([]byte, error) {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("statsToJson: encoding failed: %w", err)
	}

	return b, nil
}

func main() {
	var zoneNameFlag = flag.String("zone", "se", "zone to investigate")
	var axfrServerFlag = flag.String("axfr-server", "zonedata.iis.se:53", "server to transfer zone from")
	var resolverFlag = flag.String("resolver", "8.8.8.8:53", "resolver to query")
	var zoneFileFlag = flag.String("file", "", "zone file to parse")
	var workersFlag = flag.Int("workers", 10, "number of workers to start")
	var zoneLimitFlag = flag.Int("zone-limit", -1, "number of delegated zones to check, -1 means no limit")
	var verboseFlag = flag.Bool("verbose", false, "enable verbose logging")
	var dialTimeoutFlag = flag.String("dial-timeout", "10s", "DNS client dial timeout, 0 means using the miekg/dns default")
	var readTimeoutFlag = flag.String("read-timeout", "10s", "DNS client read timeout, 0 means using the miekg/dns default")
	var writeTimeoutFlag = flag.String("write-timeout", "0s", "DNS client write timeout, 0 means using the miekg/dns default")
	var ratelimitFlag = flag.Float64("ratelimit", 10, "DNS requests allowed per second, 0 means no limit")
	var burstlimitFlag = flag.Int("burstlimit", 1, "DNS request burst limit, must be at least 1")
	var mxSuffixesFlag = flag.String("mx-suffixes", "", "Comma-separated list of MX suffixes to count zones for, e.g. '.mx.example.com,.mail.example.net'")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	dialTimeout, err := time.ParseDuration(*dialTimeoutFlag)
	if err != nil {
		logger.Error("unable to parse dialTimeout", "error", err)
		os.Exit(1)
	}

	readTimeout, err := time.ParseDuration(*readTimeoutFlag)
	if err != nil {
		logger.Error("unable to parse readTimeout", "error", err)
		os.Exit(1)
	}

	writeTimeout, err := time.ParseDuration(*writeTimeoutFlag)
	if err != nil {
		logger.Error("unable to parse writeTimeout", "error", err)
		os.Exit(1)
	}

	ratelimit := rate.Limit(*ratelimitFlag)

	mxSuffixes := []string{}
	if *mxSuffixesFlag != "" {
		for _, mxSuffix := range strings.Split(*mxSuffixesFlag, ",") {
			mxSuffixes = append(mxSuffixes, dns.Fqdn(mxSuffix))
		}
	}

	s, err := run(*axfrServerFlag, *resolverFlag, *zoneNameFlag, *zoneFileFlag, *workersFlag, *zoneLimitFlag, *verboseFlag, dialTimeout, readTimeout, writeTimeout, ratelimit, *burstlimitFlag, mxSuffixes, logger)
	if err != nil {
		logger.Error("run failed", "error", err)
		os.Exit(1)
	}

	j, err := statsToJson(s)
	if err != nil {
		logger.Error("json encoding failed", "error", err)
		os.Exit(1)
	}

	fmt.Println(string(j))
}
