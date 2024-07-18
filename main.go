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
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

type zoneData struct {
	udpClient         *dns.Client
	tcpClient         *dns.Client
	zones             map[string]struct{}
	wwwCounter        atomic.Uint64
	nsCounter         atomic.Uint64
	mxCounter         atomic.Uint64
	udpCounter        atomic.Uint64
	tcpCounter        atomic.Uint64
	nsCache           sync.Map
	mxCache           sync.Map
	limiter           *rate.Limiter
	resolver          string
	rcodeCounterMutex sync.Mutex
	rcodeCounter      map[int]uint64
	timeoutCounter    atomic.Uint64
	zoneSerial        uint32
	verbose           bool
	zoneCounter       uint64
	zoneName          string
}

type stats struct {
	ZoneName      string            `json:"zone_name"`
	ZoneSerial    uint32            `json:"zone_serial"`
	WWWPercent    roundedFloat      `json:"www_percent"`
	WWWNum        uint64            `json:"www_num"`
	NSPercent     roundedFloat      `json:"ns_percent"`
	NSNum         uint64            `json:"ns_num"`
	MXPercent     roundedFloat      `json:"mx_percent"`
	MXNum         uint64            `json:"mx_num"`
	NumUDPQueries uint64            `json:"num_udp_queries"`
	NumTCPQueries uint64            `json:"num_tcp_queries"`
	RCodes        map[string]uint64 `json:"rcodes"`
	NumChildZones uint64            `json:"num_child_zones"`
	QueryTimeouts uint64            `json:"query_timeouts"`
}

// Float suitable for the JSON statistics
type roundedFloat float64

func (r roundedFloat) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatFloat(float64(r), 'f', 2, 64)), nil
}

func zdToStats(zd *zoneData) stats {
	s := stats{
		ZoneName:      zd.zoneName,
		ZoneSerial:    zd.zoneSerial,
		WWWPercent:    roundedFloat((float64(zd.wwwCounter.Load()) / float64(zd.zoneCounter)) * 100),
		WWWNum:        zd.wwwCounter.Load(),
		NSPercent:     roundedFloat((float64(zd.nsCounter.Load()) / float64(zd.zoneCounter)) * 100),
		NSNum:         zd.nsCounter.Load(),
		MXPercent:     roundedFloat((float64(zd.mxCounter.Load()) / float64(zd.zoneCounter)) * 100),
		MXNum:         zd.mxCounter.Load(),
		NumUDPQueries: zd.udpCounter.Load(),
		NumTCPQueries: zd.tcpCounter.Load(),
		NumChildZones: zd.zoneCounter,
		QueryTimeouts: zd.timeoutCounter.Load(),
	}

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

	for zone := range zoneCh {

		var mxIsV6, nsIsV6, wwwIsV6 bool

		var zoneWg sync.WaitGroup

		logger.Info("handling zone", "zone", zone)

		zoneWg.Add(1)
		go func() {
			var err error
			defer zoneWg.Done()
			mxIsV6, err = isMxV6(zd, zone, logger)
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					logger.Error("mxIsV6 query timed out", "zone", zone)
					zd.timeoutCounter.Add(1)
				} else {
					logger.Error("isMxV6 failed", "error", err, "zone", zone)
					os.Exit(1)
				}
			}
		}()

		zoneWg.Add(1)
		go func() {
			var err error
			defer zoneWg.Done()
			nsIsV6, err = isNsV6(zd, zone, logger)
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					logger.Error("nsIsV6 query timed out", "zone", zone)
					zd.timeoutCounter.Add(1)
				} else {
					logger.Error("nsIsV6 failed", "error", err, "zone", zone)
					os.Exit(1)
				}
			}
		}()

		zoneWg.Add(1)
		go func() {
			var err error
			defer zoneWg.Done()
			wwwIsV6, err = isWwwV6(zd, zone, logger)
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					logger.Error("wwwIsV6 query timed out", "zone", zone)
					zd.timeoutCounter.Add(1)
				} else {
					logger.Error("wwwIsV6 failed", "error", err, "zone", zone)
					os.Exit(1)
				}
			}
		}()

		zoneWg.Wait()

		if mxIsV6 {
			zd.mxCounter.Add(1)
		}
		if nsIsV6 {
			zd.nsCounter.Add(1)
		}
		if wwwIsV6 {
			zd.wwwCounter.Add(1)
		}
	}
}

func isMxV6(zd *zoneData, zone string, logger *slog.Logger) (bool, error) {

	msg, err := retryingLookup(zd, zone, dns.TypeMX, logger)
	if err != nil {
		return false, fmt.Errorf("isMxV6: retryingLookup failed for zone: %w", err)
	}

	// If we received non-successful response dont bother with looking at answer section.
	if msg.Rcode != dns.RcodeSuccess {
		return false, nil
	}

	for _, rr := range msg.Answer {
		if t, ok := rr.(*dns.MX); ok {
			if t.Mx == "." && t.Preference == 0 {
				if len(msg.Answer) == 1 {
					if zd.verbose {
						logger.Info("skipping null MX (RFC 7505) record", "zone", zone)
					}
					break
				}
				logger.Info("a domain that advertises a null MX MUST NOT advertise any other MX RR yet this one does", "zone", zone)
				continue
			}
			if v, ok := zd.mxCache.Load(t.Mx); ok {
				b := v.(bool)
				if b {
					if zd.verbose {
						logger.Info("isMxV6: got positive cache hit", "zone", zone, "mx", t.Mx)
					}
					return b, nil
				}
				if zd.verbose {
					logger.Info("isMxV6: got negative cache hit, continuing to look", "zone", zone, "mx", t.Mx)
				}
				continue
			}

			msg, err = retryingLookup(zd, t.Mx, dns.TypeAAAA, logger)
			if err != nil {
				return false, fmt.Errorf("isMxV6 retryingLookup (AAAA) failed for MX name %s: %w", t.Mx, err)
			}
			if len(msg.Answer) != 0 {
				if zd.verbose {
					logger.Info("found MX with AAAA", "zone", zone, "mx", t.Mx)
				}
				zd.mxCache.Store(t.Mx, true)
				return true, nil
			} else {
				if zd.verbose {
					logger.Info("MX missing AAAA", "zone", zone, "mx", t.Mx)
				}
				zd.mxCache.Store(t.Mx, false)
			}
		}
	}

	return false, nil
}

func isNsV6(zd *zoneData, zone string, logger *slog.Logger) (bool, error) {
	msg, err := retryingLookup(zd, zone, dns.TypeNS, logger)
	if err != nil {
		return false, fmt.Errorf("isNSV6 retryingLookup failed for zone: %w", err)
	}

	// If we received non-successful response dont bother with looking at answer section.
	if msg.Rcode != dns.RcodeSuccess {
		return false, nil
	}

	for _, rr := range msg.Answer {
		if t, ok := rr.(*dns.NS); ok {

			if v, ok := zd.nsCache.Load(t.Ns); ok {
				b := v.(bool)
				if b {
					if zd.verbose {
						logger.Info("isNsV6: got positive cache hit", "zone", zone, "ns", t.Ns)
					}
					return b, nil
				}
				if zd.verbose {
					logger.Info("isNsV6: got negative cache hit, continuing to look", "zone", zone, "ns", t.Ns)
				}
			}

			msg, err = retryingLookup(zd, t.Ns, dns.TypeAAAA, logger)
			if err != nil {
				return false, fmt.Errorf("isNsV6 retryingLookup (AAAA) failed for NS %s: %w", t.Ns, err)
			}
			if len(msg.Answer) != 0 {
				if zd.verbose {
					logger.Info("found NS with AAAA", "zone", zone, "ns", t.Ns)
				}
				zd.nsCache.Store(t.Ns, true)
				return true, nil
			} else {
				if zd.verbose {
					logger.Info("NS missing AAAA", "zone", zone, "ns", t.Ns)
				}
				zd.nsCache.Store(t.Ns, false)
			}
		}
	}

	return false, nil
}

func isWwwV6(zd *zoneData, zone string, logger *slog.Logger) (bool, error) {
	msg, err := retryingLookup(zd, "www."+zone, dns.TypeAAAA, logger)
	if err != nil {
		return false, fmt.Errorf("isWwwwV6 retryingLookup (AAAA) failed: %w", err)
	}

	// If we received non-successful response dont bother with looking at answer section.
	if msg.Rcode != dns.RcodeSuccess {
		return false, nil
	}

	if len(msg.Answer) != 0 {
		return true, nil
	}

	return false, nil
}

func retryingLookup(zd *zoneData, name string, rtype uint16, logger *slog.Logger) (*dns.Msg, error) {

	err := zd.limiter.Wait(context.Background())
	if err != nil {
		return nil, fmt.Errorf("retryingLookup: limiter.Wait failed: %w", err)
	}

	m := new(dns.Msg)
	m.SetQuestion(name, rtype)
	m.SetEdns0(4096, false)

	if zd.verbose {
		logger.Info("sending UDP query", "name", name, "rtype", dns.TypeToString[rtype])
	}

	zd.udpCounter.Add(1)
	in, _, err := zd.udpClient.Exchange(m, zd.resolver)
	if err != nil {
		return nil, fmt.Errorf("error looking up %s for '%s' over UDP: %w", dns.TypeToString[rtype], name, err)
	}

	// Retry over TCP if the response was truncated
	if in.Truncated {
		logger.Info("UDP query was truncated, retrying over TCP", "name", name, "rtype", dns.TypeToString[rtype])
		zd.tcpCounter.Add(1)
		in, _, err = zd.tcpClient.Exchange(m, zd.resolver)
		if err != nil {
			return nil, fmt.Errorf("error looking up %s for '%s' over TCP: %w", dns.TypeToString[rtype], name, err)
		}
	}

	if in.Rcode != dns.RcodeSuccess {
		logger.Info("query resulted in unsuccessful RCODE", "rtype", dns.TypeToString[rtype], "name", name, "rcode", dns.RcodeToString[in.Rcode])
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

func run(axfrServer string, resolver string, zoneName string, zoneFile string, workers int, zoneLimit int, verbose bool, dialTimeout time.Duration, readTimeout time.Duration, writeTimeout time.Duration, ratelimit rate.Limit, burstlimit int, logger *slog.Logger) (stats, error) {
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
		zoneName:     zoneName,
		zones:        map[string]struct{}{},
		limiter:      rate.NewLimiter(ratelimit, burstlimit),
		resolver:     resolver,
		udpClient:    &dns.Client{},
		tcpClient:    &dns.Client{Net: "tcp"},
		rcodeCounter: map[int]uint64{},
		verbose:      verbose,
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
		fmt.Printf("reading zone '%s' from file %s\n", zoneName, zoneFile)
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
	var dialTimeoutFlag = flag.String("dial-timeout", "0s", "DNS client dial timeout, 0 means using the miekg/dns default")
	var readTimeoutFlag = flag.String("read-timeout", "0s", "DNS client read timeout, 0 means using the miekg/dns default")
	var writeTimeoutFlag = flag.String("write-timeout", "0s", "DNS client write timeout, 0 means using the miekg/dns default")
	var ratelimitFlag = flag.Float64("ratelimit-rate", 10, "DNS requests allowed per second, 0 means no limit")
	var burstlimitFlag = flag.Int("ratelimit-burst", 1, "DNS request burst limit, must be at least 1")
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

	s, err := run(*axfrServerFlag, *resolverFlag, *zoneNameFlag, *zoneFileFlag, *workersFlag, *zoneLimitFlag, *verboseFlag, dialTimeout, readTimeout, writeTimeout, ratelimit, *burstlimitFlag, logger)
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
