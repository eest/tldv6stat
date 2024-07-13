package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

type zoneData struct {
	udpClient         *dns.Client
	tcpClient         *dns.Client
	m                 map[string]struct{}
	wwwCounter        atomic.Uint64
	nsCounter         atomic.Uint64
	mxCounter         atomic.Uint64
	nsCache           sync.Map
	mxCache           sync.Map
	limiter           *rate.Limiter
	resolver          string
	rcodeCounterMutex sync.Mutex
	rcodeCounter      map[int]uint64
	timeoutCounter    atomic.Uint64
	zoneSerial        uint32
	verbose           bool
}

func queryWorker(id int, zoneCh chan string, wg *sync.WaitGroup, zd *zoneData, logger *slog.Logger) {
	defer wg.Done()

	for zone := range zoneCh {
		fmt.Printf("worker: %d, zone: %s\n", id, zone)

		mxIsV6, err := isMxV6(zd, zone, logger)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				logger.Error("mxIsV6 query timed out", "zone", zone)
				zd.timeoutCounter.Add(1)
			} else {
				logger.Error("isMxV6 failed", "error", err, "zone", zone)
				os.Exit(1)
			}
		}

		nsIsV6, err := isNsV6(zd, zone, logger)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				logger.Error("nsIsV6 query timed out", "zone", zone)
				zd.timeoutCounter.Add(1)
			} else {
				logger.Error("nsIsV6 failed", "error", err, "zone", zone)
				os.Exit(1)
			}
		}

		wwwIsV6, err := isWwwV6(zd, zone, logger)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				logger.Error("wwwIsV6 query timed out", "zone", zone)
				zd.timeoutCounter.Add(1)
			} else {
				logger.Error("wwwIsV6 failed", "error", err, "zone", zone)
				os.Exit(1)
			}
		}

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

	in, _, err := zd.udpClient.Exchange(m, zd.resolver)
	if err != nil {
		return nil, fmt.Errorf("error looking up %s for '%s' over UDP: %w", dns.TypeToString[rtype], name, err)
	}

	// Retry over TCP if the response was truncated
	if in.Truncated {
		logger.Info("UDP query was truncated, retrying over TCP", "name", name, "rtype", dns.TypeToString[rtype])
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

func parseTransfer(transferZone string, zd *zoneData) error {

	t := new(dns.Transfer)
	m := new(dns.Msg)
	m.SetAxfr(transferZone)
	// Do zone transfer
	c, err := t.In(m, "zonedata.iis.se:53")
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

			zd.m[rr.Header().Name] = struct{}{}
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

		zd.m[rr.Header().Name] = struct{}{}
	}
	if err := zp.Err(); err != nil {
		return fmt.Errorf("parseZoneFile: parser failed: %w", err)
	}

	return nil
}

func main() {

	var zoneNameFlag = flag.String("zone", "se.", "zone to investigate")
	var resolverFlag = flag.String("resolver", "8.8.8.8:53", "resolver to query")
	var zoneFileFlag = flag.String("file", "", "zone file to parse")
	var workersFlag = flag.Int("workers", 10, "number of workers to start")
	var zoneLimitFlag = flag.Int("zone-limit", -1, "number of zones to check, -1 means no limit")
	var verboseFlag = flag.Bool("verbose", false, "enable verbose logging")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	zoneCh := make(chan string)

	zd := &zoneData{
		m:            map[string]struct{}{},
		limiter:      rate.NewLimiter(10, 1),
		resolver:     *resolverFlag,
		udpClient:    &dns.Client{DialTimeout: time.Second * 60, ReadTimeout: time.Second * 60, WriteTimeout: time.Second * 60},
		tcpClient:    &dns.Client{Net: "tcp", DialTimeout: time.Second * 60, ReadTimeout: time.Second * 60, WriteTimeout: time.Second * 60},
		rcodeCounter: map[int]uint64{},
		verbose:      *verboseFlag,
	}

	var wg sync.WaitGroup

	if *zoneFileFlag == "" {
		fmt.Printf("fetching zone '%s' via AXFR\n", *zoneNameFlag)

		err := parseTransfer(*zoneNameFlag, zd)
		if err != nil {
			logger.Error("parseTransfer failed", "error", err)
			os.Exit(1)
		}
	} else {
		fmt.Printf("reading zone '%s' from file %s\n", *zoneNameFlag, *zoneFileFlag)
		err := parseZonefile(*zoneNameFlag, *zoneFileFlag, zd)
		if err != nil {
			logger.Error("parseZonefile failed", "error", err)
			os.Exit(1)
		}
	}

	for i := 0; i < *workersFlag; i++ {
		wg.Add(1)
		go queryWorker(i, zoneCh, &wg, zd, logger)
	}

	zoneLimit := *zoneLimitFlag
	zoneCounter := 0
	for zone := range zd.m {
		if zoneLimit == 0 {
			break
		}
		zoneCh <- zone
		zoneCounter++
		if zoneLimit > 0 {
			zoneLimit -= 1
		}
	}

	close(zoneCh)
	wg.Wait()

	sortedRcodes := []int{}
	for rcode := range zd.rcodeCounter {
		sortedRcodes = append(sortedRcodes, rcode)
	}
	sort.Ints(sortedRcodes)

	fmt.Printf("At %s the .se zone (serial: %d) contains %d zones\n", time.Now().Format(time.RFC3339), zd.zoneSerial, len(zd.m))
	if *zoneLimitFlag > 0 {
		fmt.Printf("lookups limited to %d zones\n", *zoneLimitFlag)
	}
	fmt.Printf("%d of %d (%.2f%%) have IPv6 on www\n", zd.wwwCounter.Load(), zoneCounter, (float64(zd.wwwCounter.Load())/float64(zoneCounter))*100)
	fmt.Printf("%d of %d (%.2f%%) have IPv6 on one or more NS\n", zd.nsCounter.Load(), zoneCounter, (float64(zd.nsCounter.Load())/float64(zoneCounter))*100)
	fmt.Printf("%d of %d (%.2f%%) have IPv6 on one or more MX\n", zd.mxCounter.Load(), zoneCounter, (float64(zd.mxCounter.Load())/float64(zoneCounter))*100)
	fmt.Println("RCODE summary:")
	for _, rcode := range sortedRcodes {
		fmt.Printf("  %s: %d\n", dns.RcodeToString[rcode], zd.rcodeCounter[rcode])
	}
	fmt.Printf("Query timeouts: %d\n", zd.timeoutCounter.Load())
}
