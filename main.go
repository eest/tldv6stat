package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

type zoneData struct {
	udpClient         *dns.Client
	tcpClient         *dns.Client
	m                 map[string]struct{}
	wwwCounter        uint64
	nsCounter         uint64
	mxCounter         uint64
	mutex             sync.Mutex
	nsCache           sync.Map
	mxCache           sync.Map
	limiter           *rate.Limiter
	resolver          string
	rcodeCounterMutex sync.Mutex
	rcodeCounter      map[int]uint64
	zoneSerial        uint32
}

func queryWorker(id int, zoneCh chan string, wg *sync.WaitGroup, zd *zoneData) {
	defer wg.Done()

	for zone := range zoneCh {
		fmt.Printf("worker: %d, zone: %s\n", id, zone)

		mxIsV6, err := isMxV6(zd, zone)
		if err != nil {
			log.Fatal(err)
		}

		nsIsV6, err := isNsV6(zd, zone)
		if err != nil {
			log.Fatal(err)
		}

		wwwIsV6, err := isWwwV6(zd, zone)
		if err != nil {
			log.Fatal(err)
		}

		zd.mutex.Lock()
		if mxIsV6 {
			zd.mxCounter++
		}
		if nsIsV6 {
			zd.nsCounter++
		}
		if wwwIsV6 {
			zd.wwwCounter++
		}
		zd.mutex.Unlock()
	}
}

func isMxV6(zd *zoneData, name string) (bool, error) {

	msg, err := retryingLookup(zd, name, dns.TypeMX)
	if err != nil {
		log.Fatal(err)
	}

	for _, rr := range msg.Answer {
		if t, ok := rr.(*dns.MX); ok {
			if t.Mx == "." && t.Preference == 0 {
				if len(msg.Answer) == 1 {
					log.Printf("skipping null MX (RFC 7505) record for %s\n", name)
					break
				}
				log.Printf("A domain that advertises a null MX MUST NOT advertise any other MX RR yet the one for '%s' does, huh.", name)
				continue
			}
			if v, ok := zd.mxCache.Load(t.Mx); ok {
				b := v.(bool)
				if b {
					log.Printf("isMxV6: got positive cache hit (%s): %s: %t", name, t.Mx, b)
					return b, nil
				}
				log.Printf("isMxV6: got negative cache hit, continuing to look (%s): %s: %t", name, t.Mx, b)
				continue
			}

			msg, err = retryingLookup(zd, t.Mx, dns.TypeAAAA)
			if err != nil {
				return false, fmt.Errorf("isMxV6 AAAA (%s): %s: %w", name, t.Mx, err)
			}
			if len(msg.Answer) != 0 {
				log.Printf("Found MX with AAAA (%s): %s", name, t.Mx)
				zd.mxCache.Store(t.Mx, true)
				return true, nil
			} else {
				log.Printf("MX missing AAAA (%s): %s", name, t.Mx)
				zd.mxCache.Store(t.Mx, false)
			}
		}
	}

	return false, nil
}

func isNsV6(zd *zoneData, name string) (bool, error) {
	msg, err := retryingLookup(zd, name, dns.TypeNS)
	if err != nil {
		log.Fatal(err)
	}

	for _, rr := range msg.Answer {
		if t, ok := rr.(*dns.NS); ok {

			if v, ok := zd.nsCache.Load(t.Ns); ok {
				b := v.(bool)
				if b {
					log.Printf("isNsV6: got positive cache hit (%s): %s: %t", name, t.Ns, b)
					return b, nil
				}
				log.Printf("isNsV6: got negative cache hit, continuing to look (%s): %s: %t", name, t.Ns, b)
			}

			msg, err = retryingLookup(zd, t.Ns, dns.TypeAAAA)
			if err != nil {
				return false, fmt.Errorf("isNsV6 AAAA (%s): %s: %w", name, t.Ns, err)
			}
			if len(msg.Answer) != 0 {
				log.Printf("Found NS with AAAA (%s): %s", name, t.Ns)
				zd.nsCache.Store(t.Ns, true)
				return true, nil
			} else {
				log.Printf("NS missing AAAA (%s): %s", name, t.Ns)
				zd.nsCache.Store(t.Ns, false)
			}
		}
	}

	return false, nil
}

func isWwwV6(zd *zoneData, name string) (bool, error) {
	msg, err := retryingLookup(zd, "www."+name, dns.TypeAAAA)
	if err != nil {
		return false, fmt.Errorf("isWwwwV6: %w", err)
	}

	if len(msg.Answer) != 0 {
		return true, nil
	}

	return false, nil
}

func retryingLookup(zd *zoneData, name string, lookupType uint16) (*dns.Msg, error) {

	err := zd.limiter.Wait(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	m := new(dns.Msg)
	m.SetQuestion(name, lookupType)
	m.SetEdns0(4096, false)

	in, _, err := zd.udpClient.Exchange(m, zd.resolver)
	if err != nil {
		return nil, fmt.Errorf("error looking up %s for '%s' over UDP: %w", dns.TypeToString[lookupType], name, err)
	}

	// Retry over TCP if the response was truncated
	if in.Truncated {
		log.Printf("UDP query for '%s' was truncated, retrying over TCP", name)
		in, _, err = zd.tcpClient.Exchange(m, zd.resolver)
		if err != nil {
			return nil, fmt.Errorf("error looking up %s for '%s' over TCP: %w", dns.TypeToString[lookupType], name, err)
		}
	}

	if in.Rcode != dns.RcodeSuccess {
		log.Printf("%s query for '%s' resulted in unsuccessful rcode: %s", dns.TypeToString[lookupType], name, dns.RcodeToString[in.Rcode])
	}

	zd.rcodeCounterMutex.Lock()
	zd.rcodeCounter[in.Rcode] += 1
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
			log.Fatal(r.Error)
		}

		for _, rr := range r.RR {
			// Note current zone serial
			if rr.Header().Name == transferZone && rr.Header().Rrtype == dns.TypeSOA {
				if soa, ok := rr.(*dns.SOA); ok {
					zd.zoneSerial = soa.Serial
				} else {
					log.Fatal("unable to parse out zone serial")
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

			//zd.m[rr.Header().Name] = v6Status{}
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
				log.Fatal("unable to parse out zone serial")
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
	flag.Parse()

	zoneCh := make(chan string)

	zd := &zoneData{
		m:            map[string]struct{}{},
		limiter:      rate.NewLimiter(10, 1),
		resolver:     *resolverFlag,
		udpClient:    &dns.Client{DialTimeout: time.Second * 60, ReadTimeout: time.Second * 60, WriteTimeout: time.Second * 60},
		tcpClient:    &dns.Client{Net: "tcp", DialTimeout: time.Second * 60, ReadTimeout: time.Second * 60, WriteTimeout: time.Second * 60},
		rcodeCounter: map[int]uint64{},
	}

	var wg sync.WaitGroup

	if *zoneFileFlag == "" {
		fmt.Printf("fetching zone '%s' via AXFR\n", *zoneNameFlag)

		err := parseTransfer(*zoneNameFlag, zd)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		fmt.Printf("reading zone '%s' from file %s\n", *zoneNameFlag, *zoneFileFlag)
		err := parseZonefile(*zoneNameFlag, *zoneFileFlag, zd)

		if err != nil {
			log.Fatal(err)
		}
	}

	for i := 0; i < *workersFlag; i++ {
		wg.Add(1)
		go queryWorker(i, zoneCh, &wg, zd)
	}

	zoneCounter := *zoneLimitFlag
	for zone := range zd.m {
		if zoneCounter == 0 {
			break
		}
		zoneCh <- zone
		if zoneCounter > 0 {
			zoneCounter -= 1
		}
	}

	close(zoneCh)
	wg.Wait()

	sortedRcodes := []int{}
	for rcode := range zd.rcodeCounter {
		sortedRcodes = append(sortedRcodes, rcode)
	}
	sort.Ints(sortedRcodes)

	var zonesChecked int
	if *zoneLimitFlag > 0 {
		zonesChecked = *zoneLimitFlag
	} else {
		zonesChecked = len(zd.m)
	}

	fmt.Printf("At %s the .se zone (serial: %d) contains %d domains\n", time.Now().Format(time.RFC3339), zd.zoneSerial, len(zd.m))
	if zonesChecked != len(zd.m) {
		fmt.Printf("We limited the lookups to %d domains\n", zonesChecked)
	}
	fmt.Printf("%d of %d (%.2f%%) have IPv6 on www\n", zd.wwwCounter, zonesChecked, (float64(zd.wwwCounter)/float64(zonesChecked))*100)
	fmt.Printf("%d of %d (%.2f%%) have IPv6 on one or more DNS\n", zd.nsCounter, zonesChecked, (float64(zd.nsCounter)/float64(zonesChecked))*100)
	fmt.Printf("%d of %d (%.2f%%) have IPv6 on one or more MX\n", zd.mxCounter, zonesChecked, (float64(zd.mxCounter)/float64(zonesChecked))*100)
	fmt.Println("rcode summary:")
	for _, rcode := range sortedRcodes {
		fmt.Printf("  %s: %d\n", dns.RcodeToString[rcode], zd.rcodeCounter[rcode])
	}
}
