package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

type zoneData struct {
	m          map[string]struct{}
	wwwCounter uint64
	nsCounter  uint64
	mxCounter  uint64
	mutex      sync.Mutex
	nsCache    sync.Map
	mxCache    sync.Map
	limiter    *rate.Limiter
}

func queryWorker(id int, zoneCh chan string, wg *sync.WaitGroup, zd *zoneData) {
	wg.Add(1)
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

	cUDP := &dns.Client{DialTimeout: time.Second * 10, ReadTimeout: time.Second * 10, WriteTimeout: time.Second * 10}
	in, _, err := cUDP.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return nil, fmt.Errorf("error looking up mx over UDP: %w", err)
	}

	// Retry over TCP if the response was truncated
	if in.Truncated {
		log.Printf("MX query was truncated, retrying over TCP")
		cTCP := &dns.Client{Net: "tcp", DialTimeout: time.Second * 10, ReadTimeout: time.Second * 10, WriteTimeout: time.Second * 10}
		in, _, err = cTCP.Exchange(m, "8.8.8.8:53")
		if err != nil {
			return nil, fmt.Errorf("error looking up mx over TCP: %s", err)
		}
	}

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
	fh, err := os.Open(zoneFile)
	if err != nil {
		return fmt.Errorf("parseZoneFile: unable to open %s: %w", zoneFile, err)
	}
	zp := dns.NewZoneParser(fh, "", "")

	// Summarize zone names
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
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
	var zoneFileFlag = flag.String("file", "", "zone file to parse")
	flag.Parse()

	zoneCh := make(chan string)

	zd := &zoneData{
		m: map[string]struct{}{},
		limiter: rate.NewLimiter(10, 1),
	}

	numWorkers := 10

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

	for i := 0; i < numWorkers; i++ {
		go queryWorker(i, zoneCh, &wg, zd)
	}

	fmt.Println("sending work to workers...")
	counter := 100
	for zone := range zd.m {
		if counter == 0 {
			break
		}
		zoneCh <- zone
		counter -= 1
	}

	close(zoneCh)
	wg.Wait()

	fmt.Printf("At %s the .se zone contains %d domains\n", time.Now().Format(time.RFC3339), len(zd.m))
	fmt.Printf("%.2f%% have IPv6 on www\n", float64(zd.wwwCounter)/float64(len(zd.m)))
	fmt.Printf("%.2f%% have IPv6 on one or more DNS\n", float64(zd.nsCounter)/float64(len(zd.m)))
	fmt.Printf("%.2f have IPv6 on one or more MX\n", float64(zd.mxCounter)/float64(len(zd.m)))
}
