package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

func sendNotImp(t *testing.T, w dns.ResponseWriter, req *dns.Msg) {
	m := req.Copy()
	dnsutil.SetReply(m, req)
	m.Rcode = dns.RcodeNotImplemented
	err := m.Pack()
	if err != nil {
		t.Errorf("sendNotImp: m.Pack failed for %s (%s): %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
	}
	_, err = io.Copy(w, m)
	if err != nil {
		t.Errorf("sendNotImp: io.Copy failed for %s (%s): %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
	}
}

func sendRefused(t *testing.T, w dns.ResponseWriter, req *dns.Msg) {
	m := req.Copy()
	dnsutil.SetReply(m, req)
	m.Rcode = dns.RcodeRefused
	err := m.Pack()
	if err != nil {
		t.Errorf("sendRefused: m.Pack failed for %s (%s): %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
	}
	_, err = io.Copy(w, m)
	if err != nil {
		t.Errorf("sendRefused: io.Copy failed for %s (%s): %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
	}
}

func handleRequest(t *testing.T) dns.HandlerFunc {
	testZone := "test."
	testZoneFilename := testZone + "zone"
	return func(_ context.Context, w dns.ResponseWriter, req *dns.Msg) {
		if req.Question[0].Header().Class != dns.ClassINET {
			sendNotImp(t, w, req)
			return
		}

		switch dns.RRToType(req.Question[0]) {
		case dns.TypeAXFR:
			if req.Question[0].Header().Name != "test." {
				sendRefused(t, w, req)
				return
			}

			zoneFile, err := os.Open(testZoneFilename)
			if err != nil {
				t.Errorf("unable to open file: %s", err)
				return
			}

			zoneContent := []dns.RR{}

			zp := dns.NewZoneParser(zoneFile, testZone, testZoneFilename)

			for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
				zoneContent = append(zoneContent, rr)
			}
			if zp.Err() != nil {
				t.Errorf("unable to parse zone file: %s", zp.Err())
				return
			}

			err = req.Unpack()
			if err != nil {
				t.Errorf("req.Unpack() failed: %s", err)
			}
			w.Hijack()
			env := make(chan *dns.Envelope)
			c := dns.NewClient()
			var wg sync.WaitGroup
			wg.Go(func() {
				err := c.TransferOut(w, req, env)
				if err != nil {
					t.Errorf("TransferOut() failed: %s", err)
				}
				w.Close()
			})
			env <- &dns.Envelope{Answer: zoneContent}
			close(env)
			wg.Wait()
			return
		case dns.TypeA:
			switch req.Question[0].Header().Name {
			case "www.ok.test.", "www.ok-2.test.", "www.invalid-a-in-aaaa.test.", "www.invalid-mx-cname.test.", "www.invalid-ns-cname.test.", "www.additional-aaaa.test.", "www.additional-aaaa-2.test.", "www.multi-mx.test.", "www.multi-mx-onlyv4.test.", "www.multi-mx-multimatch.test.":
				// Also has A
				m := req.Copy()
				dnsutil.SetReply(m, req)

				ip4 := netip.MustParseAddr("127.0.0.1")

				a := new(dns.A)
				a.Hdr = dns.Header{Name: req.Question[0].Header().Name, Class: dns.ClassINET, TTL: 3600}
				a.Addr = ip4

				m.Answer = append(m.Answer, a)
				err := m.Pack()
				if err != nil {
					t.Errorf("%s (%s): m.Pack failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				_, err = io.Copy(w, m)
				if err != nil {
					t.Errorf("%s (%s): io.Copy failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				return
			case "www.invalid-aaaa-in-a.test.":
				// Broken response with AAAA record in A answer section
				m := req.Copy()
				dnsutil.SetReply(m, req)

				ip6 := netip.MustParseAddr("::1")

				aaaa := new(dns.AAAA)
				aaaa.Hdr = dns.Header{Name: req.Question[0].Header().Name, Class: dns.ClassINET, TTL: 3600}
				aaaa.Addr = ip6

				m.Answer = append(m.Answer, aaaa)
				err := m.Pack()
				if err != nil {
					t.Errorf("%s (%s): m.Pack failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				_, err = io.Copy(w, m)
				if err != nil {
					t.Errorf("%s (%s): io.Copy failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				return
			case "www.onlyv6.test.", "www.onlyv6-2.test.":
				// No A record present, respond with empty NOERROR
				m := req.Copy()
				dnsutil.SetReply(m, req)
				err := m.Pack()
				if err != nil {
					t.Errorf("%s (%s): m.Pack failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				_, err = io.Copy(w, m)
				if err != nil {
					t.Errorf("%s (%s): io.Copy failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				return
			case "www.timeout.test.", "www.onlyv6-a-timeout.test.":
				// Do not respond
				return
			case "www.cname-www.test.":
				// Response with CNAME followed by AAAA record in answer section, valid because it is www lookup
				m := req.Copy()
				dnsutil.SetReply(m, req)

				cnameTarget := "www-target.cname.test."

				cname := new(dns.CNAME)
				cname.Hdr = dns.Header{Name: req.Question[0].Header().Name, Class: dns.ClassINET, TTL: 3600}
				cname.Target = cnameTarget
				m.Answer = append(m.Answer, cname)

				ip4 := netip.MustParseAddr("127.0.0.1")
				a := new(dns.A)
				a.Hdr = dns.Header{Name: cnameTarget, Class: dns.ClassINET, TTL: 3600}
				a.Addr = ip4

				m.Answer = append(m.Answer, a)
				err := m.Pack()
				if err != nil {
					t.Errorf("%s (%s): m.Pack failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				_, err = io.Copy(w, m)
				if err != nil {
					t.Errorf("%s (%s): io.Copy failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				return
			default:
				sendRefused(t, w, req)
				return
			}
		case dns.TypeAAAA:
			switch req.Question[0].Header().Name {
			case "www.ok.test.", "www.ok-2.test.", "www.onlyv6.test.", "www.onlyv6-2.test.", "www.onlyv6-a-timeout.test.", "www.invalid-aaaa-in-a.test.", "www.invalid-mx-cname.test.", "www.invalid-ns-cname.test.", "www.additional-aaaa.test.", "www.additional-aaaa-2.test.", "www.multi-mx.test.", "mx1.multi-mx.test.", "mx2.multi-mx.test.", "www.multi-mx-onlyv4.test.", "www.multi-mx-multimatch.test.":
				m := req.Copy()
				dnsutil.SetReply(m, req)

				ip6 := netip.MustParseAddr("::1")

				aaaa := new(dns.AAAA)
				aaaa.Hdr = dns.Header{Name: req.Question[0].Header().Name, Class: dns.ClassINET, TTL: 3600}
				aaaa.Addr = ip6

				m.Answer = append(m.Answer, aaaa)
				err := m.Pack()
				if err != nil {
					t.Errorf("%s (%s): m.Pack failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				_, err = io.Copy(w, m)
				if err != nil {
					t.Errorf("%s (%s): io.Copy failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				return
			case "www.onlyv4.test.", "www.onlyv4-2.test.", "mx1.multi-mx-onlyv4.test.", "mx2.multi-mx-onlyv4.test.":
				// Respond with empty NOERROR
				m := req.Copy()
				dnsutil.SetReply(m, req)
				err := m.Pack()
				if err != nil {
					t.Errorf("%s (%s): m.Pack failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				_, err = io.Copy(w, m)
				if err != nil {
					t.Errorf("%s (%s): io.Copy failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				return
			case "www.timeout.test.":
				// Do not respond
				return
			case "www.invalid-a-in-aaaa.test.":
				// Broken response with A record in AAAA answer section
				m := req.Copy()
				dnsutil.SetReply(m, req)

				ip4 := netip.MustParseAddr("127.0.0.1")

				a := new(dns.A)
				a.Hdr = dns.Header{Name: req.Question[0].Header().Name, Class: dns.ClassINET, TTL: 3600}
				a.Addr = ip4

				m.Answer = append(m.Answer, a)
				err := m.Pack()
				if err != nil {
					t.Errorf("%s (%s): m.Pack failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				_, err = io.Copy(w, m)
				if err != nil {
					t.Errorf("%s (%s): io.Copy failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				return
			case "cname.test.":
				// Response with CNAME followed by AAAA record in answer section, invalid if present in NS or MX rdata.
				m := req.Copy()
				dnsutil.SetReply(m, req)

				cnameTarget := "mx.cname.test."

				cname := new(dns.CNAME)
				cname.Hdr = dns.Header{Name: req.Question[0].Header().Name, Class: dns.ClassINET, TTL: 3600}
				cname.Target = cnameTarget
				m.Answer = append(m.Answer, cname)

				ip6 := netip.MustParseAddr("::1")
				aaaa := new(dns.AAAA)
				aaaa.Hdr = dns.Header{Name: cnameTarget, Class: dns.ClassINET, TTL: 3600}
				aaaa.Addr = ip6

				m.Answer = append(m.Answer, aaaa)
				err := m.Pack()
				if err != nil {
					t.Errorf("%s (%s): m.Pack failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				_, err = io.Copy(w, m)
				if err != nil {
					t.Errorf("%s (%s): io.Copy failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				return
			case "ns.cname.test.":
				// Response with CNAME followed by AAAA record in answer section, invalid if present in NS or MX rdata.
				m := req.Copy()
				dnsutil.SetReply(m, req)

				cnameTarget := "ns-aaaa.cname.test."

				cname := new(dns.CNAME)
				cname.Hdr = dns.Header{Name: req.Question[0].Header().Name, Class: dns.ClassINET, TTL: 3600}
				cname.Target = cnameTarget
				m.Answer = append(m.Answer, cname)

				ip6 := netip.MustParseAddr("::1")
				aaaa := new(dns.AAAA)
				aaaa.Hdr = dns.Header{Name: cnameTarget, Class: dns.ClassINET, TTL: 3600}
				aaaa.Addr = ip6

				m.Answer = append(m.Answer, aaaa)
				err := m.Pack()
				if err != nil {
					t.Errorf("%s (%s): m.Pack failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				_, err = io.Copy(w, m)
				if err != nil {
					t.Errorf("%s (%s): io.Copy failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				return
			case "www.cname-www.test.":
				// Response with CNAME followed by AAAA record in answer section, valid because it is www lookup
				m := req.Copy()
				dnsutil.SetReply(m, req)

				cnameTarget := "www-target.cname.test."

				cname := new(dns.CNAME)
				cname.Hdr = dns.Header{Name: req.Question[0].Header().Name, Class: dns.ClassINET, TTL: 3600}
				cname.Target = cnameTarget
				m.Answer = append(m.Answer, cname)

				ip6 := netip.MustParseAddr("::1")
				aaaa := new(dns.AAAA)
				aaaa.Hdr = dns.Header{Name: cnameTarget, Class: dns.ClassINET, TTL: 3600}
				aaaa.Addr = ip6

				m.Answer = append(m.Answer, aaaa)
				err := m.Pack()
				if err != nil {
					t.Errorf("%s (%s): m.Pack failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				_, err = io.Copy(w, m)
				if err != nil {
					t.Errorf("%s (%s): io.Copy failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				return
			default:
				sendRefused(t, w, req)
				return
			}
		case dns.TypeMX:
			switch req.Question[0].Header().Name {
			case "ok.test.", "ok-2.test.", "onlyv6.test.", "onlyv6-2.test.", "onlyv6-a-timeout.test.", "invalid-a-in-aaaa.test.", "invalid-aaaa-in-a.test.", "invalid-ns-cname.test.", "cname-www.test.":
				m := req.Copy()
				dnsutil.SetReply(m, req)

				mx := new(dns.MX)
				mx.Hdr = dns.Header{Name: req.Question[0].Header().Name, Class: dns.ClassINET, TTL: 3600}
				mx.Preference = 10
				mx.Mx = "www.ok.test."
				m.Answer = append(m.Answer, mx)

				err := m.Pack()
				if err != nil {
					t.Errorf("%s (%s): m.Pack failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				_, err = io.Copy(w, m)
				if err != nil {
					t.Errorf("%s (%s): io.Copy failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				return
			case "onlyv4.test.", "onlyv4-2.test.":
				// Has MX, but only pointing to A
				m := req.Copy()
				dnsutil.SetReply(m, req)

				mx := new(dns.MX)
				mx.Hdr = dns.Header{Name: req.Question[0].Header().Name, Class: dns.ClassINET, TTL: 3600}
				mx.Preference = 10
				mx.Mx = "www.onlyv4.test."
				m.Answer = append(m.Answer, mx)

				err := m.Pack()
				if err != nil {
					t.Errorf("%s (%s): m.Pack failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				_, err = io.Copy(w, m)
				if err != nil {
					t.Errorf("%s (%s): io.Copy failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				return
			case "invalid-mx-cname.test.":
				// Has MX, but rdata points to CNAME
				m := req.Copy()
				dnsutil.SetReply(m, req)

				mx := new(dns.MX)
				mx.Hdr = dns.Header{Name: req.Question[0].Header().Name, Class: dns.ClassINET, TTL: 3600}
				mx.Preference = 10
				mx.Mx = "cname.test."
				m.Answer = append(m.Answer, mx)

				err := m.Pack()
				if err != nil {
					t.Errorf("%s (%s): m.Pack failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				_, err = io.Copy(w, m)
				if err != nil {
					t.Errorf("%s (%s): io.Copy failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				return
			case "timeout.test.":
				// Do not respond
				return
			case "additional-aaaa.test.", "additional-aaaa-2.test.":
				// Has MX and additional section with AAAA for the name
				m := req.Copy()
				dnsutil.SetReply(m, req)

				mxName := "mx.additional-aaaa.test."

				mx := new(dns.MX)
				mx.Hdr = dns.Header{Name: req.Question[0].Header().Name, Class: dns.ClassINET, TTL: 3600}
				mx.Preference = 10
				mx.Mx = mxName
				m.Answer = append(m.Answer, mx)

				ip6 := netip.MustParseAddr("::1")
				aaaa := new(dns.AAAA)
				aaaa.Hdr = dns.Header{Name: mxName, Class: dns.ClassINET, TTL: 3600}
				aaaa.Addr = ip6

				m.Extra = append(m.Extra, aaaa)

				err := m.Pack()
				if err != nil {
					t.Errorf("%s (%s): m.Pack failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				_, err = io.Copy(w, m)
				if err != nil {
					t.Errorf("%s (%s): io.Copy failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				return
			case "multi-mx.test.":
				// Has multiple MX records
				m := req.Copy()
				dnsutil.SetReply(m, req)

				for _, mxName := range []string{"mx1.multi-mx.test.", "mx2.multi-mx.test."} {
					mx := new(dns.MX)
					mx.Hdr = dns.Header{Name: req.Question[0].Header().Name, Class: dns.ClassINET, TTL: 3600}
					mx.Preference = 10
					mx.Mx = mxName
					m.Answer = append(m.Answer, mx)
				}

				err := m.Pack()
				if err != nil {
					t.Errorf("%s (%s): m.Pack failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				_, err = io.Copy(w, m)
				if err != nil {
					t.Errorf("%s (%s): io.Copy failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				return
			case "multi-mx-onlyv4.test.":
				// Has multiple MX records, but all of them IPv4-only
				m := req.Copy()
				dnsutil.SetReply(m, req)

				for _, mxName := range []string{"mx1.multi-mx-onlyv4.test.", "mx2.multi-mx-onlyv4.test."} {
					mx := new(dns.MX)
					mx.Hdr = dns.Header{Name: req.Question[0].Header().Name, Class: dns.ClassINET, TTL: 3600}
					mx.Preference = 10
					mx.Mx = mxName
					m.Answer = append(m.Answer, mx)
				}

				err := m.Pack()
				if err != nil {
					t.Errorf("%s (%s): m.Pack failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				_, err = io.Copy(w, m)
				if err != nil {
					t.Errorf("%s (%s): io.Copy failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				return
			case "multi-mx-multimatch.test.":
				// Has multiple MX records, matching multiple suffixes
				m := req.Copy()
				dnsutil.SetReply(m, req)

				for _, mxName := range []string{"mx1.multi-mx.test.", "mx1.multi-mx2.test."} {
					mx := new(dns.MX)
					mx.Hdr = dns.Header{Name: req.Question[0].Header().Name, Class: dns.ClassINET, TTL: 3600}
					mx.Preference = 10
					mx.Mx = mxName
					m.Answer = append(m.Answer, mx)
				}

				err := m.Pack()
				if err != nil {
					t.Errorf("%s (%s): m.Pack failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				_, err = io.Copy(w, m)
				if err != nil {
					t.Errorf("%s (%s): io.Copy failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				return
			default:
				sendRefused(t, w, req)
				return
			}
		case dns.TypeNS:
			switch req.Question[0].Header().Name {
			case "ok.test.", "ok-2.test.", "onlyv6.test.", "onlyv6-2.test.", "onlyv6-a-timeout.test.", "invalid-a-in-aaaa.test.", "invalid-aaaa-in-a.test.", "invalid-mx-cname.test.", "cname-www.test.", "multi-mx.test.", "multi-mx-onlyv4.test.", "multi-mx-multimatch.test.":
				m := req.Copy()
				dnsutil.SetReply(m, req)

				ns := new(dns.NS)
				ns.Hdr = dns.Header{Name: req.Question[0].Header().Name, Class: dns.ClassINET, TTL: 3600}
				ns.Ns = "www.ok.test."
				m.Answer = append(m.Answer, ns)

				err := m.Pack()
				if err != nil {
					t.Errorf("%s (%s): m.Pack failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				_, err = io.Copy(w, m)
				if err != nil {
					t.Errorf("%s (%s): io.Copy failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				return
			case "onlyv4.test.", "onlyv4-2.test.":
				// Has NS, but only pointing to A
				m := req.Copy()
				dnsutil.SetReply(m, req)

				ns := new(dns.NS)
				ns.Hdr = dns.Header{Name: req.Question[0].Header().Name, Class: dns.ClassINET, TTL: 3600}
				ns.Ns = "www.onlyv4.test."
				m.Answer = append(m.Answer, ns)

				err := m.Pack()
				if err != nil {
					t.Errorf("%s (%s): m.Pack failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				_, err = io.Copy(w, m)
				if err != nil {
					t.Errorf("%s (%s): io.Copy failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				return
			case "timeout.test.":
				// Do not respond
				return
			case "invalid-ns-cname.test.":
				// Has NS, but rdata points to CNAME
				m := req.Copy()
				dnsutil.SetReply(m, req)

				ns := new(dns.NS)
				ns.Hdr = dns.Header{Name: req.Question[0].Header().Name, Class: dns.ClassINET, TTL: 3600}
				ns.Ns = "cname.test."
				m.Answer = append(m.Answer, ns)

				err := m.Pack()
				if err != nil {
					t.Errorf("%s (%s): m.Pack failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				_, err = io.Copy(w, m)
				if err != nil {
					t.Errorf("%s (%s): io.Copy failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				return
			case "additional-aaaa.test.", "additional-aaaa-2.test.":
				// Has NS, and rdata name is contained in additional section
				m := req.Copy()
				dnsutil.SetReply(m, req)

				nsName := "ns.additional-aaaa.test."

				ns := new(dns.NS)
				ns.Hdr = dns.Header{Name: req.Question[0].Header().Name, Class: dns.ClassINET, TTL: 3600}
				ns.Ns = nsName
				m.Answer = append(m.Answer, ns)

				ip6 := netip.MustParseAddr("::1")
				aaaa := new(dns.AAAA)
				aaaa.Hdr = dns.Header{Name: nsName, Class: dns.ClassINET, TTL: 3600}
				aaaa.Addr = ip6

				m.Extra = append(m.Extra, aaaa)

				err := m.Pack()
				if err != nil {
					t.Errorf("%s (%s): m.Pack failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				_, err = io.Copy(w, m)
				if err != nil {
					t.Errorf("%s (%s): io.Copy failed: %s", req.Question[0].Header().Name, dns.TypeToString[dns.RRToType(req.Question[0])], err)
				}
				return
			default:
				sendRefused(t, w, req)
				return
			}
		default:
			sendRefused(t, w, req)
			return
		}
	}
}

func TestRun(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	// Manually create UDP/TCP listeners so we can have the OS give us an
	// available port instead of hardcoding something in call to
	// ListenAndServe(). The function will prefer using srv.PacketConn or
	// src.Listener if not nil.
	udpListener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket failed: %s", err)
	}

	logger.Info("UDP listener open", "listener", udpListener.LocalAddr().String())
	udpServer := &dns.Server{
		PacketConn: udpListener,
	}

	dns.NewServer()

	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %s", err)
	}

	logger.Info("TCP listener open", "listener", tcpListener.Addr().String())
	tcpServer := &dns.Server{
		Listener: tcpListener,
	}

	udpWaitCh := make(chan struct{})
	udpServer.NotifyStartedFunc = func(context.Context) { close(udpWaitCh) }
	tcpWaitCh := make(chan struct{})
	tcpServer.NotifyStartedFunc = func(context.Context) { close(tcpWaitCh) }

	dns.HandleFunc(".", handleRequest(t))

	go func() {
		err := udpServer.ListenAndServe()
		if err != nil {
			t.Errorf("UDP ActivateAndServe failed: %s", err)
		}
	}()
	go func() {
		err := tcpServer.ListenAndServe()
		if err != nil {
			t.Errorf("TCP ActivateAndServe failed: %s", err)
		}
	}()

	defer func() {
		udpServer.Shutdown(context.TODO())
	}()
	defer func() {
		tcpServer.Shutdown(context.TODO())
	}()

	// Wait for servers to be ready
	<-udpWaitCh
	<-tcpWaitCh

	timeout, err := time.ParseDuration("0s")
	if err != nil {
		t.Fatal("unable to parse duration")
	}

	mxSuffixes := []string{".multi-mx.test.", ".multi-mx2.test.", ".multi-mx-onlyv4.test."}

	// Single worker to make sure we use cached responses
	s1, err := run(tcpListener.Addr().String(), udpListener.LocalAddr().String(), "test.", "", 1, -1, true, timeout, timeout, timeout, 10, 1, mxSuffixes, logger)
	if err != nil {
		t.Fatalf("run with single worker failed: %s", err)
	}

	j1, err := statsToJSON(s1)
	if err != nil {
		t.Fatalf("statsToJSON with single worker failed: %s", err)
	}

	fmt.Println(string(j1))

	// Multiple workers to test concurrency
	s2, err := run(tcpListener.Addr().String(), udpListener.LocalAddr().String(), "test.", "", 10, -1, true, timeout, timeout, timeout, 10, 1, mxSuffixes, logger)
	if err != nil {
		t.Fatalf("run with multiple workers failed: %s", err)
	}

	j2, err := statsToJSON(s2)
	if err != nil {
		t.Fatalf("statsToJSON with multiple workers failed: %s", err)
	}

	fmt.Println(string(j2))
}
