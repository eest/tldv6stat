package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func sendNotImp(t *testing.T, w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeNotImplemented)
	err := w.WriteMsg(m)
	if err != nil {
		t.Errorf("sendNotImp: WriteMsg failed for %s (%s): %s", r.Question[0].Name, dns.TypeToString[r.Question[0].Qtype], err)
	}
}

func sendRefused(t *testing.T, w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeRefused)
	err := w.WriteMsg(m)
	if err != nil {
		t.Errorf("sendRefused: WriteMsg failed for %s (%s): %s", r.Question[0].Name, dns.TypeToString[r.Question[0].Qtype], err)

	}
}

func handleRequest(t *testing.T) dns.HandlerFunc {
	testZone := "test."
	testZoneFilename := testZone + "zone"
	return func(w dns.ResponseWriter, r *dns.Msg) {
		defer w.Close()

		if r.Question[0].Qclass != dns.ClassINET {
			sendNotImp(t, w, r)
			return
		}

		switch r.Question[0].Qtype {
		case dns.TypeAXFR:
			if r.Question[0].Name != "test." {
				sendRefused(t, w, r)
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

			ch := make(chan *dns.Envelope)
			tr := new(dns.Transfer)
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				err := tr.Out(w, r, ch)
				if err != nil {
					t.Errorf("tr.Out() failed: %s", err)
				}
				wg.Done()
			}()
			ch <- &dns.Envelope{RR: zoneContent}
			close(ch)
			wg.Wait()
		case dns.TypeA:
			switch r.Question[0].Name {
			case "www.ok.test.", "www.ok-2.test.", "www.invalid-a-in-aaaa.test.", "www.invalid-mx-cname.test.", "www.invalid-ns-cname.test.", "www.additional-aaaa.test.", "www.additional-aaaa-2.test.":
				// Also has A
				m := new(dns.Msg)
				m.SetReply(r)

				ip4 := net.ParseIP("127.0.0.1")

				a := new(dns.A)
				a.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}
				a.A = ip4

				m.Answer = append(m.Answer, a)
				err := w.WriteMsg(m)
				if err != nil {
					t.Errorf("%s (%s): WriteMsg failed: %s", r.Question[0].Name, dns.TypeToString[r.Question[0].Qtype], err)
				}
				return
			case "www.invalid-aaaa-in-a.test.":
				// Broken response with AAAA record in A answer section
				m := new(dns.Msg)
				m.SetReply(r)

				ip6 := net.ParseIP("::1")

				aaaa := new(dns.AAAA)
				aaaa.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 3600}
				aaaa.AAAA = ip6

				m.Answer = append(m.Answer, aaaa)
				err := w.WriteMsg(m)
				if err != nil {
					t.Errorf("%s (%s): WriteMsg failed: %s", r.Question[0].Name, dns.TypeToString[r.Question[0].Qtype], err)
				}
				return
			case "www.onlyv6.test.", "www.onlyv6-2.test.":
				// No A record present, respond with empty NOERROR
				m := new(dns.Msg)
				m.SetReply(r)
				err := w.WriteMsg(m)
				if err != nil {
					t.Errorf("%s (%s): WriteMsg failed: %s", r.Question[0].Name, dns.TypeToString[r.Question[0].Qtype], err)
				}
			case "www.timeout.test.", "www.onlyv6-a-timeout.test.":
				// Do not respond
				return
			case "www.cname-www.test.":
				// Response with CNAME followed by AAAA record in answer section, valid because it is www lookup
				m := new(dns.Msg)
				m.SetReply(r)

				cnameTarget := "www-target.cname.test."

				cname := new(dns.CNAME)
				cname.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 3600}
				cname.Target = cnameTarget
				m.Answer = append(m.Answer, cname)

				ip4 := net.ParseIP("127.0.0.1")
				a := new(dns.A)
				a.Hdr = dns.RR_Header{Name: cnameTarget, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}
				a.A = ip4

				m.Answer = append(m.Answer, a)
				err := w.WriteMsg(m)
				if err != nil {
					t.Errorf("%s (%s): WriteMsg failed: %s", r.Question[0].Name, dns.TypeToString[r.Question[0].Qtype], err)
				}
				return
			default:
				sendRefused(t, w, r)
				return
			}
		case dns.TypeAAAA:
			switch r.Question[0].Name {
			case "www.ok.test.", "www.ok-2.test.", "www.onlyv6.test.", "www.onlyv6-2.test.", "www.onlyv6-a-timeout.test.", "www.invalid-aaaa-in-a.test.", "www.invalid-mx-cname.test.", "www.invalid-ns-cname.test.", "www.additional-aaaa.test.", "www.additional-aaaa-2.test.":
				m := new(dns.Msg)
				m.SetReply(r)

				ip6 := net.ParseIP("::1")

				aaaa := new(dns.AAAA)
				aaaa.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 3600}
				aaaa.AAAA = ip6

				m.Answer = append(m.Answer, aaaa)
				err := w.WriteMsg(m)
				if err != nil {
					t.Errorf("%s (%s): WriteMsg failed: %s", r.Question[0].Name, dns.TypeToString[r.Question[0].Qtype], err)
				}
				return
			case "www.onlyv4.test.", "www.onlyv4-2.test.":
				// Respond with empty NOERROR
				m := new(dns.Msg)
				m.SetReply(r)
				err := w.WriteMsg(m)
				if err != nil {
					t.Errorf("%s (%s): WriteMsg failed: %s", r.Question[0].Name, dns.TypeToString[r.Question[0].Qtype], err)
				}
			case "www.timeout.test.":
				// Do not respond
				return
			case "www.invalid-a-in-aaaa.test.":
				// Broken response with A record in AAAA answer section
				m := new(dns.Msg)
				m.SetReply(r)

				ip4 := net.ParseIP("127.0.0.1")

				a := new(dns.A)
				a.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}
				a.A = ip4

				m.Answer = append(m.Answer, a)
				err := w.WriteMsg(m)
				if err != nil {
					t.Errorf("%s (%s): WriteMsg failed: %s", r.Question[0].Name, dns.TypeToString[r.Question[0].Qtype], err)
				}
				return
			case "cname.test.":
				// Response with CNAME followed by AAAA record in answer section, invalid if present in NS or MX rdata.
				m := new(dns.Msg)
				m.SetReply(r)

				cnameTarget := "mx.cname.test."

				cname := new(dns.CNAME)
				cname.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 3600}
				cname.Target = cnameTarget
				m.Answer = append(m.Answer, cname)

				ip6 := net.ParseIP("::1")
				aaaa := new(dns.AAAA)
				aaaa.Hdr = dns.RR_Header{Name: cnameTarget, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 3600}
				aaaa.AAAA = ip6

				m.Answer = append(m.Answer, aaaa)
				err := w.WriteMsg(m)
				if err != nil {
					t.Errorf("%s (%s): WriteMsg failed: %s", r.Question[0].Name, dns.TypeToString[r.Question[0].Qtype], err)
				}
				return
			case "ns.cname.test.":
				// Response with CNAME followed by AAAA record in answer section, invalid if present in NS or MX rdata.
				m := new(dns.Msg)
				m.SetReply(r)

				cnameTarget := "ns-aaaa.cname.test."

				cname := new(dns.CNAME)
				cname.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 3600}
				cname.Target = cnameTarget
				m.Answer = append(m.Answer, cname)

				ip6 := net.ParseIP("::1")
				aaaa := new(dns.AAAA)
				aaaa.Hdr = dns.RR_Header{Name: cnameTarget, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 3600}
				aaaa.AAAA = ip6

				m.Answer = append(m.Answer, aaaa)
				err := w.WriteMsg(m)
				if err != nil {
					t.Errorf("%s (%s): WriteMsg failed: %s", r.Question[0].Name, dns.TypeToString[r.Question[0].Qtype], err)
				}
				return
			case "www.cname-www.test.":
				// Response with CNAME followed by AAAA record in answer section, valid because it is www lookup
				m := new(dns.Msg)
				m.SetReply(r)

				cnameTarget := "www-target.cname.test."

				cname := new(dns.CNAME)
				cname.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 3600}
				cname.Target = cnameTarget
				m.Answer = append(m.Answer, cname)

				ip6 := net.ParseIP("::1")
				aaaa := new(dns.AAAA)
				aaaa.Hdr = dns.RR_Header{Name: cnameTarget, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 3600}
				aaaa.AAAA = ip6

				m.Answer = append(m.Answer, aaaa)
				err := w.WriteMsg(m)
				if err != nil {
					t.Errorf("%s (%s): WriteMsg failed: %s", r.Question[0].Name, dns.TypeToString[r.Question[0].Qtype], err)
				}
				return
			default:
				sendRefused(t, w, r)
				return
			}
		case dns.TypeMX:
			switch r.Question[0].Name {
			case "ok.test.", "ok-2.test.", "onlyv6.test.", "onlyv6-2.test.", "onlyv6-a-timeout.test.", "invalid-a-in-aaaa.test.", "invalid-aaaa-in-a.test.", "invalid-ns-cname.test.", "cname-www.test.":
				m := new(dns.Msg)
				m.SetReply(r)

				mx := new(dns.MX)
				mx.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 3600}
				mx.Preference = 10
				mx.Mx = "www.ok.test."
				m.Answer = append(m.Answer, mx)

				err := w.WriteMsg(m)
				if err != nil {
					t.Errorf("%s (%s): WriteMsg failed: %s", r.Question[0].Name, dns.TypeToString[r.Question[0].Qtype], err)
				}
				return
			case "onlyv4.test.", "onlyv4-2.test.":
				// Has MX, but only pointing to A
				m := new(dns.Msg)
				m.SetReply(r)

				mx := new(dns.MX)
				mx.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 3600}
				mx.Preference = 10
				mx.Mx = "www.onlyv4.test."
				m.Answer = append(m.Answer, mx)

				err := w.WriteMsg(m)
				if err != nil {
					t.Errorf("%s (%s): WriteMsg failed: %s", r.Question[0].Name, dns.TypeToString[r.Question[0].Qtype], err)
				}
			case "invalid-mx-cname.test.":
				// Has MX, but rdata points to CNAME
				m := new(dns.Msg)
				m.SetReply(r)

				mx := new(dns.MX)
				mx.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 3600}
				mx.Preference = 10
				mx.Mx = "cname.test."
				m.Answer = append(m.Answer, mx)

				err := w.WriteMsg(m)
				if err != nil {
					t.Errorf("%s (%s): WriteMsg failed: %s", r.Question[0].Name, dns.TypeToString[r.Question[0].Qtype], err)
				}
			case "timeout.test.":
				// Do not respond
				return
			case "additional-aaaa.test.", "additional-aaaa-2.test.":
				// Has MX and additional section with AAAA for the name
				m := new(dns.Msg)
				m.SetReply(r)

				mxName := "mx.additional-aaaa.test."

				mx := new(dns.MX)
				mx.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 3600}
				mx.Preference = 10
				mx.Mx = mxName
				m.Answer = append(m.Answer, mx)

				ip6 := net.ParseIP("::1")
				aaaa := new(dns.AAAA)
				aaaa.Hdr = dns.RR_Header{Name: mxName, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 3600}
				aaaa.AAAA = ip6

				m.Extra = append(m.Extra, aaaa)

				err := w.WriteMsg(m)
				if err != nil {
					t.Errorf("%s (%s): WriteMsg failed: %s", r.Question[0].Name, dns.TypeToString[r.Question[0].Qtype], err)
				}
			default:
				sendRefused(t, w, r)
				return
			}
		case dns.TypeNS:
			switch r.Question[0].Name {
			case "ok.test.", "ok-2.test.", "onlyv6.test.", "onlyv6-2.test.", "onlyv6-a-timeout.test.", "invalid-a-in-aaaa.test.", "invalid-aaaa-in-a.test.", "invalid-mx-cname.test.", "cname-www.test.":
				m := new(dns.Msg)
				m.SetReply(r)

				ns := new(dns.NS)
				ns.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}
				ns.Ns = "www.ok.test."
				m.Answer = append(m.Answer, ns)

				err := w.WriteMsg(m)
				if err != nil {
					t.Errorf("%s (%s): WriteMsg failed: %s", r.Question[0].Name, dns.TypeToString[r.Question[0].Qtype], err)
				}
				return
			case "onlyv4.test.", "onlyv4-2.test.":
				// Has NS, but only pointing to A
				m := new(dns.Msg)
				m.SetReply(r)

				ns := new(dns.NS)
				ns.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}
				ns.Ns = "www.onlyv4.test."
				m.Answer = append(m.Answer, ns)

				err := w.WriteMsg(m)
				if err != nil {
					t.Errorf("%s (%s): WriteMsg failed: %s", r.Question[0].Name, dns.TypeToString[r.Question[0].Qtype], err)
				}
			case "timeout.test.":
				// Do not respond
				return
			case "invalid-ns-cname.test.":
				// Has NS, but rdata points to CNAME
				m := new(dns.Msg)
				m.SetReply(r)

				ns := new(dns.NS)
				ns.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}
				ns.Ns = "cname.test."
				m.Answer = append(m.Answer, ns)

				err := w.WriteMsg(m)
				if err != nil {
					t.Errorf("%s (%s): WriteMsg failed: %s", r.Question[0].Name, dns.TypeToString[r.Question[0].Qtype], err)
				}
			case "additional-aaaa.test.", "additional-aaaa-2.test.":
				// Has NS, and rdata name is contained in additional section
				m := new(dns.Msg)
				m.SetReply(r)

				nsName := "ns.additional-aaaa.test."

				ns := new(dns.NS)
				ns.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}
				ns.Ns = nsName
				m.Answer = append(m.Answer, ns)

				ip6 := net.ParseIP("::1")
				aaaa := new(dns.AAAA)
				aaaa.Hdr = dns.RR_Header{Name: nsName, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 3600}
				aaaa.AAAA = ip6

				m.Extra = append(m.Extra, aaaa)

				err := w.WriteMsg(m)
				if err != nil {
					t.Errorf("%s (%s): WriteMsg failed: %s", r.Question[0].Name, dns.TypeToString[r.Question[0].Qtype], err)
				}
			default:
				sendRefused(t, w, r)
				return
			}
		default:
			sendRefused(t, w, r)
			return
		}

		// Catch anything else
		sendRefused(t, w, r)
	}

}

func TestRun(t *testing.T) {
	// Manually create UDP/TCP listeners so we can have the OS give us an
	// available port instead of hardcoding something given to
	// the normal ListenAndServe() call.
	udpListener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket failed: %s", err)
	}
	udpServer := &dns.Server{
		PacketConn: udpListener,
	}

	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %s", err)
	}
	tcpServer := &dns.Server{
		Listener: tcpListener,
	}

	udpWaitCh := make(chan struct{})
	udpServer.NotifyStartedFunc = func() { close(udpWaitCh) }
	tcpWaitCh := make(chan struct{})
	tcpServer.NotifyStartedFunc = func() { close(tcpWaitCh) }

	dns.HandleFunc(".", handleRequest(t))

	go func() {
		err := udpServer.ActivateAndServe()
		if err != nil {
			t.Errorf("UDP ActivateAndServe failed: %s", err)
		}
		udpListener.Close()
	}()
	go func() {
		err := tcpServer.ActivateAndServe()
		if err != nil {
			t.Errorf("TCP ActivateAndServe failed: %s", err)
		}
		tcpListener.Close()
	}()

	defer func() {
		err := udpServer.Shutdown()
		if err != nil {
			t.Errorf("UDP server shutdown failed: %s", err)
		}
	}()
	defer func() {
		err := tcpServer.Shutdown()
		if err != nil {
			t.Errorf("TCP server shutdown failed: %s", err)
		}
	}()

	// Wait for servers to be ready
	<-udpWaitCh
	<-tcpWaitCh

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	timeout, err := time.ParseDuration("0s")
	if err != nil {
		t.Fatal("unable to parse duration")
	}

	mxSuffixes := []string{"www.ok.test."}

	// Single worker to make sure we use cached responses
	s1, err := run(tcpListener.Addr().String(), udpListener.LocalAddr().String(), "test.", "", 1, -1, true, timeout, timeout, timeout, 10, 1, mxSuffixes, logger)
	if err != nil {
		t.Fatalf("run with single worker failed: %s", err)
	}

	j1, err := statsToJson(s1)
	if err != nil {
		t.Fatalf("statsToJson with single worker failed: %s", err)
	}

	fmt.Println(string(j1))

	// Multiple worker to test concurrency
	s2, err := run(tcpListener.Addr().String(), udpListener.LocalAddr().String(), "test.", "", 10, -1, true, timeout, timeout, timeout, 10, 1, mxSuffixes, logger)
	if err != nil {
		t.Fatalf("run with multiple workers failed: %s", err)
	}

	j2, err := statsToJson(s2)
	if err != nil {
		t.Fatalf("statsToJson with multiple workers failed: %s", err)
	}

	fmt.Println(string(j2))
}
