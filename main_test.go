package main

import (
	"log/slog"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

func sendNotImp(t *testing.T, w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeNotImplemented)
	err := w.WriteMsg(m)
	if err != nil {
		t.Errorf("sendNotImp: WriteMsg failed: %s", err)
	}
}

func sendRefused(t *testing.T, w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeRefused)
	err := w.WriteMsg(m)
	if err != nil {
		t.Errorf("sendRefused: WriteMsg failed: %s", err)
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
				t.Errorf("unable to parse zone file: %s", err)
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
		case dns.TypeAAAA:
			switch r.Question[0].Name {
			case "www.ok.test.":
				m := new(dns.Msg)
				m.SetReply(r)

				ip6 := net.ParseIP("::1")

				aaaa := new(dns.AAAA)
				aaaa.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 3600}
				aaaa.AAAA = ip6

				m.Answer = append(m.Answer, aaaa)
				err := w.WriteMsg(m)
				if err != nil {
					t.Errorf("AAAA WriteMsg failed: %s", err)
				}
				return
			default:
				sendRefused(t, w, r)
				return
			}
		case dns.TypeMX:
			switch r.Question[0].Name {
			case "ok.test.":
				m := new(dns.Msg)
				m.SetReply(r)

				mx := new(dns.MX)
				mx.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 3600}
				mx.Preference = 10
				mx.Mx = "www.ok.test."
				m.Answer = append(m.Answer, mx)

				err := w.WriteMsg(m)
				if err != nil {
					t.Errorf("MX WriteMsg failed: %s", err)
				}
				return
			default:
				sendRefused(t, w, r)
				return
			}
		case dns.TypeNS:
			switch r.Question[0].Name {
			case "ok.test.":
				m := new(dns.Msg)
				m.SetReply(r)

				ns := new(dns.NS)
				ns.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}
				ns.Ns = "www.ok.test."

				m.Answer = append(m.Answer, ns)

				err := w.WriteMsg(m)
				if err != nil {
					t.Errorf("MX WriteMsg failed: %s", err)
				}
				return
			default:
				sendRefused(t, w, r)
				return
			}
		default:
			sendNotImp(t, w, r)
			return
		}

		// Catch anything else
		sendNotImp(t, w, r)
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

	_, err = run(tcpListener.Addr().String(), udpListener.LocalAddr().String(), "test.", "", runtime.NumCPU(), -1, true, logger)
	if err != nil {
		logger.Error("run failed", "error", err)
		os.Exit(1)
	}
}
