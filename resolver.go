package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ResolvError type
type ResolvError struct {
	qname, net  string
	nameservers []string
}

// Error formats a ResolvError
func (e ResolvError) Error() string {
	errmsg := fmt.Sprintf("%s resolv failed on %s (%s)", e.qname, strings.Join(e.nameservers, "; "), e.net)
	return errmsg
}

// Resolver type
type Resolver struct {
	config *dns.ClientConfig
}

// Lookup will ask each nameserver in top-to-bottom fashion, starting a new request
// in every second, and return as early as possbile (have an answer).
// It returns an error if no request has succeeded.
func (r *Resolver) Lookup(net string, req *dns.Msg, timeout int, interval int, nameServers []string, dohs []string, dnsFallback bool) (message *dns.Msg, err error) {

	res := make(chan *dns.Msg, 1)
	var wg sync.WaitGroup
	qname := req.Question[0].Name

	c := &dns.Client{
		Net:          net,
		ReadTimeout:  r.Timeout(timeout),
		WriteTimeout: r.Timeout(timeout),
	}

	ticker := time.NewTicker(time.Duration(interval) * time.Millisecond)
	defer ticker.Stop()

	// func to complete a DoH lookup
	D := func(dohURL string) {
		defer wg.Done()
		r, err := r.DoHLookup(dohURL, timeout, req)
		if err != nil {
			logger.Errorf("DoH lookup error. Host: %s Error: %v", dohURL, err.Error())
			return // exit the goroutine without returning result
		}
		// non blocking select. If we can't send on the channel then select default and exit goroutine
		select {
		case res <- r:
		default:
		}
	}

	// func to complete a DNS lookup
	L := func(nameserver string) {
		defer wg.Done()
		r, _, err := c.Exchange(req, nameserver)
		if err != nil {
			logger.Errorf("%s socket error on %s", qname, nameserver)
			logger.Errorf("error:%s", err.Error())
			return
		}
		if r != nil && r.Rcode != dns.RcodeSuccess {
			logger.Warningf("%s failed to get an valid answer on %s", qname, nameserver)
			if r.Rcode == dns.RcodeServerFailure {
				return
			}
		} else {
			logger.Debugf("%s resolv on %s (%s)\n", UnFqdn(qname), nameserver, net)
		}
		// non blocking select. If we can't send on the channel then select default and exit goroutine
		select {
		case res <- r:
		default:
		}
	}

	//Is DoH enabled
	if x := len(dohs); x > 0 {
		//First try and use DOH. Privacy First

		// Start lookup on each nameserver top-down, in every second
		for _, doh := range dohs {
			logger.Debugf("DoH lookup to host: %s for query: %s", doh, qname)
			wg.Add(1)
			go D(doh)
			// Block until we have an answer or timeout
			select {
			case r := <-res:
				return r, nil
			case <-ticker.C:
				// no answer so ask other upstreams
				continue
			}
		}

		// wait for all the DoH requests to finish
		wg.Wait()
		// non blocking select. If no answer is awaiting then select default and fallback or fail
		select {
		case r := <-res:
			return r, nil
		default:
			if !dnsFallback {
				logger.Debugf("DoH lookup failed and not falling back to DNS nameservers")
				return nil, ResolvError{qname, net, dohs}
			}
		}
	}

	// Start lookup on each nameserver top-down, in every second
	for _, nameServer := range nameServers {
		logger.Debugf("DNS lookup to host: %s for query: %s", nameServer, qname)
		wg.Add(1)
		go L(nameServer)
		// but exit early, if we have an answer
		select {
		case r := <-res:
			return r, nil
		case <-ticker.C:
			continue
		}
	}

	// wait for all the namservers to finish
	wg.Wait()
	select {
	case r := <-res:
		return r, nil
	default:
		return nil, ResolvError{qname, net, nameServers}
	}
}

// Timeout returns the resolver timeout
func (r *Resolver) Timeout(timeout int) time.Duration {
	return time.Duration(timeout) * time.Second
}

//DoHLookup performs a DNS lookup over https
func (r *Resolver) DoHLookup(url string, timeout int, req *dns.Msg) (*dns.Msg, error) {
	qname := req.Question[0].Name

	//Turn message into wire format
	data, err := req.Pack()
	if err != nil {
		logger.Errorf("Failed to pack DNS message to wire format; %s", err)
		return nil, ResolvError{qname, "HTTPS", []string{url}}
	}

	//Make the request to the server
	client := http.Client{
		Timeout: r.Timeout(timeout),
	}

	reader := bytes.NewReader(data)
	resp, err := client.Post(url, "application/dns-message", reader)
	if err != nil {
		logger.Errorf("Request to DoH server failed; %s", err)
		return nil, ResolvError{qname, "HTTPS", []string{url}}
	}

	defer resp.Body.Close()

	//Check the request went ok
	if resp.StatusCode != http.StatusOK {
		return nil, ResolvError{qname, "HTTPS", []string{url}}
	}

	if resp.Header.Get("Content-Type") != "application/dns-message" {
		return nil, ResolvError{qname, "HTTPS", []string{url}}
	}

	//Unpack the message from the HTTPS response
	respPacket, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, ResolvError{qname, "HTTPS", []string{url}}
	}

	res := dns.Msg{}
	err = res.Unpack(respPacket)
	if err != nil {
		logger.Errorf("Failed to unpack message from response; %s", err)
		return nil, ResolvError{qname, "HTTPS", []string{url}}
	}

	//Finally return
	return &res, nil
}
