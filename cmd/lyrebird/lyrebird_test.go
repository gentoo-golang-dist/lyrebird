package main

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/txthinking/socks5"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/base"
	sf "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/client/lib"
)

type Transport struct {
	name     string
	thandler *testing.T
}

func (t *Transport) Name() string {
	return t.name
}

type argsCallback func(interface{})

type simpleClientFactory struct {
	transport base.Transport
	testArgs  argsCallback
}

func (t *Transport) ClientFactory(stateDir string) (base.ClientFactory, error) {
	cf := &simpleClientFactory{transport: t}
	return cf, nil
}

func (t *Transport) ServerFactory(stateDir string, args *pt.Args) (base.ServerFactory, error) {
	return nil, nil
}

func (cf *simpleClientFactory) Transport() base.Transport {
	return cf.transport
}

func (cf *simpleClientFactory) ParseArgs(args *pt.Args) (interface{}, error) {
	config := sf.ClientConfig{}
	return config, nil
}

func (cf *simpleClientFactory) OnEvent(f func(e base.TransportEvent)) {}

func (cf *simpleClientFactory) Dial(network, address string, dialFn base.DialFunc, args interface{}) (net.Conn, error) {
	cf.testArgs(args)
	return nil, fmt.Errorf("not implemented")
}

func encodeArgs(args []string) string {
	return strings.Join(args[:], ";")
}

func TestClientProxy(t *testing.T) {

	var wg sync.WaitGroup
	wg.Add(1)
	termMon = newTermMonitor()
	go termMon.wait(true)
	args := []string{"url=https://1098762253.rsc.cdn77.org/", "fronts=app.datapacket.com,www.datapacket.com"}
	proxyURI, _ := url.Parse("http://example.com")

	transport := &Transport{name: "snowflake", thandler: t}
	f, _ := transport.ClientFactory("")
	cf, ok := f.(*simpleClientFactory)
	if !ok {
		t.Error("failed to cast to simpleClientFactory")
	}
	cf.testArgs = func(args interface{}) {
		config, ok := args.(sf.ClientConfig)
		if !ok {
			t.Error("invalid type for args")
		}
		if config.CommunicationProxy == nil ||
			config.CommunicationProxy.String() != "http://example.com" {
			t.Error("Failed to preserve proxy URI")
		}
		wg.Done()
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err.Error())
	}
	go func() {
		_ = clientAcceptLoop(cf, ln, proxyURI)
	}()

	client, _ := socks5.NewClient(ln.Addr().String(), encodeArgs(args), "\x00", 0, 0)
	client.Dial("tcp", "127.0.0.1:9090")

	wg.Wait()
}
