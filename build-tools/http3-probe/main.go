package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "CADDY_HTTP3_CANARY=FAIL:"+format+"\n", args...)
	os.Exit(2)
}

func main() {
	if len(os.Args) != 4 {
		fail("usage: SERVER_NAME IP_ADDRESS PATH")
	}
	serverName := strings.TrimSpace(os.Args[1])
	address := strings.TrimSpace(os.Args[2])
	requestPath := strings.TrimSpace(os.Args[3])
	if serverName == "" || net.ParseIP(address) == nil || !strings.HasPrefix(requestPath, "/") {
		fail("invalid arguments")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         serverName,
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true, // Ephemeral local-CA canary only.
		},
	}
	defer transport.Close()

	url := "https://" + net.JoinHostPort(address, "443") + requestPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		fail("request:%T", err)
	}
	req.Host = serverName
	resp, err := transport.RoundTrip(req)
	if err != nil {
		fail("roundtrip:%T", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		fail("status:%d", resp.StatusCode)
	}
	if resp.ProtoMajor != 3 {
		fail("protocol:%s", resp.Proto)
	}
	fmt.Printf("CADDY_HTTP3_CANARY=PASS protocol=%s status=%d\n", resp.Proto, resp.StatusCode)
}
