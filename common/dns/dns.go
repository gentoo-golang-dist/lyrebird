package dns

import (
	"context"
	"net"
	"strings"
	"time"
)

const DefaultDNSTimeout = 10 * time.Second

/*
 * Performs DNS resolution and returns single list of IP addresses,
 * where IPv6 addresses appear first.
 */
func LookupHost(domain string, timeout time.Duration) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ipAddrs, err := net.DefaultResolver.LookupHost(ctx, domain)
	if err != nil {
		return nil, err
	}

	addrsIPv4, addrsIPv6 := splitIPAddrListByIPVersion(ipAddrs)
	ipAddrs = nil

	for _, addrIPv6 := range addrsIPv6 {
		ipAddrs = append(ipAddrs, addrIPv6)
	}

	for _, addrIPv4 := range addrsIPv4 {
		ipAddrs = append(ipAddrs, addrIPv4)
	}

	return ipAddrs, nil
}

/*
 * Performs DNS resolution and returns two separate lists of IPv4 and IPv6 addresses.
 */
func LookupHostSeparateIPVersion(domain string, timeout time.Duration) ([]string, []string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ipAddrs, err := net.DefaultResolver.LookupHost(ctx, domain)
	if err != nil {
		return nil, nil, err
	}

	addrsIPv4, addrsIPv6 := splitIPAddrListByIPVersion(ipAddrs)

	return addrsIPv4, addrsIPv6, nil
}

/*
 * Split IPv4 and IPv6 addresses from the passed list into two separate lists.
 */
func splitIPAddrListByIPVersion(ipAddrs []string) ([]string, []string) {
	var addrsIPv4, addrsIPv6 []string

	for _, ipAddr := range ipAddrs {
		if strings.Contains(ipAddr, ":") {
			addrsIPv6 = append(addrsIPv6, ipAddr)
		} else if strings.Contains(ipAddr, ".") {
			addrsIPv4 = append(addrsIPv4, ipAddr)
		}
	}

	return addrsIPv4, addrsIPv6
}
