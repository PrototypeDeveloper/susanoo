package egress

import (
	"net/netip"

	"susanoo/internal/policy"
)

// DoHServers は既知の公開 DNS サーバー。DoH と DoT を遮断するグループでは、ここへの 443 と 853 の通信を遮断する。
var DoHServers = prefixes(
	"8.8.8.8/32", "8.8.4.4/32", "2001:4860:4860::8888/128", "2001:4860:4860::8844/128", // Google
	"1.1.1.1/32", "1.0.0.1/32", "2606:4700:4700::1111/128", "2606:4700:4700::1001/128", // Cloudflare
	"9.9.9.9/32", "149.112.112.112/32", "2620:fe::fe/128", "2620:fe::9/128", // Quad9
	"208.67.222.222/32", "208.67.220.220/32", "2620:119:35::35/128", "2620:119:53::53/128", // OpenDNS
	"94.140.14.14/32", "94.140.15.15/32", "2a10:50c0::ad1:ff/128", "2a10:50c0::ad2:ff/128", // AdGuard
	"185.228.168.168/32", "185.228.169.168/32", // CleanBrowsing
)

// dohNames は、DoH を遮断するグループで名前を引かせない（存在しない名前として返す）DoH の接続先。
// use-application-dns.net は、引けなければ Firefox が DoH を自動では使わない合図の名前。
var dohNames = domains(
	"use-application-dns.net",
	"dns.google", "dns.google.com", "dns64.dns.google",
	"cloudflare-dns.com", "*.cloudflare-dns.com", "one.one.one.one",
	"dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net",
	"doh.opendns.com", "dns.opendns.com",
	"dns.adguard-dns.com", "*.adguard-dns.com", "dns.adguard.com",
	"dns.nextdns.io", "*.dns.nextdns.io",
	"doh.cleanbrowsing.org",
)

// relayNames は、VPN を遮断するグループで名前を引かせない iCloud プライベートリレーの接続先。
// 引けなければ、プライベートリレーはこのネットワークでは使われない。
var relayNames = domains("mask.icloud.com", "mask-h2.icloud.com", "mask-api.icloud.com")

func prefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, p := range s {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}

func domains(s ...string) []policy.Destination {
	out := make([]policy.Destination, len(s))
	for i, d := range s {
		out[i] = policy.Destination{Domain: d}
	}
	return out
}

func matchAny(list []policy.Destination, name string) bool {
	for _, d := range list {
		if d.MatchDomain(name) {
			return true
		}
	}
	return false
}
