package controller

import (
	"cmp"
	"net/netip"
	"strconv"
	"time"

	"susanoo/internal/behavior"
	"susanoo/internal/event"
)

// FlowRecord は GW が記録した 1 件の通信（G5）。
type FlowRecord struct {
	Open       bool // true なら TLS か HTTP の始まり、false なら接続の終わり
	Blocked    bool // GW が落とした接続の試み（脅威情報のアドレスへの転送など）
	Time       time.Time
	Proto      uint8
	Src, Dst   netip.AddrPort
	BytesOut   uint64
	BytesIn    uint64
	PacketsOut uint64
	PacketsIn  uint64
	Start, End time.Time
	SNI        string
	JA4        string
	TLSVersion string
	ALPN       string
	HTTPMethod string
	HTTPHost   string
}

var protoNames = map[uint8]string{1: "icmp", 6: "tcp", 17: "udp", 58: "ipv6-icmp"}

// RecordFlow は通信を OCSF の Network Activity として保存する。始まり（Open）には SNI か Host を、
// 終わり（Close）には通信量と時刻を含める。
func (c *Controller) RecordFlow(r FlowRecord) {
	sub, t, s := c.behaviorTarget(subject{ip: r.Src.Addr()})
	deviceID := t.device

	activity, sev := event.NetworkClose, event.SeverityInformational
	switch {
	case r.Blocked:
		activity, sev = event.NetworkRefuse, event.SeverityLow
	case r.Open:
		activity = event.NetworkOpen
	}
	e := event.New(event.ClassNetworkActivity, activity, sev, r.Time)
	e.SrcEndpoint = &event.Endpoint{IP: r.Src.Addr().String(), Port: int(r.Src.Port()), UID: deviceID}
	e.DstEndpoint = &event.Endpoint{IP: r.Dst.Addr().String(), Port: int(r.Dst.Port()), Hostname: cmp.Or(r.SNI, r.HTTPHost)}
	proto, ok := protoNames[r.Proto]
	if !ok {
		proto = strconv.Itoa(int(r.Proto))
	}
	e.Connection = &event.Connection{ProtocolName: proto, DirectionID: 2}
	e.Device = &event.Device{UID: deviceID, IP: r.Src.Addr().String()}
	if r.Blocked {
		e.Message = "GW が遮断しました"
	}
	if !r.Open && !r.Blocked {
		e.Traffic = &event.Traffic{BytesOut: int64(r.BytesOut), BytesIn: int64(r.BytesIn), PacketsOut: int64(r.PacketsOut), PacketsIn: int64(r.PacketsIn)}
		if !r.Start.IsZero() {
			e.StartTime = r.Start.UnixMilli()
		}
		if !r.End.IsZero() {
			e.EndTime = r.End.UnixMilli()
		}
	}
	if r.SNI != "" || r.TLSVersion != "" {
		e.TLS = &event.TLS{SNI: r.SNI, Version: r.TLSVersion}
	}
	if r.HTTPMethod != "" {
		e.HTTPRequest = &event.HTTPRequest{Method: r.HTTPMethod, URL: &event.URL{Hostname: r.HTTPHost}}
	}
	if r.JA4 != "" || r.ALPN != "" {
		e.Unmapped = map[string]any{"tls": map[string]any{"ja4": r.JA4, "alpn": r.ALPN}}
	}
	c.observe(e, s)
	c.intelFlow(r, t, s)
	if r.Blocked {
		return
	}
	f := behavior.Flow{Open: r.Open, Time: r.Time, Start: r.Start, End: r.End, Proto: r.Proto, Src: r.Src, Dst: r.Dst,
		BytesOut: r.BytesOut, BytesIn: r.BytesIn, Hostname: cmp.Or(r.SNI, r.HTTPHost)}
	c.reportBehavior(c.detector.Flow(sub, f, c.now()), t, s)
}
