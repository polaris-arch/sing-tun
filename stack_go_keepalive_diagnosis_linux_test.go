//go:build linux && !android

package tun

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
)

type keepaliveDiagnosticPacket struct {
	Microseconds int64  `json:"us"`
	Outbound     bool   `json:"outbound"`
	Sequence     uint32 `json:"seq"`
	ACK          uint32 `json:"ack"`
	Flags        uint8  `json:"flags"`
	Payload      int    `json:"payload"`
}

func keepaliveDiagnosticCounter(t *testing.T) uint64 {
	t.Helper()
	b, err := os.ReadFile("/proc/net/netstat")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(b), "\n")
	for i := 0; i+1 < len(lines); i++ {
		if !strings.HasPrefix(lines[i], "TcpExt:") {
			continue
		}
		names, values := strings.Fields(lines[i]), strings.Fields(lines[i+1])
		for j, name := range names {
			if name == "TCPACKSkippedSeq" {
				v, err := strconv.ParseUint(values[j], 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				return v
			}
		}
	}
	t.Fatal("TCPACKSkippedSeq counter missing")
	return 0
}

func TestKeepaliveDiagnosis(t *testing.T) {
	idleMS, err := strconv.Atoi(os.Getenv("KA_IDLE_MS"))
	if err != nil || idleMS < 100 {
		t.Fatal("KA_IDLE_MS must be at least 100")
	}
	rate, err := os.ReadFile("/proc/sys/net/ipv4/tcp_invalid_ratelimit")
	if err != nil {
		t.Fatal(err)
	}
	for _, ipv6 := range []bool{false, true} {
		for _, dialed := range []bool{true, false} {
			t.Run(fmt.Sprintf("ipv6=%v,dialed=%v", ipv6, dialed), func(t *testing.T) {
				fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500, memoryLink: true})
				start := time.Now()
				var mu sync.Mutex
				var packets []keepaliveDiagnosticPacket
				observe := func(packet []byte, outbound bool) {
					var transport []byte
					switch header.IPVersion(packet) {
					case 4:
						ip := header.IPv4(packet)
						if ip.Protocol() != uint8(header.TCPProtocolNumber) {
							return
						}
						transport = ip.Payload()
					case 6:
						ip := header.IPv6(packet)
						if ip.NextHeader() != uint8(header.TCPProtocolNumber) {
							return
						}
						transport = ip.Payload()
					default:
						return
					}
					tcp := header.TCP(transport)
					mu.Lock()
					packets = append(packets, keepaliveDiagnosticPacket{
						Microseconds: time.Since(start).Microseconds(), Outbound: outbound,
						Sequence: tcp.SequenceNumber(), ACK: tcp.AckNumber(), Flags: uint8(tcp.Flags()),
						Payload: len(transport) - int(tcp.DataOffset()),
					})
					mu.Unlock()
				}
				fixture.bridge.observe(func(p []byte) { observe(p, false) }, func(p []byte) { observe(p, true) })
				t.Cleanup(func() { fixture.bridge.observe(nil, nil) })
				conn, kernel, _ := openConnection(t, fixture, ipv6, dialed)
				before := keepaliveDiagnosticCounter(t)
				configuredUS := time.Since(start).Microseconds()
				err := conn.SetKeepAliveConfig(net.KeepAliveConfig{
					Enable: true, Idle: time.Duration(idleMS) * time.Millisecond,
					Interval: time.Duration(idleMS) * time.Millisecond, Count: 2,
				})
				if err != nil {
					t.Fatal(err)
				}
				window := 2100 * time.Millisecond
				if idleMS == 1000 {
					window = 2500 * time.Millisecond
				}
				time.Sleep(window)
				skipped := keepaliveDiagnosticCounter(t) - before
				mu.Lock()
				quiet := append([]keepaliveDiagnosticPacket(nil), packets...)
				mu.Unlock()
				// A new connection with no data has SND.NXT = local SYN sequence + 1.
				// A genuine keepalive therefore uses the captured local SYN sequence.
				var isn uint32
				found := false
				for _, p := range quiet {
					if p.Outbound && header.TCPFlags(p.Flags)&header.TCPFlagSyn != 0 {
						isn, found = p.Sequence, true
						break
					}
				}
				if !found {
					t.Fatal("local SYN missing from trace")
				}
				probes, responses, plainACKs := 0, 0, 0
				for _, p := range quiet {
					if p.Microseconds < configuredUS || p.Flags != uint8(header.TCPFlagAck) || p.Payload != 0 {
						continue
					}
					if p.Outbound {
						plainACKs++
						if p.Sequence == isn {
							probes++
						}
					} else if p.ACK == isn+1 {
						responses++
					}
				}
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				kernel.SetDeadline(time.Now().Add(2 * time.Second))
				_, writeErr := conn.Write([]byte{0x5a})
				var transferErr error
				if writeErr == nil {
					var b [1]byte
					_, transferErr = io.ReadFull(kernel, b[:])
					if transferErr == nil && b[0] != 0x5a {
						transferErr = fmt.Errorf("wrong payload: %x", b)
					}
				}
				result := map[string]any{
					"ipv6": ipv6, "dialed": dialed, "idle_ms": idleMS,
					"invalid_ratelimit_ms": strings.TrimSpace(string(rate)), "configured_us": configuredUS,
					"syn_seq": isn, "strict_probes": probes, "responses": responses,
					"legacy_plain_acks": plainACKs, "ack_skipped_seq_delta": skipped,
					"write_error": fmt.Sprint(writeErr), "transfer_error": fmt.Sprint(transferErr),
					"timed_out":        errors.Is(writeErr, syscall.ETIMEDOUT),
					"healthy_transfer": writeErr == nil && transferErr == nil,
					"packets":          quiet,
				}
				b, err := json.Marshal(result)
				if err != nil {
					t.Fatal(err)
				}
				t.Log("KA_DIAG_JSON=" + string(b))
			})
		}
	}
}
