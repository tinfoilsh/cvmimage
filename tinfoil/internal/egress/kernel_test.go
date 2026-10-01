package egress

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"tinfoil/internal/containernet"
	"tinfoil/internal/firewall"
	"tinfoil/internal/runtimeconfig"
)

func TestIsolatedKernelDNS(t *testing.T) {
	if os.Getenv("TINFOIL_DNS_KERNEL_TEST") != "1" {
		t.Skip("requires an isolated root network and mount namespace")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	initial, err := os.Readlink("/proc/1/ns/net")
	if err != nil || current == initial {
		t.Fatal("refusing to alter the host network namespace")
	}
	current, err = os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	initial, err = os.Readlink("/proc/1/ns/mnt")
	if err != nil || current == initial {
		t.Fatal("refusing to alter the host mount namespace")
	}
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v: %s", args, err, out)
		}
	}
	run("ip", "link", "set", "lo", "up")
	run("ip", "address", "add", containernet.DNSAddress+"/32", "dev", "lo")
	run("sysctl", "-w", "net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0")
	// Keep named namespace mounts private to this test's mount namespace.
	run("mount", "--make-rprivate", "/")
	run("mount", "-t", "tmpfs", "tmpfs", "/run/netns")
	for i, name := range []string{"alpha", "beta"} {
		gateway := fmt.Sprintf("10.%d.0.1", 42+i)
		source := fmt.Sprintf("10.%d.0.2", 42+i)
		run("ip", "link", "add", name, "type", "bridge")
		run("ip", "addr", "add", gateway+"/24", "dev", name)
		run("ip", "link", "set", name, "up")
		run("ip", "netns", "add", name)
		run("ip", "link", "add", name+"-host", "type", "veth", "peer", "name", name+"-app")
		run("ip", "link", "set", name+"-host", "master", name)
		run("ip", "link", "set", name+"-host", "up")
		run("ip", "link", "set", name+"-app", "netns", name)
		run("ip", "-n", name, "addr", "add", source+"/24", "dev", name+"-app")
		run("ip", "-n", name, "link", "set", name+"-app", "up")
		run("ip", "-n", name, "link", "set", "lo", "up")
		run("ip", "-n", name, "route", "add", "default", "via", gateway)
	}
	run("nft", "-f", "../../../image/rootfs/etc/nftables.conf")
	config := &runtimeconfig.Config{Networks: map[string]*runtimeconfig.NetworkSpec{"alpha": {Egress: "allowlist", Allow: []string{"storage.example"}}, "beta": {Egress: "closed"}}}
	if err := firewall.ApplyContainerNetworks(config, false, 1); err != nil {
		t.Fatal(err)
	}

	run("ip", "netns", "add", "remote")
	run("ip", "link", "add", "uplink", "type", "veth", "peer", "name", "remote-peer")
	run("ip", "addr", "add", "8.8.8.1/24", "dev", "uplink")
	run("ip", "link", "set", "uplink", "up")
	run("ip", "link", "set", "remote-peer", "netns", "remote")
	run("ip", "-n", "remote", "addr", "add", "8.8.8.8/24", "dev", "remote-peer")
	run("ip", "-n", "remote", "addr", "add", "8.8.4.4/32", "dev", "remote-peer")
	run("ip", "-n", "remote", "link", "set", "remote-peer", "up")
	run("ip", "-n", "remote", "route", "add", "default", "via", "8.8.8.1")
	run("ip", "route", "add", "8.8.4.4/32", "via", "8.8.8.8")
	executable, _ := os.Executable()
	echo := exec.Command("ip", "netns", "exec", "remote", executable, "-test.run=^TestIsolatedEcho$")
	echo.Env = append(os.Environ(), "TINFOIL_ECHO=1")
	if err := echo.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { echo.Process.Kill(); echo.Wait() }()
	echoDeadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", "8.8.8.8:8080", 50*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(echoDeadline) {
			t.Fatal(err)
		}
	}
	e := New()
	e.policies = []policy{{"alpha", netip.MustParsePrefix("10.42.0.0/24"), config.Networks["alpha"]}, {"beta", netip.MustParsePrefix("10.43.0.0/24"), config.Networks["beta"]}}
	var queries atomic.Int32
	var retained atomic.Bool
	e.exchange = func(_ context.Context, q *dns.Msg) (*dns.Msg, error) {

		n := queries.Add(1)
		if n == 3 {
			output, err := e.listSet(context.Background(), "allow-alpha")
			if err != nil {
				return nil, err
			}
			retained.Store(strings.Contains(string(output), "8.8.8.8") && strings.Contains(string(output), "8.8.4.4"))
			if _, err := e.nft(context.Background(), "flush set inet tinfoil allow-alpha\n"); err != nil {
				return nil, err
			}
		}
		if n == 4 {
			if err := firewall.ApplyContainerNetworks(config, false, 3); err != nil {
				return nil, err
			}
		}

		ip := "8.8.8.8"
		if n > 1 {
			ip = "8.8.4.4"
		}
		rr, _ := dns.NewRR("storage.example. 60 IN A " + ip)
		a := new(dns.Msg).SetReply(q)
		a.Answer = []dns.RR{rr}
		return a, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- e.Run(ctx) }()
	// Synchronize on the actual listener, not a fixed startup delay.
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", containernet.DNSReadyAddress, 50*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
	}
	binary, _ := os.Executable()
	for _, name := range []string{"alpha", "beta"} {
		command := exec.Command("ip", "netns", "exec", name, binary, "-test.run=^TestIsolatedDNSClient$", "-test.v")
		command.Env = append(os.Environ(), "TINFOIL_DNS_CLIENT="+name)
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("client %s: %v: %s", name, err, out)
		} else {
			t.Logf("%s", out)
		}
	}
	if queries.Load() != 4 {
		t.Fatalf("closed query leaked upstream: %d", queries.Load())
	}
	output, err := e.listSet(ctx, "allow-alpha")
	if err != nil {
		t.Fatal(err)
	}
	if !retained.Load() {
		t.Fatalf("rotating addresses not retained: %s", output)
	}
	// A restarted engine must not shorten an earlier answer's lifetime.
	restarted := New()
	if err := restarted.install(ctx, "alpha", map[string]uint32{"8.8.8.8": 30}); err != nil {
		t.Fatal(err)
	}
	if err := New().install(ctx, "alpha", map[string]uint32{"8.8.8.8": 1}); err != nil {
		t.Fatal(err)
	}
	output, err = e.listSet(ctx, "allow-alpha")
	if err != nil {
		t.Fatal(err)
	}
	var state struct {
		NFTables []struct {
			Set struct {
				Elements []struct {
					Element struct {
						Value   string `json:"val"`
						Expires uint32 `json:"expires"`
					} `json:"elem"`
				} `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(output, &state); err != nil {
		t.Fatal(err)
	}
	preserved := false
	for _, entry := range state.NFTables {
		for _, element := range entry.Set.Elements {
			if element.Element.Value == "8.8.8.8" && element.Element.Expires >= 30 {
				preserved = true
			}
		}
	}
	if !preserved {
		t.Fatalf("restart shortened an outstanding DNS lease: %s", output)
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestIsolatedDNSClient(t *testing.T) {
	name := os.Getenv("TINFOIL_DNS_CLIENT")
	if name == "" {
		t.Skip("namespace child only")
	}
	var established net.Conn
	for _, network := range []string{"udp", "tcp"} {
		c := dns.Client{Net: network, Timeout: time.Second}
		a, _, err := c.Exchange(new(dns.Msg).SetQuestion("storage.example.", dns.TypeA), net.JoinHostPort(containernet.DNSAddress, "53"))
		if err != nil {
			t.Fatal(err)
		}
		expected := dns.RcodeSuccess
		if name == "beta" {
			expected = dns.RcodeNameError
		}
		if a.Rcode != expected {
			t.Fatalf("%s response=%v", network, a)
		}

		if name == "alpha" {
			endpoint := net.JoinHostPort(a.Answer[0].(*dns.A).A.String(), "8080")
			connection, err := net.DialTimeout("tcp", endpoint, time.Second)
			if err != nil {
				t.Fatalf("connection immediately after DNS: %v", err)
			}
			connection.SetDeadline(time.Now().Add(time.Second))
			connection.Write([]byte("ping"))
			got := make([]byte, 4)
			if _, err := io.ReadFull(connection, got); err != nil || string(got) != "ping" {
				t.Fatalf("forwarded connection: %q, %v", got, err)
			}
			if established == nil {
				established = connection
				defer connection.Close()
			} else {
				connection.Close()
			}
			t.Logf("immediate TCP connection to %s succeeded", endpoint)
		}
		t.Logf("%s %s DNS code=%d answers=%v", name, network, a.Rcode, a.Answer)
	}
	if name == "alpha" {
		client := dns.Client{Net: "tcp", Timeout: time.Second}
		query := new(dns.Msg).SetQuestion("storage.example.", dns.TypeA)
		if _, _, err := client.Exchange(query, containernet.DNSAddress+":53"); err != nil {
			t.Fatal(err)
		}
		established.SetDeadline(time.Now().Add(time.Second))
		established.Write([]byte("ping"))
		got := make([]byte, 4)
		if _, err := io.ReadFull(established, got); err != nil || string(got) != "ping" {
			t.Fatalf("DNS expiry interrupted an authorized connection: %q, %v", got, err)
		}
		if _, _, err := client.Exchange(query, containernet.DNSAddress+":53"); err != nil {
			t.Fatal(err)
		}
		established.SetDeadline(time.Now().Add(200 * time.Millisecond))
		established.Write([]byte("ping"))
		if _, err := io.ReadFull(established, got); err == nil {
			t.Fatal("old connection remained authorized after policy replacement")
		}
	}
	if name == "beta" {
		if out, err := exec.Command("ip", "address", "add", "10.42.0.99/32", "dev", "beta-app").CombinedOutput(); err != nil {
			t.Fatalf("spoof setup: %v: %s", err, out)
		}
		client := dns.Client{Net: "udp", Timeout: 200 * time.Millisecond, Dialer: &net.Dialer{LocalAddr: &net.UDPAddr{IP: net.ParseIP("10.42.0.99")}}}
		if _, _, err := client.Exchange(new(dns.Msg).SetQuestion("storage.example.", dns.TypeA), net.JoinHostPort(containernet.DNSAddress, "53")); err == nil {
			t.Fatal("DNS accepted a source address from a different bridge")
		}
	}
}

func TestIsolatedEcho(t *testing.T) {
	if os.Getenv("TINFOIL_ECHO") != "1" {
		t.Skip("namespace child only")
	}
	listener, err := net.Listen("tcp4", ":8080")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		go func() { defer connection.Close(); io.Copy(connection, connection) }()
	}
}
