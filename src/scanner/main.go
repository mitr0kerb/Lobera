// lobera-scan — port & service scanner para Lobera
// Autor: mitr0kerb
//
// Uso:
//   lobera-scan -t 10.10.10.5
//   lobera-scan -t 10.10.10.0/24
//   lobera-scan -t 10.10.10.1-10.10.10.50
//   lobera-scan -t 10.10.10.5 -p 445,80,443,389
//   lobera-scan -t 10.10.10.5 -p ad          (puertos AD: SMB,RPC,LDAP,Kerberos,WinRM)
//   lobera-scan -t 10.10.10.5 -p all         (puertos comunes: ~100)
//   lobera-scan -t 10.10.10.0/24 --timeout 500 --threads 500
//
// Output: JSON a stdout
//   {"hosts": [{"ip": "10.10.10.5", "open": [{"port": 445, "service": "smb", "banner": "..."}, ...], "closed": [80]}]}

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── Puertos predefinidos ──────────────────────────────────────────────────────

var portProfiles = map[string][]int{
	"ad": {
		21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143,
		389, 443, 445, 464, 593, 636, 873, 1433, 3268, 3269,
		3389, 5985, 5986, 8080, 8443, 9389,
	},
	"all": {
		21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 137, 139, 143, 161,
		389, 443, 445, 464, 465, 587, 593, 636, 873, 993, 995, 1080, 1433,
		1521, 2049, 2375, 2376, 3000, 3268, 3269, 3306, 3389, 4443, 4848,
		5432, 5900, 5985, 5986, 6379, 7001, 7443, 8000, 8080, 8443, 8888,
		9000, 9090, 9200, 9389, 27017,
	},
}

// Mapeo puerto → nombre de servicio
var portService = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	80: "http", 81: "http-alt", 88: "kerberos", 110: "pop3",
	111: "rpcbind", 135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn",
	143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
	464: "kpasswd", 465: "smtps", 587: "submission", 593: "http-rpc",
	636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s",
	1080: "socks", 1433: "mssql", 1521: "oracle", 2049: "nfs",
	2375: "docker", 2376: "docker-tls", 3000: "http-alt", 3268: "ldap-gc",
	3269: "ldaps-gc", 3306: "mysql", 3389: "rdp", 4443: "https-alt",
	4848: "glassfish", 5432: "postgresql", 5900: "vnc", 5985: "winrm",
	5986: "winrm-tls", 6379: "redis", 7001: "weblogic", 7443: "https-alt",
	8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
	8888: "http-alt", 9000: "http-alt", 9090: "http-alt",
	9200: "elasticsearch", 9389: "adws", 27017: "mongodb",
}

// ── Estructuras de output ─────────────────────────────────────────────────────

type PortResult struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Banner  string `json:"banner,omitempty"`
}

type HostResult struct {
	IP     string       `json:"ip"`
	Open   []PortResult `json:"open"`
	Closed []int        `json:"closed,omitempty"`
}

type ScanResult struct {
	Hosts    []HostResult `json:"hosts"`
	Duration string       `json:"duration"`
	Total    int          `json:"total_hosts"`
	Up       int          `json:"up_hosts"`
}

// ── Banner grabbing ───────────────────────────────────────────────────────────

func grabBanner(ip string, port int, timeout time.Duration) string {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout / 2))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n > 0 {
		banner := strings.TrimSpace(string(buf[:n]))
		// Limpiar caracteres no imprimibles
		banner = strings.Map(func(r rune) rune {
			if r >= 32 && r < 127 {
				return r
			}
			return -1
		}, banner)
		if len(banner) > 100 {
			banner = banner[:100] + "..."
		}
		return banner
	}
	return ""
}

// ── Escaneo de un puerto ──────────────────────────────────────────────────────

type scanJob struct {
	ip   string
	port int
}

type scanRes struct {
	ip     string
	port   int
	open   bool
	banner string
}

func scanPort(job scanJob, timeout time.Duration, grabBanners bool) scanRes {
	addr := fmt.Sprintf("%s:%d", job.ip, job.port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return scanRes{ip: job.ip, port: job.port, open: false}
	}
	defer conn.Close()

	banner := ""
	if grabBanners {
		conn.SetReadDeadline(time.Now().Add(timeout / 2))
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		if n > 0 {
			raw := strings.TrimSpace(string(buf[:n]))
			raw = strings.Map(func(r rune) rune {
				if r >= 32 && r < 127 {
					return r
				}
				return -1
			}, raw)
			if len(raw) > 100 {
				raw = raw[:100] + "..."
			}
			banner = raw
		}
	}
	return scanRes{ip: job.ip, port: job.port, open: true, banner: banner}
}

// ── Expansión de rangos de IPs ────────────────────────────────────────────────

func expandTargets(target string) ([]string, error) {
	// CIDR: 10.10.10.0/24
	if strings.Contains(target, "/") {
		_, ipnet, err := net.ParseCIDR(target)
		if err != nil {
			return nil, fmt.Errorf("CIDR inválido: %s", target)
		}
		var ips []string
		for ip := cloneIP(ipnet.IP); ipnet.Contains(ip); incIP(ip) {
			// Saltar dirección de red y broadcast
			s := ip.String()
			if s == ipnet.IP.String() {
				continue
			}
			ips = append(ips, s)
		}
		// Eliminar último (broadcast)
		if len(ips) > 0 {
			ips = ips[:len(ips)-1]
		}
		return ips, nil
	}

	// Rango: 10.10.10.1-10.10.10.50 o 10.10.10.1-50
	if strings.Contains(target, "-") {
		parts := strings.SplitN(target, "-", 2)
		startIP := net.ParseIP(parts[0])
		if startIP == nil {
			return nil, fmt.Errorf("IP de inicio inválida: %s", parts[0])
		}

		var endIP net.IP
		if strings.Contains(parts[1], ".") {
			endIP = net.ParseIP(parts[1])
			if endIP == nil {
				return nil, fmt.Errorf("IP de fin inválida: %s", parts[1])
			}
		} else {
			// Rango corto: 10.10.10.1-50
			endOctet, err := strconv.Atoi(parts[1])
			if err != nil || endOctet < 0 || endOctet > 255 {
				return nil, fmt.Errorf("octet final inválido: %s", parts[1])
			}
			endIP = cloneIP(startIP.To4())
			endIP[3] = byte(endOctet)
		}

		start := ipToUint32(startIP.To4())
		end := ipToUint32(endIP.To4())
		if start > end {
			return nil, fmt.Errorf("rango inválido: inicio > fin")
		}

		var ips []string
		for i := start; i <= end; i++ {
			ips = append(ips, uint32ToIP(i).String())
		}
		return ips, nil
	}

	// IP simple
	if net.ParseIP(target) != nil {
		return []string{target}, nil
	}

	// Hostname
	addrs, err := net.LookupHost(target)
	if err != nil {
		return nil, fmt.Errorf("no se pudo resolver '%s': %v", target, err)
	}
	return addrs[:1], nil
}

func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(n uint32) net.IP {
	return net.IP{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

// ── Parseo de puertos ─────────────────────────────────────────────────────────

func parsePorts(portStr string) ([]int, error) {
	portStr = strings.ToLower(strings.TrimSpace(portStr))

	if profile, ok := portProfiles[portStr]; ok {
		return profile, nil
	}

	var ports []int
	seen := map[int]bool{}

	for _, part := range strings.Split(portStr, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			start, err1 := strconv.Atoi(bounds[0])
			end, err2 := strconv.Atoi(bounds[1])
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("rango de puertos inválido: %s", part)
			}
			for p := start; p <= end; p++ {
				if !seen[p] {
					ports = append(ports, p)
					seen[p] = true
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("puerto inválido: %s", part)
			}
			if !seen[p] {
				ports = append(ports, p)
				seen[p] = true
			}
		}
	}
	return ports, nil
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	target    := flag.String("t",        "",    "IP, CIDR o rango (ej: 10.10.10.0/24, 10.10.10.1-50)")
	portStr   := flag.String("p",        "ad",  "Puertos: ad | all | 80,443,445 | 80-1000")
	threads   := flag.Int("threads",     200,   "Goroutines paralelas")
	timeoutMs := flag.Int("timeout",     500,   "Timeout por puerto (ms)")
	banners   := flag.Bool("banners",    false, "Intentar leer banner de puertos abiertos")
	showClosed:= flag.Bool("closed",     false, "Incluir puertos cerrados en el output")
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "Error: falta -t <objetivo>")
		flag.Usage()
		os.Exit(1)
	}

	timeout := time.Duration(*timeoutMs) * time.Millisecond
	start   := time.Now()

	// Expandir targets
	ips, err := expandTargets(*target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Parsear puertos
	ports, err := parsePorts(*portStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Cola de trabajos
	jobs := make(chan scanJob, *threads*2)
	results := make(chan scanRes, *threads*2)

	// Workers
	var wg sync.WaitGroup
	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				results <- scanPort(job, timeout, *banners)
			}
		}()
	}

	// Productor
	go func() {
		for _, ip := range ips {
			for _, port := range ports {
				jobs <- scanJob{ip: ip, port: port}
			}
		}
		close(jobs)
	}()

	// Cerrar results cuando terminen workers
	go func() {
		wg.Wait()
		close(results)
	}()

	// Agregar resultados por IP
	hostMap := map[string]*HostResult{}
	for _, ip := range ips {
		hostMap[ip] = &HostResult{IP: ip}
	}

	_ = context.Background() // import usado

	for res := range results {
		h := hostMap[res.ip]
		if res.open {
			svc := portService[res.port]
			if svc == "" {
				svc = "unknown"
			}
			h.Open = append(h.Open, PortResult{
				Port:    res.port,
				Service: svc,
				Banner:  res.banner,
			})
		} else if *showClosed {
			h.Closed = append(h.Closed, res.port)
		}
	}

	// Ordenar y construir resultado
	var hostResults []HostResult
	upHosts := 0
	for _, ip := range ips {
		h := hostMap[ip]
		if len(h.Open) > 0 {
			sort.Slice(h.Open, func(i, j int) bool {
				return h.Open[i].Port < h.Open[j].Port
			})
			sort.Ints(h.Closed)
			hostResults = append(hostResults, *h)
			upHosts++
		}
	}

	elapsed := time.Since(start)
	result := ScanResult{
		Hosts:    hostResults,
		Duration: fmt.Sprintf("%.2fs", elapsed.Seconds()),
		Total:    len(ips),
		Up:       upHosts,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(result)
}
