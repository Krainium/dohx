package main

import (
        "bufio"
        "crypto/tls"
        "encoding/json"
        "fmt"
        "io"
        "net"
        "net/http"
        "os"
        "sort"
        "strings"
        "sync"
        "time"
)

// ── ANSI ───────────────────────────────────────────────────────────────────────

const (
        reset         = "\033[0m"
        bold          = "\033[1m"
        dim           = "\033[2m"
        red           = "\033[31m"
        green         = "\033[32m"
        yellow        = "\033[33m"
        cyan          = "\033[36m"
        white         = "\033[37m"
        brightRed     = "\033[91m"
        brightGreen   = "\033[92m"
        brightYellow  = "\033[93m"
        brightBlue    = "\033[94m"
        brightMagenta = "\033[95m"
        brightCyan    = "\033[96m"
        brightWhite   = "\033[97m"
        brightBlack   = "\033[90m"
        bgBlack       = "\033[40m"
        bgRed         = "\033[41m"
        bgGreen       = "\033[42m"
        bgYellow      = "\033[43m"
        bgBlue        = "\033[44m"
        bgMagenta     = "\033[45m"
        bgCyan        = "\033[46m"
        bgWhite       = "\033[47m"
)

func c(color, s string) string { return color + s + reset }

const divW = 66

func div() string   { return c(brightBlack, strings.Repeat("─", divW)) }
func thick() string { return c(brightBlack, strings.Repeat("━", divW)) }

func sectionBar(bg, label string) string {
        return fmt.Sprintf("\n  %s\n", c(bg+bold+white, fmt.Sprintf("  %s  ", label)))
}

func row(label, val, valColor string) {
        fmt.Printf("  %s  %s\n",
                c(brightBlack+bold, fmt.Sprintf("%-14s", label)),
                c(valColor, val))
}

// ── TLS probe ─────────────────────────────────────────────────────────────────

type TLSInfo struct {
        Issuer   string
        Subject  string
        Expires  time.Time
        DaysLeft int
        Proto    string
        SANs     []string
        Err      error
}

var tlsVersionName = map[uint16]string{
        tls.VersionTLS10: "TLS 1.0",
        tls.VersionTLS11: "TLS 1.1",
        tls.VersionTLS12: "TLS 1.2",
        tls.VersionTLS13: "TLS 1.3",
}

func checkTLS(domain string) TLSInfo {
        conn, err := tls.DialWithDialer(
                &net.Dialer{Timeout: 8 * time.Second},
                "tcp", domain+":443",
                &tls.Config{ServerName: domain},
        )
        if err != nil {
                return TLSInfo{Err: err}
        }
        defer conn.Close()
        state := conn.ConnectionState()
        cert := state.PeerCertificates[0]
        issuer := cert.Issuer.CommonName
        if len(cert.Issuer.Organization) > 0 {
                issuer = cert.Issuer.Organization[0]
                if cert.Issuer.CommonName != "" && cert.Issuer.CommonName != issuer {
                        issuer += " — " + cert.Issuer.CommonName
                }
        }
        proto := tlsVersionName[state.Version]
        if proto == "" {
                proto = fmt.Sprintf("0x%04x", state.Version)
        }
        return TLSInfo{
                Issuer:   issuer,
                Subject:  cert.Subject.CommonName,
                Expires:  cert.NotAfter,
                DaysLeft: int(time.Until(cert.NotAfter).Hours() / 24),
                Proto:    proto,
                SANs:     cert.DNSNames,
        }
}

func expiryColor(days int) string {
        switch {
        case days < 0:
                return brightRed + bold
        case days <= 14:
                return brightRed
        case days <= 30:
                return brightYellow
        default:
                return brightGreen
        }
}

func printTLS(info TLSInfo) {
        fmt.Print(sectionBar(bgBlue, "TLS CERTIFICATE"))
        fmt.Println()
        if info.Err != nil {
                fmt.Printf("  %s  %s\n", c(brightRed+bold, "✗"), c(red, info.Err.Error()))
                return
        }
        exLabel := fmt.Sprintf("%s  (%d days)", info.Expires.UTC().Format("2006-01-02 15:04 UTC"), info.DaysLeft)
        if info.DaysLeft < 0 {
                exLabel += "  !! EXPIRED !!"
        }
        row("Subject", info.Subject, brightWhite+bold)
        row("Issuer", info.Issuer, brightCyan)
        row("Expires", exLabel, expiryColor(info.DaysLeft))
        row("TLS Version", info.Proto, brightBlue)
        if len(info.SANs) > 0 && !(len(info.SANs) == 1 && info.SANs[0] == info.Subject) {
                shown, extra := info.SANs, 0
                if len(shown) > 5 {
                        shown, extra = info.SANs[:5], len(info.SANs)-5
                }
                s := strings.Join(shown, c(brightBlack, ", "))
                if extra > 0 {
                        s += c(brightBlack, fmt.Sprintf("  +%d more", extra))
                }
                row("SANs", s, dim+white)
        }
}

// ── HTTP probe + security grade ───────────────────────────────────────────────

type HTTPInfo struct {
        Proto       string
        H3          bool
        StatusCode  int
        Server      string
        PoweredBy   string
        HSTS        bool
        CSP         bool
        XFrame      bool
        XCT         bool // X-Content-Type-Options
        Referrer    bool
        Permissions bool
        Grade       string
        Elapsed     time.Duration
        Err         error
}

var httpProbeClient = &http.Client{
        Timeout: 10 * time.Second,
        CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
                return http.ErrUseLastResponse
        },
}

func checkHTTP(domain string) HTTPInfo {
        t0 := time.Now()
        req, _ := http.NewRequest("HEAD", "https://"+domain+"/", nil)
        req.Header.Set("User-Agent", "doh-tool/2.0")
        resp, err := httpProbeClient.Do(req)
        elapsed := time.Since(t0)
        if err != nil {
                return HTTPInfo{Err: err, Elapsed: elapsed}
        }
        defer resp.Body.Close()

        proto := resp.Proto
        if proto == "HTTP/2.0" {
                proto = "HTTP/2"
        }
        h3 := false
        for _, v := range resp.Header["Alt-Svc"] {
                for _, tok := range strings.Split(v, ",") {
                        if strings.HasPrefix(strings.TrimSpace(tok), "h3") {
                                h3 = true
                                break
                        }
                }
        }
        display := proto
        if h3 {
                display = proto + " + HTTP/3"
        }

        hsts := resp.Header.Get("Strict-Transport-Security") != ""
        csp := resp.Header.Get("Content-Security-Policy") != ""
        xframe := resp.Header.Get("X-Frame-Options") != ""
        xct := resp.Header.Get("X-Content-Type-Options") != ""
        ref := resp.Header.Get("Referrer-Policy") != ""
        perm := resp.Header.Get("Permissions-Policy") != ""

        score := 0
        for _, b := range []bool{hsts, csp, xframe, xct, ref, perm} {
                if b {
                        score++
                }
        }
        grades := []string{"F", "F", "D", "C", "B", "A", "A+"}
        grade := grades[score]

        return HTTPInfo{
                Proto: display, H3: h3, StatusCode: resp.StatusCode,
                Server:    resp.Header.Get("Server"),
                PoweredBy: resp.Header.Get("X-Powered-By"),
                HSTS: hsts, CSP: csp, XFrame: xframe, XCT: xct,
                Referrer: ref, Permissions: perm,
                Grade: grade, Elapsed: elapsed,
        }
}

func protoColor(proto string) string {
        if strings.Contains(proto, "HTTP/3") && strings.Contains(proto, "HTTP/2") {
                return brightMagenta
        }
        if strings.Contains(proto, "HTTP/2") {
                return brightCyan
        }
        return yellow
}

func gradeColor(g string) string {
        switch g {
        case "A+", "A":
                return bgGreen + bold + white
        case "B":
                return bgCyan + bold + white
        case "C":
                return bgYellow + bold + black
        case "D":
                return bgRed + bold + white
        default:
                return bgRed + bold + brightWhite
        }
}

func checkMark(b bool) string {
        if b {
                return c(brightGreen, "✓")
        }
        return c(brightBlack, "✗")
}

const black = "\033[30m"

func printHTTP(info HTTPInfo) {
        fmt.Print(sectionBar(bgMagenta, "HTTP PROTOCOL"))
        fmt.Println()
        if info.Err != nil {
                fmt.Printf("  %s  %s\n", c(brightRed+bold, "✗"), c(red, info.Err.Error()))
                return
        }
        row("Protocol", info.Proto, protoColor(info.Proto)+bold)
        sc := brightGreen
        if info.StatusCode >= 400 {
                sc = brightRed
        } else if info.StatusCode >= 300 {
                sc = brightYellow
        }
        row("Status", fmt.Sprintf("%d", info.StatusCode), sc)
        row("Latency", info.Elapsed.Round(time.Millisecond).String(), dim+white)
        if info.Server != "" {
                row("Server", info.Server, brightWhite)
        }
        if info.PoweredBy != "" {
                row("Powered-By", info.PoweredBy, brightWhite)
        }
        fmt.Println()
        fmt.Printf("  %s  %s\n", c(brightBlack+bold, "Security Grade"), c(gradeColor(info.Grade), " "+info.Grade+" "))
        fmt.Println()
        fmt.Printf("  %s HSTS  %s CSP  %s X-Frame  %s X-CTO  %s Referrer  %s Permissions\n",
                checkMark(info.HSTS), checkMark(info.CSP), checkMark(info.XFrame),
                checkMark(info.XCT), checkMark(info.Referrer), checkMark(info.Permissions))
}

// ── RDAP / WHOIS ──────────────────────────────────────────────────────────────

type RDAPInfo struct {
        Registrar   string
        CreatedAt   time.Time
        ExpiresAt   time.Time
        UpdatedAt   time.Time
        Status      []string
        Nameservers []string
        Err         error
}

type rdapResp struct {
        Status  []string `json:"status"`
        Events  []struct {
                Action string `json:"eventAction"`
                Date   string `json:"eventDate"`
        } `json:"events"`
        Entities []struct {
                Roles     []string      `json:"roles"`
                VcardArray []interface{} `json:"vcardArray"`
        } `json:"entities"`
        Nameservers []struct {
                LdhName string `json:"ldhName"`
        } `json:"nameservers"`
}

func extractVcardFN(vcardArray []interface{}) string {
        if len(vcardArray) < 2 {
                return ""
        }
        entries, ok := vcardArray[1].([]interface{})
        if !ok {
                return ""
        }
        for _, e := range entries {
                props, ok := e.([]interface{})
                if !ok || len(props) < 4 {
                        continue
                }
                if label, ok := props[0].(string); ok && label == "fn" {
                        if val, ok := props[3].(string); ok {
                                return val
                        }
                }
        }
        return ""
}

func checkRDAP(domain string) RDAPInfo {
        client := &http.Client{Timeout: 10 * time.Second}
        req, _ := http.NewRequest("GET", "https://rdap.org/domain/"+domain, nil)
        req.Header.Set("Accept", "application/rdap+json")
        req.Header.Set("User-Agent", "doh-tool/2.0")
        resp, err := client.Do(req)
        if err != nil {
                return RDAPInfo{Err: err}
        }
        defer resp.Body.Close()
        body, _ := io.ReadAll(resp.Body)
        if resp.StatusCode == 404 {
                return RDAPInfo{Err: fmt.Errorf("domain not found in RDAP")}
        }
        var r rdapResp
        if err := json.Unmarshal(body, &r); err != nil {
                return RDAPInfo{Err: fmt.Errorf("RDAP parse error: %w", err)}
        }
        info := RDAPInfo{Status: r.Status}
        for _, ev := range r.Events {
                t, _ := time.Parse(time.RFC3339, ev.Date)
                switch strings.ToLower(ev.Action) {
                case "registration":
                        info.CreatedAt = t
                case "expiration":
                        info.ExpiresAt = t
                case "last changed":
                        info.UpdatedAt = t
                }
        }
        for _, ent := range r.Entities {
                for _, role := range ent.Roles {
                        if role == "registrar" && info.Registrar == "" {
                                info.Registrar = extractVcardFN(ent.VcardArray)
                        }
                }
        }
        for _, ns := range r.Nameservers {
                info.Nameservers = append(info.Nameservers, strings.ToLower(ns.LdhName))
        }
        return info
}

func printRDAP(info RDAPInfo) {
        fmt.Print(sectionBar(bgCyan+black, "RDAP / WHOIS"))
        fmt.Println()
        if info.Err != nil {
                fmt.Printf("  %s  %s\n", c(brightRed+bold, "✗"), c(red, info.Err.Error()))
                return
        }
        if info.Registrar != "" {
                row("Registrar", info.Registrar, brightWhite+bold)
        }
        fmtDate := func(t time.Time) string {
                if t.IsZero() {
                        return c(dim, "—")
                }
                return t.UTC().Format("2006-01-02")
        }
        row("Created", fmtDate(info.CreatedAt), brightGreen)
        row("Expires", fmtDate(info.ExpiresAt), expiryColor(int(time.Until(info.ExpiresAt).Hours()/24)))
        if !info.UpdatedAt.IsZero() {
                row("Updated", fmtDate(info.UpdatedAt), dim+white)
        }
        if len(info.Status) > 0 {
                row("Status", strings.Join(info.Status, c(brightBlack, ", ")), brightYellow)
        }
        if len(info.Nameservers) > 0 {
                row("Nameservers", strings.Join(info.Nameservers, c(brightBlack, ", ")), dim+white)
        }
}

// ── Email Security ────────────────────────────────────────────────────────────

type EmailSecInfo struct {
        SPFRecord     string
        SPFPolicy     string
        DMARCRecord   string
        DMARCPolicy   string
        DMARCPct      string
        DMARCRua      string
        DKIMSelectors []string
        BIMI          bool
        BIMILogo      string
        BIMIVmc       bool
        Score         int
        Issues        []string
        Err           error
}

var dkimSelectors = []string{
        "default", "google", "selector1", "selector2",
        "mail", "dkim", "s1", "s2", "k1", "key1",
        "protonmail", "pm",
}

func checkEmailSec(domain, resolverURL string) EmailSecInfo {
        info := EmailSecInfo{}

        var mu sync.Mutex
        var wg sync.WaitGroup

        // SPF
        wg.Add(1)
        go func() {
                defer wg.Done()
                doh, _, err := dohQuery(resolverURL, domain, "TXT")
                if err != nil || doh.Status != 0 {
                        mu.Lock()
                        info.Issues = append(info.Issues, "SPF lookup failed")
                        mu.Unlock()
                        return
                }
                for _, rec := range doh.Answer {
                        if rec.Type == 16 && strings.Contains(rec.Data, "v=spf1") {
                                mu.Lock()
                                info.SPFRecord = strings.Trim(rec.Data, "\"")
                                for _, part := range strings.Fields(info.SPFRecord) {
                                        switch part {
                                        case "+all", "all":
                                                info.SPFPolicy = "+all — FAIL (accepts everything)"
                                        case "-all":
                                                info.SPFPolicy = "-all — PASS (hard reject)"
                                        case "~all":
                                                info.SPFPolicy = "~all — WARN (soft fail)"
                                        case "?all":
                                                info.SPFPolicy = "?all — NEUTRAL"
                                        }
                                }
                                if info.SPFPolicy == "" {
                                        info.SPFPolicy = "no catch-all directive"
                                }
                                mu.Unlock()
                                break
                        }
                }
        }()

        // DMARC
        wg.Add(1)
        go func() {
                defer wg.Done()
                doh, _, err := dohQuery(resolverURL, "_dmarc."+domain, "TXT")
                if err != nil || doh.Status != 0 {
                        return
                }
                for _, rec := range doh.Answer {
                        if rec.Type == 16 && strings.Contains(rec.Data, "v=DMARC1") {
                                mu.Lock()
                                info.DMARCRecord = strings.Trim(rec.Data, "\"")
                                for _, part := range strings.Split(info.DMARCRecord, ";") {
                                        kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
                                        if len(kv) != 2 {
                                                continue
                                        }
                                        switch strings.TrimSpace(kv[0]) {
                                        case "p":
                                                info.DMARCPolicy = strings.TrimSpace(kv[1])
                                        case "pct":
                                                info.DMARCPct = strings.TrimSpace(kv[1]) + "%"
                                        case "rua":
                                                info.DMARCRua = strings.TrimSpace(kv[1])
                                        }
                                }
                                mu.Unlock()
                                break
                        }
                }
        }()

        // DKIM selectors — all in parallel
        type dkimHit struct{ sel string }
        dkimCh := make(chan dkimHit, len(dkimSelectors))
        for _, sel := range dkimSelectors {
                wg.Add(1)
                go func(sel string) {
                        defer wg.Done()
                        doh, _, err := dohQuery(resolverURL, sel+"._domainkey."+domain, "TXT")
                        if err != nil || doh.Status != 0 || len(doh.Answer) == 0 {
                                return
                        }
                        for _, rec := range doh.Answer {
                                if rec.Type == 16 && (strings.Contains(rec.Data, "k=") || strings.Contains(rec.Data, "p=")) {
                                        dkimCh <- dkimHit{sel}
                                        return
                                }
                        }
                }(sel)
        }

        // BIMI
        wg.Add(1)
        go func() {
                defer wg.Done()
                doh, _, err := dohQuery(resolverURL, "default._bimi."+domain, "TXT")
                if err != nil || doh.Status != 0 {
                        return
                }
                for _, rec := range doh.Answer {
                        if rec.Type == 16 && strings.Contains(rec.Data, "v=BIMI1") {
                                mu.Lock()
                                info.BIMI = true
                                raw := strings.Trim(rec.Data, "\"")
                                for _, part := range strings.Split(raw, ";") {
                                        kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
                                        if len(kv) != 2 {
                                                continue
                                        }
                                        switch strings.TrimSpace(kv[0]) {
                                        case "l":
                                                info.BIMILogo = strings.TrimSpace(kv[1])
                                        case "a":
                                                info.BIMIVmc = strings.TrimSpace(kv[1]) != ""
                                        }
                                }
                                mu.Unlock()
                                return
                        }
                }
        }()

        wg.Wait()
        close(dkimCh)
        for hit := range dkimCh {
                info.DKIMSelectors = append(info.DKIMSelectors, hit.sel)
        }
        sort.Strings(info.DKIMSelectors)

        // Score 0–100
        score := 0
        if info.SPFRecord != "" {
                score += 20
                if strings.Contains(info.SPFPolicy, "-all") {
                        score += 10
                }
        } else {
                info.Issues = append(info.Issues, "No SPF record")
        }
        if info.DMARCRecord != "" {
                score += 20
                switch info.DMARCPolicy {
                case "reject":
                        score += 20
                case "quarantine":
                        score += 10
                default:
                        info.Issues = append(info.Issues, "DMARC policy is 'none' — monitor only")
                }
        } else {
                info.Issues = append(info.Issues, "No DMARC record")
        }
        if len(info.DKIMSelectors) > 0 {
                score += 20
        } else {
                info.Issues = append(info.Issues, "No DKIM selectors found (tried "+fmt.Sprintf("%d", len(dkimSelectors))+")")
        }
        if info.BIMI {
                score += 10
        }
        info.Score = score
        return info
}

func emailScoreColor(score int) string {
        switch {
        case score >= 80:
                return brightGreen + bold
        case score >= 50:
                return brightYellow + bold
        default:
                return brightRed + bold
        }
}

func printEmailSec(info EmailSecInfo) {
        fmt.Print(sectionBar(bgGreen+black, "EMAIL SECURITY"))
        fmt.Println()
        if info.Err != nil {
                fmt.Printf("  %s  %s\n", c(brightRed+bold, "✗"), c(red, info.Err.Error()))
                return
        }

        fmt.Printf("  %s  %s\n\n",
                c(brightBlack+bold, "Score"),
                c(emailScoreColor(info.Score), fmt.Sprintf("%d / 100", info.Score)))

        // SPF
        if info.SPFRecord != "" {
                row("SPF Policy", info.SPFPolicy, func() string {
                        if strings.Contains(info.SPFPolicy, "-all") {
                                return brightGreen
                        } else if strings.Contains(info.SPFPolicy, "~all") {
                                return brightYellow
                        }
                        return brightRed
                }())
        } else {
                row("SPF", "missing", brightRed+bold)
        }

        // DMARC
        if info.DMARCRecord != "" {
                dmarcCol := brightRed
                switch info.DMARCPolicy {
                case "reject":
                        dmarcCol = brightGreen
                case "quarantine":
                        dmarcCol = brightYellow
                }
                dval := info.DMARCPolicy
                if info.DMARCPct != "" {
                        dval += "  " + c(dim, "pct="+info.DMARCPct)
                }
                if info.DMARCRua != "" {
                        dval += "  " + c(dim, "rua="+info.DMARCRua)
                }
                row("DMARC Policy", dval, dmarcCol)
        } else {
                row("DMARC", "missing", brightRed+bold)
        }

        // DKIM
        if len(info.DKIMSelectors) > 0 {
                row("DKIM Selectors", strings.Join(info.DKIMSelectors, c(brightBlack, ", ")), brightGreen)
        } else {
                row("DKIM", "none found", brightRed)
        }

        // BIMI
        if info.BIMI {
                bval := "configured"
                if info.BIMIVmc {
                        bval += "  " + c(brightCyan, "+ VMC (verified mark)")
                }
                row("BIMI", bval, brightGreen)
        }

        if len(info.Issues) > 0 {
                fmt.Println()
                for _, iss := range info.Issues {
                        fmt.Printf("  %s  %s\n", c(brightYellow, "⚠"), c(yellow, iss))
                }
        }
}

// ── ASN / BGP via Cymru DoH ───────────────────────────────────────────────────

type ASNEntry struct {
        IP       string
        ASN      string
        Prefix   string
        Country  string
        Registry string
        Org      string
}

type ASNInfo struct {
        Entries []ASNEntry
        Err     error
}

func reverseIPv4(ip string) string {
        p := strings.Split(ip, ".")
        if len(p) != 4 {
                return ""
        }
        return p[3] + "." + p[2] + "." + p[1] + "." + p[0]
}

// reverseIPv6 expands and nibble-reverses an IPv6 address for Cymru lookup.
func reverseIPv6(ip string) string {
        parsed := net.ParseIP(ip)
        if parsed == nil {
                return ""
        }
        parsed = parsed.To16()
        var nibbles []string
        for _, b := range parsed {
                nibbles = append([]string{fmt.Sprintf("%x", b&0xf), fmt.Sprintf("%x", b>>4)}, nibbles...)
        }
        return strings.Join(nibbles, ".")
}

func checkASN(ips []string, resolverURL string) ASNInfo {
        if len(ips) == 0 {
                return ASNInfo{}
        }
        entries := make([]ASNEntry, len(ips))
        var wg sync.WaitGroup
        for i, ip := range ips {
                wg.Add(1)
                go func(idx int, ip string) {
                        defer wg.Done()
                        entry := ASNEntry{IP: ip}
                        var queryName string
                        if strings.Contains(ip, ":") {
                                rev := reverseIPv6(ip)
                                if rev == "" {
                                        entries[idx] = entry
                                        return
                                }
                                queryName = rev + ".origin6.asn.cymru.com"
                        } else {
                                rev := reverseIPv4(ip)
                                if rev == "" {
                                        entries[idx] = entry
                                        return
                                }
                                queryName = rev + ".origin.asn.cymru.com"
                        }

                        doh, _, err := dohQuery(resolverURL, queryName, "TXT")
                        if err != nil || doh.Status != 0 || len(doh.Answer) == 0 {
                                entries[idx] = entry
                                return
                        }
                        raw := strings.Trim(doh.Answer[0].Data, "\"")
                        parts := strings.Split(raw, "|")
                        if len(parts) >= 4 {
                                entry.ASN = strings.TrimSpace(parts[0])
                                entry.Prefix = strings.TrimSpace(parts[1])
                                entry.Country = strings.TrimSpace(parts[2])
                                entry.Registry = strings.TrimSpace(parts[3])
                        }

                        // Resolve org name: AS{asn}.asn.cymru.com
                        if entry.ASN != "" {
                                orgDoh, _, err := dohQuery(resolverURL, "AS"+entry.ASN+".asn.cymru.com", "TXT")
                                if err == nil && orgDoh.Status == 0 && len(orgDoh.Answer) > 0 {
                                        orgRaw := strings.Trim(orgDoh.Answer[0].Data, "\"")
                                        orgParts := strings.Split(orgRaw, "|")
                                        if len(orgParts) >= 5 {
                                                entry.Org = strings.TrimSpace(orgParts[4])
                                        }
                                }
                        }
                        entries[idx] = entry
                }(i, ip)
        }
        wg.Wait()

        // Deduplicate by prefix — group IPs under same subnet
        prefixMap := map[string]*ASNEntry{}
        var prefixOrder []string
        for _, e := range entries {
                key := e.Prefix
                if key == "" {
                        key = e.IP
                }
                if _, exists := prefixMap[key]; !exists {
                        clone := e
                        prefixMap[key] = &clone
                        prefixOrder = append(prefixOrder, key)
                }
        }
        var deduped []ASNEntry
        for _, k := range prefixOrder {
                deduped = append(deduped, *prefixMap[k])
        }
        return ASNInfo{Entries: deduped}
}

func printASN(info ASNInfo) {
        fmt.Print(sectionBar(bgYellow+black, "ASN / BGP  (via Cymru DoH)"))
        fmt.Println()
        if info.Err != nil {
                fmt.Printf("  %s  %s\n", c(brightRed+bold, "✗"), c(red, info.Err.Error()))
                return
        }
        if len(info.Entries) == 0 {
                fmt.Printf("  %s\n", c(dim, "no IP data"))
                return
        }
        for _, e := range info.Entries {
                asn := c(brightYellow+bold, "AS"+e.ASN)
                if e.ASN == "" {
                        asn = c(dim, "ASN unknown")
                }
                org := ""
                if e.Org != "" {
                        org = "  " + c(dim+white, e.Org)
                }
                fmt.Printf("  %s  %s  %s  %s  %s%s\n",
                        c(brightWhite, fmt.Sprintf("%-20s", e.IP)),
                        asn,
                        c(brightBlack, fmt.Sprintf("%-20s", e.Prefix)),
                        c(brightBlue, e.Country),
                        c(brightBlack, e.Registry),
                        org)
        }
}

// ── Port scanner ──────────────────────────────────────────────────────────────

type PortResult struct {
        Port    int
        Service string
        Open    bool
        Banner  string
}

var commonPorts = []struct {
        Port    int
        Service string
}{
        {21, "FTP"}, {22, "SSH"}, {25, "SMTP"}, {80, "HTTP"}, {443, "HTTPS"},
        {587, "SMTPSUB"}, {993, "IMAPS"}, {995, "POP3S"},
        {3306, "MySQL"}, {8080, "HTTP-ALT"}, {8443, "HTTPS-ALT"},
}

func scanPorts(host string) []PortResult {
        results := make([]PortResult, len(commonPorts))
        var wg sync.WaitGroup
        for i, p := range commonPorts {
                wg.Add(1)
                go func(idx, port int, svc string) {
                        defer wg.Done()
                        conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 3*time.Second)
                        if err != nil {
                                results[idx] = PortResult{Port: port, Service: svc, Open: false}
                                return
                        }
                        defer conn.Close()
                        banner := ""
                        conn.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
                        buf := make([]byte, 256)
                        n, _ := conn.Read(buf)
                        if n > 0 {
                                banner = strings.Map(func(r rune) rune {
                                        if r < 32 || r > 126 {
                                                return ' '
                                        }
                                        return r
                                }, strings.TrimSpace(string(buf[:n])))
                                if len(banner) > 55 {
                                        banner = banner[:55] + "…"
                                }
                        }
                        results[idx] = PortResult{Port: port, Service: svc, Open: true, Banner: banner}
                }(i, p.Port, p.Service)
        }
        wg.Wait()
        return results
}

func printPorts(results []PortResult) {
        fmt.Print(sectionBar(bgBlack+brightWhite, "PORT REACHABILITY"))
        fmt.Println()
        open, closed := 0, 0
        for _, r := range results {
                if r.Open {
                        open++
                } else {
                        closed++
                }
        }
        for _, r := range results {
                portStr := c(brightBlack, fmt.Sprintf("%5d", r.Port))
                svcStr := fmt.Sprintf("%-10s", r.Service)
                if r.Open {
                        banner := ""
                        if r.Banner != "" {
                                banner = "  " + c(dim+white, r.Banner)
                        }
                        fmt.Printf("  %s  %s  %s  %s%s\n",
                                portStr,
                                c(brightGreen, "OPEN  "),
                                c(brightWhite, svcStr),
                                c(brightBlack, "▸"),
                                banner)
                } else {
                        fmt.Printf("  %s  %s  %s\n",
                                portStr,
                                c(brightBlack, "closed"),
                                c(dim, svcStr))
                }
        }
        fmt.Println()
        fmt.Printf("  %s open  %s closed\n",
                c(brightGreen+bold, fmt.Sprintf("%d", open)),
                c(brightBlack, fmt.Sprintf("%d", closed)))
}

// ── DNS Propagation ───────────────────────────────────────────────────────────

type PropResult struct {
        Resolver string
        IPs      []string
        Status   int
        Err      error
}

var propagationResolvers = []struct{ Name, URL string }{
        {"Cloudflare", "https://cloudflare-dns.com/dns-query"},
        {"Google   ", "https://dns.google/resolve"},
        {"AdGuard  ", "https://dns.adguard-dns.com/resolve"},
        {"NextDNS  ", "https://dns.nextdns.io/dns-query"},
        {"Google(2)", "https://8.8.4.4/resolve"},
}

func checkPropagation(domain string) []PropResult {
        results := make([]PropResult, len(propagationResolvers))
        var wg sync.WaitGroup
        for i, r := range propagationResolvers {
                wg.Add(1)
                go func(idx int, name, url string) {
                        defer wg.Done()
                        doh, _, err := dohQuery(url, domain, "A")
                        if err != nil {
                                results[idx] = PropResult{Resolver: name, Err: err}
                                return
                        }
                        var ips []string
                        for _, rec := range doh.Answer {
                                if rec.Type == 1 {
                                        ips = append(ips, rec.Data)
                                }
                        }
                        sort.Strings(ips)
                        results[idx] = PropResult{Resolver: name, IPs: ips, Status: doh.Status}
                }(i, r.Name, r.URL)
        }
        wg.Wait()
        return results
}

func printPropagation(results []PropResult) {
        fmt.Print(sectionBar(bgBlue+brightWhite, "DNS PROPAGATION  (5 global resolvers)"))
        fmt.Println()

        // Build consensus: all non-error results should agree
        ipSets := map[string]int{}
        for _, r := range results {
                if r.Err == nil {
                        key := strings.Join(r.IPs, ",")
                        ipSets[key]++
                }
        }
        var dominant string
        maxCount := 0
        for k, v := range ipSets {
                if v > maxCount {
                        maxCount, dominant = v, k
                }
        }

        for _, r := range results {
                nameStr := c(brightWhite, fmt.Sprintf("%-12s", r.Resolver))
                if r.Err != nil {
                        fmt.Printf("  %s  %s\n", nameStr, c(red, "error: "+r.Err.Error()))
                        continue
                }
                ipsStr := strings.Join(r.IPs, c(brightBlack, ", "))
                if ipsStr == "" {
                        ipsStr = c(brightYellow, "NXDOMAIN")
                }
                key := strings.Join(r.IPs, ",")
                indicator := c(brightGreen, "✓")
                if key != dominant {
                        indicator = c(brightRed, "✗ MISMATCH")
                }
                fmt.Printf("  %s  %s  %s\n", nameStr, indicator, ipsStr)
        }

        if len(ipSets) > 1 {
                fmt.Printf("\n  %s  Resolvers disagree — possible partial propagation or hijack\n",
                        c(brightRed+bold, "⚠"))
        } else {
                fmt.Printf("\n  %s  All resolvers agree\n", c(brightGreen, "✓"))
        }
}

// ── DNS types + DoH query ─────────────────────────────────────────────────────

var typeNames = map[int]string{
        1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
        15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 257: "CAA",
}

var typeColor = map[string]string{
        "A": brightGreen, "AAAA": brightCyan, "MX": brightYellow,
        "TXT": brightMagenta, "CNAME": brightBlue, "NS": cyan,
        "SOA": dim + white, "PTR": green, "SRV": yellow, "CAA": brightRed,
}

var rcodeColor = map[int]string{
        0: brightGreen, 1: brightRed, 2: brightRed,
        3: brightYellow, 4: brightYellow, 5: brightRed,
}
var rcodeName = map[int]string{
        0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL",
        3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
}

func typStr(t int) string {
        if n, ok := typeNames[t]; ok {
                return n
        }
        return fmt.Sprintf("TYPE%d", t)
}

func typColored(t int) string {
        n := typStr(t)
        if col, ok := typeColor[n]; ok {
                return c(col+bold, n)
        }
        return c(bold, n)
}

type DoHResponse struct {
        Status    int        `json:"Status"`
        TC        bool       `json:"TC"`
        RD        bool       `json:"RD"`
        RA        bool       `json:"RA"`
        AD        bool       `json:"AD"`
        CD        bool       `json:"CD"`
        Question  []Question `json:"Question"`
        Answer    []Record   `json:"Answer"`
        Authority []Record   `json:"Authority"`
        Comment   string     `json:"Comment"`
}
type Question struct {
        Name string `json:"name"`
        Type int    `json:"type"`
}
type Record struct {
        Name string `json:"name"`
        Type int    `json:"type"`
        TTL  int    `json:"TTL"`
        Data string `json:"data"`
}

type Resolver struct{ Name, URL string }

var resolvers = []Resolver{
        {"Cloudflare 1.1.1.1", "https://cloudflare-dns.com/dns-query"},
        {"Google 8.8.8.8", "https://dns.google/resolve"},
        {"Quad9 9.9.9.9", "https://dns.quad9.net/dns-query"},
        {"AdGuard 94.140.14.14", "https://dns.adguard-dns.com/resolve"},
        {"OpenDNS 208.67.222.222", "https://doh.opendns.com/dns-query"},
        {"Custom", ""},
}

var recordTypes = []string{
        "A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA", "PTR", "SRV", "CAA",
}

var allQueryTypes = []string{"A", "AAAA", "MX", "TXT", "CNAME", "NS", "CAA"}

var httpClient = &http.Client{Timeout: 12 * time.Second}

func dohQuery(resolverURL, domain, qtype string) (*DoHResponse, time.Duration, error) {
        req, err := http.NewRequest("GET", resolverURL, nil)
        if err != nil {
                return nil, 0, err
        }
        q := req.URL.Query()
        q.Set("name", domain)
        q.Set("type", qtype)
        req.URL.RawQuery = q.Encode()
        req.Header.Set("Accept", "application/dns-json")
        t0 := time.Now()
        resp, err := httpClient.Do(req)
        elapsed := time.Since(t0)
        if err != nil {
                return nil, elapsed, err
        }
        defer resp.Body.Close()
        body, err := io.ReadAll(resp.Body)
        if err != nil {
                return nil, elapsed, err
        }
        if resp.StatusCode != http.StatusOK {
                return nil, elapsed, fmt.Errorf("HTTP %d", resp.StatusCode)
        }
        var doh DoHResponse
        return &doh, elapsed, json.Unmarshal(body, &doh)
}

// ── DNS output ────────────────────────────────────────────────────────────────

func printRecords(title string, records []Record) {
        if len(records) == 0 {
                return
        }
        bg := bgMagenta
        if title == "ANSWER" {
                bg = bgCyan
        }
        fmt.Printf("\n  %s\n\n", c(bg+bold+white, fmt.Sprintf("  %s  %d record(s)  ", title, len(records))))
        for _, r := range records {
                dataColor := brightWhite
                if r.Type == 16 {
                        dataColor = brightMagenta
                }
                if r.Type == 15 {
                        dataColor = brightYellow
                }
                fmt.Printf("  %s  %s  %s  %s\n",
                        c(brightBlack, fmt.Sprintf("%-36s", r.Name)),
                        c(dim+yellow, fmt.Sprintf("%5ds", r.TTL)),
                        fmt.Sprintf("%-12s", typColored(r.Type)),
                        c(dataColor, r.Data))
        }
}

func printDNSStatus(doh *DoHResponse, elapsed time.Duration) {
        sc := rcodeColor[doh.Status]
        if sc == "" {
                sc = yellow
        }
        sn := rcodeName[doh.Status]
        if sn == "" {
                sn = fmt.Sprintf("RCODE%d", doh.Status)
        }
        var flags []string
        for _, pair := range []struct {
                b    bool
                name string
                col  string
        }{
                {doh.RD, "RD", brightBlue}, {doh.RA, "RA", brightBlue},
                {doh.AD, "AD", brightGreen}, {doh.CD, "CD", brightYellow},
                {doh.TC, "TC", brightRed},
        } {
                if pair.b {
                        flags = append(flags, c(pair.col, pair.name))
                }
        }
        fmt.Printf("  %s  %s  %s\n",
                c(sc+bold, fmt.Sprintf("%-10s", sn)),
                c(brightBlack, strings.Join(flags, " ")),
                c(dim, elapsed.Round(time.Millisecond).String()))
}

// ── Single query output ───────────────────────────────────────────────────────

func printSingle(doh *DoHResponse, tlsInfo TLSInfo, httpInfo HTTPInfo,
        domain, qtype, resolverName string, elapsed time.Duration) {

        tc := typeColor[qtype]
        if tc == "" {
                tc = white
        }
        fmt.Println()
        fmt.Println(thick())
        fmt.Printf("  %s  %s  %s  %s\n",
                c(bgBlue+bold+brightWhite, " DOH "),
                c(bold+brightWhite, domain),
                c(tc+bold, qtype),
                c(brightBlack, "via "+resolverName))
        fmt.Println(div())
        printDNSStatus(doh, elapsed)
        printRecords("ANSWER", doh.Answer)
        printRecords("AUTHORITY", doh.Authority)
        if len(doh.Answer) == 0 && len(doh.Authority) == 0 {
                fmt.Printf("\n  %s\n", c(brightYellow, "∅  No records"))
        }
        if doh.Comment != "" {
                fmt.Printf("\n  %s\n", c(dim, "note: "+doh.Comment))
        }
        printHTTP(httpInfo)
        printTLS(tlsInfo)
        fmt.Println()
        fmt.Println(thick())
        fmt.Println()
}

// ── ALL mode (DNS types + TLS + HTTP) ─────────────────────────────────────────

type queryResult struct {
        qtype   string
        doh     *DoHResponse
        elapsed time.Duration
        err     error
}

func runAll(domain, resolverURL, resolverName string) {
        dnsResults := make([]queryResult, len(allQueryTypes))
        var tlsResult TLSInfo
        var httpResult HTTPInfo
        var wg sync.WaitGroup

        for i, qt := range allQueryTypes {
                wg.Add(1)
                go func(idx int, qt string) {
                        defer wg.Done()
                        doh, el, err := dohQuery(resolverURL, domain, qt)
                        dnsResults[idx] = queryResult{qt, doh, el, err}
                }(i, qt)
        }
        wg.Add(2)
        go func() { defer wg.Done(); tlsResult = checkTLS(domain) }()
        go func() { defer wg.Done(); httpResult = checkHTTP(domain) }()

        fmt.Printf("\n  %s  ALL records + TLS + HTTP for %s …\n\n",
                c(brightCyan, "⟳"), c(bold+brightWhite, domain))
        wg.Wait()

        fmt.Println(thick())
        fmt.Printf("  %s  %s  %s\n",
                c(bgBlue+bold+brightWhite, " DOH ALL "),
                c(bold+brightWhite, domain),
                c(brightBlack, "via "+resolverName))
        fmt.Println(div())
        fmt.Println()

        var totalAnswers int
        for _, r := range dnsResults {
                tc := typeColor[r.qtype]
                if tc == "" {
                        tc = white
                }
                label := c(tc+bold, fmt.Sprintf("%-6s", r.qtype))
                if r.err != nil {
                        fmt.Printf("  %s  %s\n", label, c(brightRed, r.err.Error()))
                        continue
                }
                sc := rcodeColor[r.doh.Status]
                if sc == "" {
                        sc = yellow
                }
                sn, ok := rcodeName[r.doh.Status]
                if !ok {
                        sn = fmt.Sprintf("RCODE%d", r.doh.Status)
                }
                count := len(r.doh.Answer)
                totalAnswers += count
                cntStr := c(brightBlack, fmt.Sprintf("(%d)", count))
                if count > 0 {
                        cntStr = c(brightGreen, fmt.Sprintf("(%d)", count))
                }
                fmt.Printf("  %s  %s  %s  %s\n",
                        label, c(sc, fmt.Sprintf("%-10s", sn)), cntStr,
                        c(dim, r.elapsed.Round(time.Millisecond).String()))
                for _, rec := range r.doh.Answer {
                        dc := brightWhite
                        if rec.Type == 16 {
                                dc = brightMagenta
                        }
                        if rec.Type == 15 {
                                dc = brightYellow
                        }
                        fmt.Printf("    %s  %s  %s\n",
                                c(brightBlack, fmt.Sprintf("%-5ds", rec.TTL)),
                                fmt.Sprintf("%-12s", typColored(rec.Type)),
                                c(dc, rec.Data))
                }
        }
        fmt.Println()
        fmt.Println(div())
        printHTTP(httpResult)
        printTLS(tlsResult)
        fmt.Println()
        fmt.Println(thick())
        fmt.Printf("  %s records across %s types\n\n",
                c(brightGreen+bold, fmt.Sprintf("%d", totalAnswers)),
                c(bold, fmt.Sprintf("%d", len(allQueryTypes))))
}

// ── FULL SCAN mode ────────────────────────────────────────────────────────────

func runFullScan(domain, resolverURL, resolverName string) {
        // Stage 1: fire all probes in parallel (DNS queries + side-channel probes)
        dnsResults := make([]queryResult, len(allQueryTypes))
        var tlsResult TLSInfo
        var httpResult HTTPInfo
        var rdapResult RDAPInfo
        var emailResult EmailSecInfo
        var portResults []PortResult
        var propResults []PropResult

        var wg sync.WaitGroup

        for i, qt := range allQueryTypes {
                wg.Add(1)
                go func(idx int, qt string) {
                        defer wg.Done()
                        doh, el, err := dohQuery(resolverURL, domain, qt)
                        dnsResults[idx] = queryResult{qt, doh, el, err}
                }(i, qt)
        }
        wg.Add(6)
        go func() { defer wg.Done(); tlsResult = checkTLS(domain) }()
        go func() { defer wg.Done(); httpResult = checkHTTP(domain) }()
        go func() { defer wg.Done(); rdapResult = checkRDAP(domain) }()
        go func() { defer wg.Done(); emailResult = checkEmailSec(domain, resolverURL) }()
        go func() { defer wg.Done(); portResults = scanPorts(domain) }()
        go func() { defer wg.Done(); propResults = checkPropagation(domain) }()

        fmt.Printf("\n  %s  FULL SCAN firing %s probes for %s …\n\n",
                c(brightMagenta, "⟳"),
                c(bold+brightWhite, "12"),
                c(bold+brightWhite, domain))

        wg.Wait()

        // Collect IPs from A + AAAA results for ASN lookup (run after DNS resolves)
        var ips []string
        for _, r := range dnsResults {
                if r.err != nil || r.doh == nil {
                        continue
                }
                for _, rec := range r.doh.Answer {
                        if rec.Type == 1 || rec.Type == 28 {
                                ips = append(ips, rec.Data)
                        }
                }
        }
        asnResult := checkASN(ips, resolverURL)

        // ── Output ─────────────────────────────────────────────────────────────
        fmt.Println(thick())
        fmt.Printf("  %s  %s  %s\n",
                c(bgMagenta+bold+brightWhite, " FULL SCAN "),
                c(bold+brightWhite, domain),
                c(brightBlack, "via "+resolverName))
        fmt.Println(div())
        fmt.Println()

        // DNS records
        var totalAnswers int
        for _, r := range dnsResults {
                tc := typeColor[r.qtype]
                if tc == "" {
                        tc = white
                }
                label := c(tc+bold, fmt.Sprintf("%-6s", r.qtype))
                if r.err != nil {
                        fmt.Printf("  %s  %s\n", label, c(brightRed, r.err.Error()))
                        continue
                }
                sc := rcodeColor[r.doh.Status]
                if sc == "" {
                        sc = yellow
                }
                sn, ok := rcodeName[r.doh.Status]
                if !ok {
                        sn = fmt.Sprintf("RCODE%d", r.doh.Status)
                }
                count := len(r.doh.Answer)
                totalAnswers += count
                cntStr := c(brightBlack, fmt.Sprintf("(%d)", count))
                if count > 0 {
                        cntStr = c(brightGreen, fmt.Sprintf("(%d)", count))
                }
                fmt.Printf("  %s  %s  %s  %s\n",
                        label, c(sc, fmt.Sprintf("%-10s", sn)), cntStr,
                        c(dim, r.elapsed.Round(time.Millisecond).String()))
                for _, rec := range r.doh.Answer {
                        dc := brightWhite
                        if rec.Type == 16 {
                                dc = brightMagenta
                        }
                        if rec.Type == 15 {
                                dc = brightYellow
                        }
                        fmt.Printf("    %s  %s  %s\n",
                                c(brightBlack, fmt.Sprintf("%-5ds", rec.TTL)),
                                fmt.Sprintf("%-12s", typColored(rec.Type)),
                                c(dc, rec.Data))
                }
        }
        fmt.Println()
        fmt.Printf("  %s DNS records across %s types\n",
                c(brightGreen+bold, fmt.Sprintf("%d", totalAnswers)),
                c(bold, fmt.Sprintf("%d", len(allQueryTypes))))

        fmt.Println()
        fmt.Println(div())
        printHTTP(httpResult)
        fmt.Println()
        fmt.Println(div())
        printTLS(tlsResult)
        fmt.Println()
        fmt.Println(div())
        printRDAP(rdapResult)
        fmt.Println()
        fmt.Println(div())
        printEmailSec(emailResult)
        fmt.Println()
        fmt.Println(div())
        printASN(asnResult)
        fmt.Println()
        fmt.Println(div())
        printPorts(portResults)
        fmt.Println()
        fmt.Println(div())
        printPropagation(propResults)

        fmt.Println()
        fmt.Println(thick())
        fmt.Printf("  %s complete\n\n", c(brightMagenta+bold, "FULL SCAN"))
}

// ── Input ─────────────────────────────────────────────────────────────────────

var stdin = bufio.NewReader(os.Stdin)

func prompt(label string) string {
        fmt.Printf("  %s%s%s ", c(brightBlack, "["), c(brightCyan+bold, label), c(brightBlack, "]"))
        line, _ := stdin.ReadString('\n')
        return strings.TrimSpace(line)
}

func pickNumber(max int) int {
        for {
                raw := prompt("›")
                var n int
                if _, err := fmt.Sscanf(raw, "%d", &n); err == nil && n >= 1 && n <= max {
                        return n
                }
                fmt.Printf("  %s  1–%d\n", c(red, "✗"), max)
        }
}

func selectDomain() string {
        for {
                v := prompt("domain")
                if v != "" {
                        return v
                }
                fmt.Printf("  %s  enter a domain\n", c(red, "✗"))
        }
}

func selectType() string {
        fmt.Println()
        fmt.Println(c(bold+brightWhite, "  Record type"))
        fmt.Println()
        for i, t := range recordTypes {
                tc := typeColor[t]
                if tc == "" {
                        tc = white
                }
                fmt.Printf("    %s  %s\n",
                        c(brightBlack, fmt.Sprintf("%2d.", i+1)),
                        c(tc+bold, t))
        }
        n := len(recordTypes)
        fmt.Printf("    %s  %s\n",
                c(brightBlack, fmt.Sprintf("%2d.", n+1)),
                c(bold+brightWhite, "ALL")+" "+c(dim, "(7 DNS types + TLS + HTTP, parallel)"))
        fmt.Printf("    %s  %s\n",
                c(brightBlack, fmt.Sprintf("%2d.", n+2)),
                c(brightMagenta+bold, "FULL SCAN")+" "+c(dim, "(DNS + TLS + HTTP + RDAP + Email + ASN + Ports + Propagation)"))
        fmt.Printf("    %s  %s\n",
                c(brightBlack, fmt.Sprintf("%2d.", n+3)),
                c(dim, "custom type"))
        fmt.Println()
        choice := pickNumber(n + 3)
        switch {
        case choice <= n:
                return recordTypes[choice-1]
        case choice == n+1:
                return "ALL"
        case choice == n+2:
                return "FULLSCAN"
        default:
                for {
                        v := strings.ToUpper(prompt("type"))
                        if v != "" {
                                return v
                        }
                }
        }
}

func selectResolver() (string, string) {
        fmt.Println()
        fmt.Println(c(bold+brightWhite, "  Resolver"))
        fmt.Println()
        for i, r := range resolvers {
                fmt.Printf("    %s  %s\n",
                        c(brightBlack, fmt.Sprintf("%2d.", i+1)),
                        c(brightWhite, r.Name))
        }
        fmt.Println()
        choice := pickNumber(len(resolvers))
        picked := resolvers[choice-1]
        if picked.URL == "" {
                url := prompt("url")
                return "custom", url
        }
        return picked.Name, picked.URL
}

// ── Banner + main ─────────────────────────────────────────────────────────────

func banner() {
        fmt.Println(c(brightCyan+bold, `
  ·▄▄▄▄  ▄ .▄
  ██▪ ██ ██▪▐█
  ▐█· ▐█▌██▀▐█
  ██. ██ ██▌▐▀
  ▀▀▀▀▀• ▀▀▀ ·  `) + c(reset+brightBlack, "DNS over HTTPS  ·  domain intelligence tool") +
                c(brightBlack, "  ·  ") + c(dim+brightMagenta, "krainium"))
        fmt.Println()
}

func run() {
        domain := selectDomain()
        qtype := selectType()
        resolverName, resolverURL := selectResolver()

        switch qtype {
        case "ALL":
                runAll(domain, resolverURL, resolverName)
        case "FULLSCAN":
                runFullScan(domain, resolverURL, resolverName)
        default:
                tc := typeColor[qtype]
                if tc == "" {
                        tc = white
                }
                fmt.Printf("\n  %s  %s %s + TLS + HTTP …\n",
                        c(brightCyan, "⟳"), c(bold+brightWhite, domain), c(tc+bold, qtype))

                var doh *DoHResponse
                var tlsInfo TLSInfo
                var httpInfo HTTPInfo
                var elapsed time.Duration
                var dnsErr error
                var wg sync.WaitGroup
                wg.Add(3)
                go func() { defer wg.Done(); doh, elapsed, dnsErr = dohQuery(resolverURL, domain, qtype) }()
                go func() { defer wg.Done(); tlsInfo = checkTLS(domain) }()
                go func() { defer wg.Done(); httpInfo = checkHTTP(domain) }()
                wg.Wait()

                if dnsErr != nil {
                        fmt.Printf("  %s  %s\n\n", c(brightRed+bold, "error"), c(red, dnsErr.Error()))
                        return
                }
                printSingle(doh, tlsInfo, httpInfo, domain, qtype, resolverName, elapsed)
        }
}

func main() {
        banner()
        for {
                run()
                fmt.Println(c(brightBlack, "  ─────────────────────────────────"))
                again := strings.ToLower(prompt("query again? [y/n]"))
                if again != "y" && again != "yes" {
                        fmt.Println(c(brightBlack, "\n  done.\n"))
                        return
                }
                fmt.Println()
        }
}
