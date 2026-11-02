// router_go — risk-calib hybrid test: vjerna Go kopija risk-calib/router.py
//
// Ulaz (stdin): JSON array stringova (zadaci) ILI jedan string po liniji.
// Izlaz (stdout): JSON array rezultata route() — identično Python routeru.
//
// Režimi:
//   go run . -in fixtures/inputs.json          # JSON array ulaza
//   go run . -bench -n 10000 < fixtures/inputs.json   # bench (isti izlaz na kraju)
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// Konstante / pragovi (identično Pythonu)
// ---------------------------------------------------------------------------

const (
	PrahSingle      = 0.62
	PrahGroup       = 0.38
	RiskHardBlock   = 0.85
)

// DOMAIN_AGENTS — identično Pythonu.
var domainAgents = map[string][]string{
	"prodaja":       {"agent_prodaja", "agent_ponuda"},
	"nabavka":       {"agent_nabavka", "agent_dobavljac"},
	"finansije":     {"agent_finansije", "agent_fakture", "agent_knjizenje"},
	"racunovodstvo": {"agent_knjizenje", "agent_pdv", "agent_bilans"},
	"logistika":     {"agent_logistika", "agent_zalihe"},
	"magacin":       {"agent_zalihe", "agent_magacin"},
	"kadrovi":       {"agent_kadrovi", "agent_plate"},
	"it":            {"agent_it", "agent_ops"},
	"kod":           {"agent_kod", "agent_review"},
	"pravo":         {"agent_pravo", "agent_ugovori"},
	"marketing":     {"agent_marketing", "agent_seo"},
	"analitika":     {"agent_analitika", "agent_report"},
	"podrska":       {"agent_podrska", "agent_ticket"},
	"opste":         {"agent_general"},
}

// DOMAIN_KEYWORDS — identično Pythonu (redoslijed bitan zbog težina).
var domainKeywords = map[string][]string{
	"prodaja":       {"kupac", "prodaja", "ponuda", "narudzba", "cjenovnik", "popust", "klijent", "lead", "deal", "cijena"},
	"nabavka":       {"nabavka", "dobavljac", "ulazna", "porudzbina", "supplier", "naruciti", "kolicina", "veleprodaja"},
	"finansije":     {"faktura", "racun", "uplata", "isplata", "dugovanje", "likvidnost", "kredit", "kamat", "saldo", "placanje"},
	"racunovodstvo": {"knjizenje", "pdv", "porez", "bilans", "kontiranje", "konto", "amortizacija", "prijava", "obracun"},
	"logistika":     {"dostava", "transport", "vozilo", "ruta", "isporuka", "posiljka", "kamion", "otpremnica"},
	"magacin":       {"magacin", "zaliha", "lager", "skladiste", "inventar", "ulaz", "izlaz", "artikal", "sifra"},
	"kadrovi":       {"radnik", "zaposleni", "kadrovi", "ugovor o radu", "godisnji", "odmor", "plata", "zaposljavanje", "cv"},
	"it":            {"server", "mreza", "baza", "backup", "sistem", "infra", "sigurnost", "login", "pristup", "vpn"},
	"kod":           {"kod", "program", "funkcija", "bug", "debug", "refactor", "python", "api", "skripta", "compile", "test"},
	"pravo":         {"ugovor", "zakon", "pravni", "tuzba", "regulativa", "gdpr", "obaveza", "klauzula", "rok"},
	"marketing":     {"marketing", "kampanja", "seo", "reklama", "brend", "objava", "drustvene mreze", "reels", "tekst oglasa"},
	"analitika":     {"analiza", "izvjestaj", "report", "statistika", "kpi", "trend", "grafikon", "dashboard", "metrika"},
	"podrska":       {"podrska", "ticket", "zalba", "pomoc", "problem", "korisnik pita", "reklamacija", "support"},
}

var sensitiveDomains = map[string]float64{
	"finansije":     0.25,
	"racunovodstvo": 0.20,
	"pravo":         0.30,
	"kadrovi":       0.15,
}

// HIGH_RISK_PATTERNS — isto, ali bez \b (Go RE2 ne podržava \b isto kao Python
// za non-ASCII; koristimo iste patternе; \b postoji u RE2 i radi za ASCII).
var highRiskPatterns = []string{
	`\bobrisi\b`, `\bdelete\b`, `\bdrop\b`, `\btruncate\b`,
	`\bformatiraj\b`, `\bprebrisi\b`, `\boverwrite\b`,
	`\bplati\b`, `\buplati\b`, `\btransfer\b`, `\bprenos\s+novc`,
	`\bpotpisi\b`, `\bsign\b`, `\bposalji\s+svima\b`, `\bbroadcast\b`,
	`\badmin\b`, `\broot\b`, `\bsudo\b`, `\bprod\b`, `\bdeploy\b`,
	`\bmailing\s+lista\b`, `\bizbrisi\s+bazu\b`, `\buninstall\b`,
	`\brm\s+-rf\b`, `\bshutdown\b`, `\breboot\b`, `\bpassword\b`,
	`\bsifra\b`, `\bprivatni\s+kljuc\b`, `\bprivate\s+key\b`,
}

// RISK_MODEL v2 — T1 katastrofalno / T2 visoko (usklađeno sa Rust/Python v2).
var t1Patterns = []string{
	`rm\s+-rf\s*/`, `rm\s+-rf\s+~`, `rm\s+-rf\s+\*`, `format\s+[a-z]:`,
	`\bmkfs\b`, `\bdd\s+if=.*of=/dev/`, `drop\s+(table|database)`,
	`\btruncate\s+table`, `\bshutdown\b`, `\breboot\b`,
	`obrisi\s+(sve|citav|cijeli)`, `izbrisi\s+(sve|bazu|disk)`,
}
var t2Patterns = []string{
	`obrisi\s+(fajl|folder|direktorij|log|datotek)`, `delete\s+(file|folder|all)`,
	`\brm\b`, `\bdrop\b`, `\btruncate\b`, `root\s+(pristup|bez)`,
	`ugasi\s+server`, `stop\s+all`, `killall`, `pkill\s+-9`,
	`chmod\s+777`, `chown\s+-R`,
}

var multiDomainMarkers = []string{
	" i ", " te ", " zatim ", " nakon ", " kao i ", " plus ", " uz to ",
	"korak 1", "korak 2", "prvo", "drugo", "treće", "takođe", "pored",
}

// Domain order mora biti stabilan da težine i tie-break budu identični Pythonu.
var domainOrder = []string{
	"prodaja", "nabavka", "finansije", "racunovodstvo", "logistika", "magacin",
	"kadrovi", "it", "kod", "pravo", "marketing", "analitika", "podrska",
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

type Router struct {
	highRisk []*regexp.Regexp
	t1       []*regexp.Regexp
	t2       []*regexp.Regexp
}

func compileAll(patterns []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, regexp.MustCompile("(?i)"+p))
	}
	return out
}

func NewRouter() *Router {
	return &Router{
		highRisk: compileAll(highRiskPatterns),
		t1:       compileAll(t1Patterns),
		t2:       compileAll(t2Patterns),
	}
}

type classification struct {
	domain          string
	confidence      float64
	scores          map[string]float64
	matchedKeywords []string
	multiDomain     bool
}

// hit — stem/prefix match (identično Python _hit).
func hit(kw, txt string) bool {
	if strings.Contains(txt, kw) {
		return true
	}
	for _, L := range []int{6, 5, 4} {
		if len(kw) >= L && strings.Contains(txt, kw[:L]) {
			return true
		}
	}
	return false
}

func (r *Router) classify(task string) classification {
	text := strings.ToLower(strings.TrimSpace(task))
	if text == "" {
		return classification{domain: "opste", confidence: 0.10,
			scores: map[string]float64{"opste": 0.10}}
	}

	raw := map[string]float64{}
	matched := map[string][]string{}

	for _, domain := range domainOrder {
		keywords := domainKeywords[domain]
		var hitList []string
		for _, kw := range keywords {
			if hit(kw, text) {
				hitList = append(hitList, kw)
			}
		}
		if len(hitList) > 0 {
			weight := 0.0
			for idx := range hitList {
				weight += 1.0 / (1.0 + 0.15*float64(idx))
			}
			sumLen := 0
			for _, kw := range hitList {
				sumLen += len(kw)
			}
			weight += 0.10 * float64(sumLen) / 10.0
			raw[domain] = raw[domain] + weight
			matched[domain] = hitList
		}
	}

	if len(raw) == 0 {
		return classification{domain: "opste", confidence: 0.20,
			scores: map[string]float64{"opste": 0.20}}
	}

	total := 0.0
	for _, v := range raw {
		total += v
	}
	scores := map[string]float64{}
	for d, v := range raw {
		scores[d] = v / total
	}

	bestDomain := ""
	bestScore := -1.0
	// Deterministički tie-break: po domainOrder (map iteracija je slučajna u Go).
	for _, d := range domainOrder {
		s, ok := scores[d]
		if !ok {
			continue
		}
		if s > bestScore {
			bestScore = s
			bestDomain = d
		}
	}

	// runner-up (2. najveći)
	var vals []float64
	for _, v := range scores {
		vals = append(vals, v)
	}
	sort.Sort(sort.Reverse(sort.Float64Slice(vals)))
	second := 0.0
	if len(vals) > 1 {
		second = vals[1]
	}

	confidence := 0.6*bestScore + 0.4*(bestScore-second) + 0.2
	if confidence > 1.0 {
		confidence = 1.0
	}
	if confidence < 0.0 {
		confidence = 0.0
	}

	markerHits := 0
	for _, m := range multiDomainMarkers {
		if strings.Contains(text, m) {
			markerHits++
		}
	}
	multiDomain := markerHits >= 2 || (len(scores) >= 3 && confidence < PrahSingle)

	return classification{
		domain:          bestDomain,
		confidence:      confidence,
		scores:          scores,
		matchedKeywords: matched[bestDomain],
		multiDomain:     multiDomain,
	}
}

func (r *Router) assessRisk(task, domain string) float64 {
	text := strings.ToLower(task)
	hits := 0
	for _, rx := range r.highRisk {
		if rx.MatchString(text) {
			hits++
		}
	}
	risk := 0.0
	for _, rx := range r.t1 {
		if rx.MatchString(text) {
			if risk < 0.9 {
				risk = 0.9
			}
		}
	}
	for _, rx := range r.t2 {
		if rx.MatchString(text) {
			if risk < 0.7 {
				risk = 0.7
			}
		}
	}
	m := float64(hits) * 0.35
	if m > 0.75 {
		m = 0.75
	}
	if m > risk {
		risk = m
	}
	risk += sensitiveDomains[domain]
	if domain == "finansije" && strings.Contains(text, "transfer") {
		risk += 0.15
	}
	if risk < 0.0 {
		risk = 0.0
	}
	if risk > 1.0 {
		risk = 1.0
	}
	return risk
}

type routeResult struct {
	Mode       string   `json:"mode"`
	Agents     []string `json:"agents"`
	Reason     string   `json:"reason"`
	Domain     string   `json:"domain"`
	Confidence float64  `json:"confidence"`
	Risk       float64  `json:"risk"`
	Blocked    bool     `json:"blocked"`
}

func routeOut(mode string, agents []string, reason, domain string, conf, risk float64, blocked bool) routeResult {
	if agents == nil {
		agents = []string{}
	}
	return routeResult{
		Mode:       mode,
		Agents:     agents,
		Reason:     reason,
		Domain:     domain,
		Confidence: round4(conf),
		Risk:       round4(risk),
		Blocked:    blocked,
	}
}

func (r *Router) route(task string) routeResult {
	cls := r.classify(task)
	riskVal := r.assessRisk(task, cls.domain)
	if riskVal < 0.0 {
		riskVal = 0.0
	}
	if riskVal > 1.0 {
		riskVal = 1.0
	}

	primary := domainAgents[cls.domain]
	if primary == nil {
		primary = domainAgents["opste"]
	}

	// 1) HARD-BLOCK
	if riskVal >= RiskHardBlock {
		return routeOut("single", []string{},
			fmt.Sprintf("HARD-BLOCK: rizik=%.2f >= %.2f (domen=%s). Zadr\u017eano na ljudsku verifikaciju prije izvr\u0161enja.",
				riskVal, RiskHardBlock, cls.domain),
			cls.domain, cls.confidence, riskVal, true)
	}

	// 2) SINGLE
	if cls.confidence >= PrahSingle {
		return routeOut("single", []string{primary[0]},
			fmt.Sprintf("Visoka pouzdanost=%.2f >= %.2f za domen=%s; jedan nosivi agent je dovoljan.",
				cls.confidence, PrahSingle, cls.domain),
			cls.domain, cls.confidence, riskVal, false)
	}

	// 3) GROUP
	if cls.confidence >= PrahGroup {
		var agents []string
		if len(primary) >= 2 {
			agents = append(agents, primary[:2]...)
		} else {
			agents = append(agents, primary...)
		}
		if cls.multiDomain && len(cls.scores) > 1 {
			rk := rankedDomains(cls.scores)
			if len(rk) > 1 {
				secondDomain := rk[1]
				for _, a := range firstN(domainAgents[secondDomain], 1) {
					if !contains(agents, a) {
						agents = append(agents, a)
					}
				}
			}
		}
		reason := fmt.Sprintf("Srednja pouzdanost=%.2f u [%.2f,%.2f); anga\u017euje se grupa agenata za domen=%s",
			cls.confidence, PrahGroup, PrahSingle, cls.domain)
		if cls.multiDomain {
			reason += " (multi-domen)"
		}
		return routeOut("group", agents, reason, cls.domain, cls.confidence, riskVal, false)
	}

	// 4) SWARM
	agents := append([]string{}, primary...)
	ranked := rankedDomains(cls.scores)
	for _, d := range sliceSafe(ranked, 1, 3) {
		for _, a := range firstN(domainAgents[d], 1) {
			if !contains(agents, a) {
				agents = append(agents, a)
			}
		}
	}
	return routeOut("swarm", agents,
		fmt.Sprintf("Niska pouzdanost=%.2f < %.2f; zadatak je neodre\u0111en/\u0161irok te se pokre\u0107e Roj agenata (domen\u2248%s).",
			cls.confidence, PrahGroup, cls.domain),
		cls.domain, cls.confidence, riskVal, false)
}

// rankedDomains — domeni sortirani po skoru opadajuće; tie-break po domainOrder.
func rankedDomains(scores map[string]float64) []string {
	type kv struct {
		d string
		s float64
	}
	var items []kv
	for _, d := range domainOrder {
		if s, ok := scores[d]; ok {
			items = append(items, kv{d, s})
		}
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].s > items[j].s })
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.d
	}
	return out
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// sliceSafe — safe[lo:hi] kao Python (clamp, prazno ako lo>=hi).
func sliceSafe(s []string, lo, hi int) []string {
	if lo < 0 {
		lo = 0
	}
	if hi > len(s) {
		hi = len(s)
	}
	if lo >= hi {
		return nil
	}
	return s[lo:hi]
}

func contains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

func round4(x float64) float64 {
	return math.Round(x*10000) / 10000
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	inFile := flag.String("in", "", "putanja do inputs.json (JSON array stringova); prazno = stdin")
	bench := flag.Bool("bench", false, "benchmark mod")
	n := flag.Int("n", 10000, "broj ponavljanja u bench modu")
	flag.Parse()

	var tasks []string
	if *inFile != "" {
		data, err := os.ReadFile(*inFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "greska citanja:", err)
			os.Exit(1)
		}
		if err := json.Unmarshal(data, &tasks); err != nil {
			fmt.Fprintln(os.Stderr, "greska JSON:", err)
			os.Exit(1)
		}
	} else {
		// stdin: JSON array ili linije
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		var b strings.Builder
		for sc.Scan() {
			b.WriteString(sc.Text())
			b.WriteByte('\n')
		}
		raw := strings.TrimSpace(b.String())
		if strings.HasPrefix(raw, "[") {
			if err := json.Unmarshal([]byte(raw), &tasks); err != nil {
				fmt.Fprintln(os.Stderr, "greska JSON:", err)
				os.Exit(1)
			}
		} else {
			for _, ln := range strings.Split(raw, "\n") {
				tasks = append(tasks, ln)
			}
		}
	}

	router := NewRouter()

	if *bench {
		var last []routeResult
		start := nowFn()
		for i := 0; i < *n; i++ {
			last = make([]routeResult, 0, len(tasks))
			for _, t := range tasks {
				last = append(last, router.route(t))
			}
		}
		el := nowFn().Sub(start)
		total := *n * len(tasks)
		fmt.Fprintf(os.Stderr, "BENCH: %d upita u %.4fs = %.2f us/upit (%.0f upita/s)\n",
			total, el.Seconds(), el.Seconds()*1e6/float64(total), float64(total)/el.Seconds())
		// Ispiši posljednji rezultat (identičan izlaz kao jednokratno).
		out, _ := json.MarshalIndent(last, "", "  ")
		os.Stdout.Write(out)
		os.Stdout.Write([]byte("\n"))
		return
	}

	results := make([]routeResult, 0, len(tasks))
	for _, t := range tasks {
		results = append(results, router.route(t))
	}
	out, _ := json.MarshalIndent(results, "", "  ")
	os.Stdout.Write(out)
	os.Stdout.Write([]byte("\n"))
}
