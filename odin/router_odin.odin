// router_odin.odin â€” risk-calib hybrid: Odin verzija router.py (vjerna kopija).
//
// Build:  odin build router_odin.odin -file -o:speed -out:router_odin
// Pokretanje: ./router_odin -in ../fixtures/inputs.json
//             ./router_odin -bench -n 10000 -in ../fixtures/inputs.json
#+feature dynamic-literals
package main

import "core:fmt"
import "core:os"
import "core:strings"
import "core:strconv"
import "core:slice"
import "core:time"
import "core:mem"

// ---------------------------------------------------------------------------
// Konstante
// ---------------------------------------------------------------------------
PRAH_SINGLE :: 0.62
PRAH_GROUP :: 0.38
RISK_HARD_BLOCK :: 0.85

Domain_Agents :: struct {
	domain: string,
	agents: []string,
}

domain_agents := []Domain_Agents{
	{"prodaja", {"agent_prodaja", "agent_ponuda"}},
	{"nabavka", {"agent_nabavka", "agent_dobavljac"}},
	{"finansije", {"agent_finansije", "agent_fakture", "agent_knjizenje"}},
	{"racunovodstvo", {"agent_knjizenje", "agent_pdv", "agent_bilans"}},
	{"logistika", {"agent_logistika", "agent_zalihe"}},
	{"magacin", {"agent_zalihe", "agent_magacin"}},
	{"kadrovi", {"agent_kadrovi", "agent_plate"}},
	{"it", {"agent_it", "agent_ops"}},
	{"kod", {"agent_kod", "agent_review"}},
	{"pravo", {"agent_pravo", "agent_ugovori"}},
	{"marketing", {"agent_marketing", "agent_seo"}},
	{"analitika", {"agent_analitika", "agent_report"}},
	{"podrska", {"agent_podrska", "agent_ticket"}},
	{"opste", {"agent_general"}},
}

Domain_KW :: struct {
	domain: string,
	keywords: []string,
}

domain_keywords := []Domain_KW{
	{"prodaja", {"kupac", "prodaja", "ponuda", "narudzba", "cjenovnik", "popust", "klijent", "lead", "deal", "cijena"}},
	{"nabavka", {"nabavka", "dobavljac", "ulazna", "porudzbina", "supplier", "naruciti", "kolicina", "veleprodaja"}},
	{"finansije", {"faktura", "racun", "uplata", "isplata", "dugovanje", "likvidnost", "kredit", "kamat", "saldo", "placanje"}},
	{"racunovodstvo", {"knjizenje", "pdv", "porez", "bilans", "kontiranje", "konto", "amortizacija", "prijava", "obracun"}},
	{"logistika", {"dostava", "transport", "vozilo", "ruta", "isporuka", "posiljka", "kamion", "otpremnica"}},
	{"magacin", {"magacin", "zaliha", "lager", "skladiste", "inventar", "ulaz", "izlaz", "artikal", "sifra"}},
	{"kadrovi", {"radnik", "zaposleni", "kadrovi", "ugovor o radu", "godisnji", "odmor", "plata", "zaposljavanje", "cv"}},
	{"it", {"server", "mreza", "baza", "backup", "sistem", "infra", "sigurnost", "login", "pristup", "vpn"}},
	{"kod", {"kod", "program", "funkcija", "bug", "debug", "refactor", "python", "api", "skripta", "compile", "test"}},
	{"pravo", {"ugovor", "zakon", "pravni", "tuzba", "regulativa", "gdpr", "obaveza", "klauzula", "rok"}},
	{"marketing", {"marketing", "kampanja", "seo", "reklama", "brend", "objava", "drustvene mreze", "reels", "tekst oglasa"}},
	{"analitika", {"analiza", "izvjestaj", "report", "statistika", "kpi", "trend", "grafikon", "dashboard", "metrika"}},
	{"podrska", {"podrska", "ticket", "zalba", "pomoc", "problem", "korisnik pita", "reklamacija", "support"}},
}

sensitive := map[string]f64{
	"finansije" = 0.25, "racunovodstvo" = 0.20, "pravo" = 0.30, "kadrovi" = 0.15,
}

high_risk := []string{
	"obrisi", "delete", "drop", "truncate", "formatiraj", "prebrisi", "overwrite",
	"plati", "uplati", "transfer", "prenos novc", "potpisi", "sign", "posalji svima",
	"broadcast", "admin", "root", "sudo", "prod", "deploy", "mailing lista",
	"izbrisi bazu", "uninstall", "rm -rf", "shutdown", "reboot", "password",
	"sifra", "privatni kljuc", "private key",
}

t1_patterns := []string{
	"rm -rf /", "rm -rf ~", "rm -rf *", "format c:", "format d:", "mkfs",
	"drop table", "drop database", "truncate table", "shutdown", "reboot",
	"obrisi sve", "obrisi citav", "obrisi cijeli", "izbrisi sve", "izbrisi bazu", "izbrisi disk",
}

t2_patterns := []string{
	"obrisi fajl", "obrisi folder", "obrisi direktorij", "obrisi log",
	"delete file", "delete folder", "rm", "drop", "truncate", "root pristup", "root bez",
	"ugasi server", "stop all", "killall", "pkill -9", "chmod 777", "chown -r",
}

multi_markers := []string{
	" i ", " te ", " zatim ", " nakon ", " kao i ", " plus ", " uz to ",
	"korak 1", "korak 2", "prvo", "drugo", "\u0107e", "tako", "pored",
}

// ---------------------------------------------------------------------------
// PomoÄ‡ne
// ---------------------------------------------------------------------------
agents_for :: proc(domain: string) -> []string {
	for da in domain_agents {
		if da.domain == domain { return da.agents }
	}
	return domain_agents[len(domain_agents)-1].agents
}

sensitive_for :: proc(domain: string) -> f64 {
	if v, ok := sensitive[domain]; ok { return v }
	return 0.0
}

kw_hit :: proc(kw, text: string) -> bool {
	if strings.contains(text, kw) { return true }
	for L in ([]int{6, 5, 4}) {
		if len(kw) >= L {
			if strings.contains(text, kw[:L]) { return true }
		}
	}
	return false
}

word_hit :: proc(w, text: string) -> bool {
	init := 0
	for {
		idx := strings.index(text[init:], w)
		if idx < 0 { return false }
		s := init + idx
		e := s + len(w)
		ok_b := s == 0 || !is_word_char(text[s-1])
		ok_a := e >= len(text) || !is_word_char(text[e])
		if ok_b && ok_a { return true }
		init = e
		if init >= len(text) { return false }
	}
}

is_word_char :: proc(c: u8) -> bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') || c == '_'
}

round4 :: proc(x: f64) -> f64 {
	return f64(i64(x * 10000.0 + 0.5)) / 10000.0
}

// ---------------------------------------------------------------------------
// Klasifikacija
// ---------------------------------------------------------------------------
Classification :: struct {
	domain: string,
	confidence: f64,
	scores: []Score,
	order: []string,
	matched: []string,
	multi: bool,
}

Score :: struct { domain: string, val: f64 }

// Globalni literali (izbjegavamo stack-frame return greÅ¡ke).
EMPTY_OPSTE10 := [1]Score{{"opste", 0.10}}
EMPTY_OPSTE20 := [1]Score{{"opste", 0.20}}
OPSTE_ONLY := [1]string{"opste"}
EMPTY_STR: []string = {}   // pravi prazan niz (ne [1]{})

classify :: proc(task: string, allocator := context.allocator) -> Classification {
	text := strings.to_lower(strings.trim_space(task), allocator)

	if len(text) == 0 {
		return Classification{domain = "opste", confidence = 0.10,
			scores = EMPTY_OPSTE10[:], order = OPSTE_ONLY[:]}
	}

	raw := make([dynamic]Score, allocator)
	order := make([dynamic]string, allocator)
	matched := make(map[string][]string, allocator)

	for kw_set in domain_keywords {
		hits := make([dynamic]string, allocator)
		for kw in kw_set.keywords {
			if kw_hit(kw, text) { append(&hits, kw) }
		}
		if len(hits) > 0 {
			weight := 0.0
			for _, idx in hits {
				_ = idx
			}
			for i in 0 ..< len(hits) {
				weight += 1.0 / (1.0 + 0.15 * f64(i))
			}
			sum_len := 0
			for kw in hits { sum_len += len(kw) }
			weight += 0.10 * f64(sum_len) / 10.0
			append(&raw, Score{kw_set.domain, weight})
			append(&order, kw_set.domain)
			matched[kw_set.domain] = slice.clone(hits[:], allocator)
		}
	}

	if len(raw) == 0 {
		return Classification{domain = "opste", confidence = 0.20,
			scores = EMPTY_OPSTE20[:], order = OPSTE_ONLY[:]}
	}

	total := 0.0
	for s in raw { total += s.val }
	scores := make([dynamic]Score, allocator)
	for s in raw { append(&scores, Score{s.domain, s.val / total}) }

	best_domain := ""
	best_score := -1.0
	for s in scores {
		if s.val > best_score { best_score = s.val; best_domain = s.domain }
	}

	// runner-up
	vals := make([dynamic]f64, allocator)
	for s in scores { append(&vals, s.val) }
	slice.sort_by(vals[:], proc(a, b: f64) -> bool { return a > b })
	second := 0.0
	if len(vals) > 1 { second = vals[1] }

	confidence := 0.6 * best_score + 0.4 * (best_score - second) + 0.2
	if confidence > 1.0 { confidence = 1.0 }
	if confidence < 0.0 { confidence = 0.0 }

	mh := 0
	for m in multi_markers { if strings.contains(text, m) { mh += 1 } }
	multi := mh >= 2 || (len(scores) >= 3 && confidence < PRAH_SINGLE)

	best_matched: []string
	if m, ok := matched[best_domain]; ok { best_matched = m }

	return Classification{domain = best_domain, confidence = confidence,
		scores = scores[:], order = order[:], matched = best_matched, multi = multi}
}

// ---------------------------------------------------------------------------
// Rizik
// ---------------------------------------------------------------------------
assess_risk :: proc(task, domain: string, allocator := context.allocator) -> f64 {
	// RISK_V2: T1/T2 + transfer boost; bez translita (Python zlatni standard).
	text := strings.to_lower(task, allocator)
	risk := 0.0
	for w in t1_patterns {
		if word_hit(w, text) { risk = 0.9 }
	}
	if strings.contains(text, "dd if=") && strings.contains(text, "of=/dev/") { risk = 0.9 }
	for w in t2_patterns {
		if word_hit(w, text) && risk < 0.7 { risk = 0.7 }
	}
	hits := 0
	for w in high_risk {
		if word_hit(w, text) { hits += 1 }
	}
	if f64(hits) * 0.35 < risk { } else { risk = min(0.75, f64(hits) * 0.35) }
	risk += sensitive_for(domain)
	if domain == "finansije" && strings.contains(text, "transfer") { risk += 0.15 }
	return clamp(risk, 0.0, 1.0)
}

// ---------------------------------------------------------------------------
// Rutiranje
// ---------------------------------------------------------------------------
Route_Result :: struct {
	mode: string,
	agents: []string,
	reason: string,
	domain: string,
	confidence: f64,
	risk: f64,
	blocked: bool,
}

ranked_domains :: proc(cls: Classification, allocator := context.allocator) -> []string {
	out := slice.clone(cls.order, allocator)
	slice.sort_by(out, proc(a, b: string) -> bool {
		// tie-break: originalni redoslijed â€” treba nam scores lookup; radimo closure preko globala
		return false
	})
	return out
}

route :: proc(task: string, allocator := context.allocator) -> Route_Result {
	cls := classify(task, allocator)
	risk := assess_risk(task, cls.domain, allocator)
	primary := agents_for(cls.domain)

	if risk >= RISK_HARD_BLOCK {
		res: Route_Result
		res.mode = "single"
		res.agents = EMPTY_STR[:]
		res.reason = fmt.aprintf("HARD-BLOCK: rizik=%.2f >= %.2f (domen=%s). Zadrzano na ljudsku verifikaciju prije izvrsenja.",
				risk, RISK_HARD_BLOCK, cls.domain, allocator = allocator)
		res.domain = cls.domain
		res.confidence = round4(cls.confidence)
		res.risk = round4(risk)
		res.blocked = true
		return res
	}

	if cls.confidence >= PRAH_SINGLE {
		one := make([]string, 1, allocator)
		one[0] = primary[0]
		res: Route_Result
		res.mode = "single"
		res.agents = one
		res.reason = fmt.aprintf("Visoka pouzdanost=%.2f >= %.2f za domen=%s; jedan nosivi agent je dovoljan.",
				cls.confidence, PRAH_SINGLE, cls.domain, allocator = allocator)
		res.domain = cls.domain
		res.confidence = round4(cls.confidence)
		res.risk = round4(risk)
		res.blocked = false
		return res
	}

	if cls.confidence >= PRAH_GROUP {
		agents := make([dynamic]string, allocator)
		if len(primary) >= 2 {
			append(&agents, primary[0]); append(&agents, primary[1])
		} else {
			append(&agents, ..primary)
		}
		if cls.multi && len(cls.scores) > 1 {
			rk := ranked_by_score(cls, allocator)
			if len(rk) > 1 {
				da := agents_for(rk[1])
				if len(da) > 0 && !contains(agents[:], da[0]) { append(&agents, da[0]) }
			}
		}
		reason := fmt.aprintf("Srednja pouzdanost=%.2f u [%.2f,%.2f); angazuje se grupa agenata za domen=%s",
			cls.confidence, PRAH_GROUP, PRAH_SINGLE, cls.domain, allocator = allocator)
		if cls.multi { reason = strings.concatenate({reason, " (multi-domen)"}, allocator) }
		res: Route_Result
		res.mode = "group"
		res.agents = agents[:]
		res.reason = reason
		res.domain = cls.domain
		res.confidence = round4(cls.confidence)
		res.risk = round4(risk)
		res.blocked = false
		return res
	}

	agents := make([dynamic]string, allocator)
	append(&agents, ..primary)
	rk := ranked_by_score(cls, allocator)
	end := min(3, len(rk))
	for i in 1 ..< end {
		da := agents_for(rk[i])
		if len(da) > 0 && !contains(agents[:], da[0]) { append(&agents, da[0]) }
	}
	res: Route_Result
	res.mode = "swarm"
	res.agents = agents[:]
	res.reason = fmt.aprintf("Niska pouzdanost=%.2f < %.2f; zadatak je neodredjen/sirok te se pokrece Roj agenata (domen~%s).",
			cls.confidence, PRAH_GROUP, cls.domain, allocator = allocator)
	res.domain = cls.domain
	res.confidence = round4(cls.confidence)
	res.risk = round4(risk)
	res.blocked = false
	return res
}

// ranked_by_score â€” sortiraj po skoru opadajuce; tie-break po order (stabilno).
ranked_by_score :: proc(cls: Classification, allocator := context.allocator) -> []string {
	out := slice.clone(cls.order, allocator)
	// bubble-like stabilan sort (mali N, determinizam)
	for i in 0 ..< len(out) {
		for j in 0 ..< len(out)-1-i {
			vi, _ := score_of(cls, out[j])
			vj, _ := score_of(cls, out[j+1])
			if vj > vi {
				out[j], out[j+1] = out[j+1], out[j]
			}
		}
	}
	return out
}

score_of :: proc(cls: Classification, domain: string) -> (f64, bool) {
	for s in cls.scores {
		if s.domain == domain { return s.val, true }
	}
	return 0.0, false
}

contains :: proc(arr: []string, x: string) -> bool {
	for v in arr { if v == x { return true } }
	return false
}

// ---------------------------------------------------------------------------
// JSON encode (minimalno, deterministiÄki â€” sortirani kljucevi)
// ---------------------------------------------------------------------------
json_escape :: proc(s: string, b: ^strings.Builder) {
	for c in s {
		switch c {
		case '"': strings.write_string(b, "\\\"")
		case '\\': strings.write_string(b, "\\\\")
		case '\n': strings.write_string(b, "\\n")
		case '\r': strings.write_string(b, "\\r")
		case '\t': strings.write_string(b, "\\t")
		case: strings.write_rune(b, c)
		}
	}
}

write_num4 :: proc(b: ^strings.Builder, x: f64) {
	// 4 decimale, skini suvisne nule (kao Python round4 -> json)
	if x == f64(i64(x)) {
		fmt.sbprintf(b, "%.0f", x)
		return
	}
	s := fmt.aprintf("%.4f", x)
	// skini trailing nule
	t := s
	for len(t) > 0 && t[len(t)-1] == '0' { t = t[:len(t)-1] }
	if len(t) > 0 && t[len(t)-1] == '.' { t = t[:len(t)-1] }
	strings.write_string(b, t)
}

encode_result :: proc(r: Route_Result, b: ^strings.Builder) {
	strings.write_string(b, "{")
	strings.write_string(b, "\"agents\":[")
	for a, i in r.agents {
		if i > 0 { strings.write_string(b, ",") }
		strings.write_string(b, "\"")
		json_escape(a, b)
		strings.write_string(b, "\"")
	}
	strings.write_string(b, "],")
	fmt.sbprintf(b, "\"blocked\":%s,", r.blocked ? "true" : "false")
	strings.write_string(b, "\"confidence\":")
	write_num4(b, r.confidence)
	strings.write_string(b, ",\"domain\":\"")
	json_escape(r.domain, b)
	strings.write_string(b, "\",\"mode\":\"")
	json_escape(r.mode, b)
	strings.write_string(b, "\",\"reason\":\"")
	json_escape(r.reason, b)
	strings.write_string(b, "\",\"risk\":")
	write_num4(b, r.risk)
	strings.write_string(b, "}")
}

encode_array :: proc(results: []Route_Result, allocator := context.allocator) -> string {
	b := strings.builder_make(allocator)
	strings.write_string(&b, "[")
	for r, i in results {
		if i > 0 { strings.write_string(&b, ",") }
		encode_result(r, &b)
	}
	strings.write_string(&b, "]")
	return strings.to_string(b)
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
main :: proc() {
	args := os.args
	in_file := ""
	bench := false
	n := 10000

	i := 1
	for i < len(args) {
		a := args[i]
		switch {
		case a == "-in" || a == "--in":
			i += 1; in_file = args[i]
		case strings.has_prefix(a, "-in="):
			in_file = a[4:]
		case a == "-bench" || a == "--bench":
			bench = true
		case a == "-n" || a == "--n":
			i += 1; v, _ := strconv.parse_int(args[i]); n = v
		case strings.has_prefix(a, "-n="):
			v, _ := strconv.parse_int(a[3:]); n = v
		}
		i += 1
	}

	raw: []byte
	err: os.Error
	if in_file != "" {
		raw, err = os.read_entire_file_from_path(in_file, context.allocator)
	} else {
		raw, err = os.read_entire_file_from_path("/dev/stdin", context.allocator)
	}
	if err != nil {
		fmt.eprintln("greska citanja")
		os.exit(1)
	}
	content := string(raw)

	// parse: JSON array stringova (jednostavan parser za ["a","b",...])
	tasks := make([dynamic]string)
	trimmed := strings.trim_space(content)
	if in_file != "" || strings.has_prefix(trimmed, "[") {
		// izvuci stringove izmedju navodnika (uz escape)
		s := trimmed
		idx := 0
		for idx < len(s) {
			if s[idx] == '"' {
				idx += 1
				b := strings.builder_make()
				for idx < len(s) && s[idx] != '"' {
					if s[idx] == '\\' && idx+1 < len(s) {
						switch s[idx+1] {
						case 'n': strings.write_byte(&b, '\n')
						case 't': strings.write_byte(&b, '\t')
						case '"': strings.write_byte(&b, '"')
						case '\\': strings.write_byte(&b, '\\')
						case '/': strings.write_byte(&b, '/')
						case 'u':
							if idx+5 < len(s) {
								hex := s[idx+2:idx+6]
								code := 0; _ = code
							}
							strings.write_byte(&b, '?')
							idx += 4
						}
						idx += 2
					} else {
						strings.write_byte(&b, s[idx])
						idx += 1
					}
				}
				append(&tasks, strings.to_string(b))
				idx += 1
			} else {
				idx += 1
			}
		}
	} else {
		for line in strings.split_lines(trimmed) {
			if len(line) > 0 { append(&tasks, line) }
		}
	}

	if bench {
		start := time.now()
		last: []Route_Result
		for _ in 0 ..< n {
			res := make([]Route_Result, len(tasks))
			for t, k in tasks { res[k] = route(t) }
			last = res
		}
		el := time.since(start)
		el_s := f64(el) / 1e9
		total := f64(n * len(tasks))
		fmt.eprintf("BENCH: %d upita u %.4fs = %.2f us/upit (%.0f upita/s)\n",
			int(total), el_s, el_s*1e6/total, total/el_s)
		fmt.println(encode_array(last))
		return
	}

	results := make([]Route_Result, len(tasks))
	for t, k in tasks { results[k] = route(t) }
	fmt.println(encode_array(results))
}



