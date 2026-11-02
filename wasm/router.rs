// router.rs — risk-calib hybrid: Rust router LOGIKA kao modul (biblioteka).
// Koristi ga i CLI (main.rs) i topli sidecar (sidecar.rs).
// 1:1 vjerna kopija Python router.py (i Go router_go/main.go).

use regex::Regex;
use std::sync::OnceLock;
use serde::Serialize;
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Konstante / pragovi (identično Pythonu i Go-u)
// ---------------------------------------------------------------------------
pub const PRAH_SINGLE: f64 = 0.62;
pub const PRAH_GROUP: f64 = 0.38;
pub const RISK_HARD_BLOCK: f64 = 0.85;

// Domain order mora biti stabilan da težine i tie-break budu identični Pythonu.
// (DOMAIN_KEYWORDS je već u ovom redu; konstanta je referenca/dokumentacija.)
#[allow(dead_code)]
const DOMAIN_ORDER: [&str; 13] = [
    "prodaja", "nabavka", "finansije", "racunovodstvo", "logistika", "magacin",
    "kadrovi", "it", "kod", "pravo", "marketing", "analitika", "podrska",
];

// DOMAIN_KEYWORDS — identično Pythonu (redoslijed bitan zbog težina).
const DOMAIN_KEYWORDS: [(&str, &[&str]); 13] = [
    ("prodaja", &["kupac", "prodaja", "ponuda", "narudzba", "cjenovnik", "popust", "klijent", "lead", "deal", "cijena"]),
    ("nabavka", &["nabavka", "dobavljac", "ulazna", "porudzbina", "supplier", "naruciti", "kolicina", "veleprodaja"]),
    ("finansije", &["faktura", "racun", "uplata", "isplata", "dugovanje", "likvidnost", "kredit", "kamat", "saldo", "placanje"]),
    ("racunovodstvo", &["knjizenje", "pdv", "porez", "bilans", "kontiranje", "konto", "amortizacija", "prijava", "obracun"]),
    ("logistika", &["dostava", "transport", "vozilo", "ruta", "isporuka", "posiljka", "kamion", "otpremnica"]),
    ("magacin", &["magacin", "zaliha", "lager", "skladiste", "inventar", "ulaz", "izlaz", "artikal", "sifra"]),
    ("kadrovi", &["radnik", "zaposleni", "kadrovi", "ugovor o radu", "godisnji", "odmor", "plata", "zaposljavanje", "cv"]),
    ("it", &["server", "mreza", "baza", "backup", "sistem", "infra", "sigurnost", "login", "pristup", "vpn"]),
    ("kod", &["kod", "program", "funkcija", "bug", "debug", "refactor", "python", "api", "skripta", "compile", "test"]),
    ("pravo", &["ugovor", "zakon", "pravni", "tuzba", "regulativa", "gdpr", "obaveza", "klauzula", "rok"]),
    ("marketing", &["marketing", "kampanja", "seo", "reklama", "brend", "objava", "drustvene mreze", "reels", "tekst oglasa"]),
    ("analitika", &["analiza", "izvjestaj", "report", "statistika", "kpi", "trend", "grafikon", "dashboard", "metrika"]),
    ("podrska", &["podrska", "ticket", "zalba", "pomoc", "problem", "korisnik pita", "reklamacija", "support"]),
];

// DOMAIN_AGENTS — identično Pythonu (uključuje "opste").
const DOMAIN_AGENTS: [(&str, &[&str]); 14] = [
    ("prodaja", &["agent_prodaja", "agent_ponuda"]),
    ("nabavka", &["agent_nabavka", "agent_dobavljac"]),
    ("finansije", &["agent_finansije", "agent_fakture", "agent_knjizenje"]),
    ("racunovodstvo", &["agent_knjizenje", "agent_pdv", "agent_bilans"]),
    ("logistika", &["agent_logistika", "agent_zalihe"]),
    ("magacin", &["agent_zalihe", "agent_magacin"]),
    ("kadrovi", &["agent_kadrovi", "agent_plate"]),
    ("it", &["agent_it", "agent_ops"]),
    ("kod", &["agent_kod", "agent_review"]),
    ("pravo", &["agent_pravo", "agent_ugovori"]),
    ("marketing", &["agent_marketing", "agent_seo"]),
    ("analitika", &["agent_analitika", "agent_report"]),
    ("podrska", &["agent_podrska", "agent_ticket"]),
    ("opste", &["agent_general"]),
];

const SENSITIVE_DOMAINS: [(&str, f64); 4] = [
    ("finansije", 0.25),
    ("racunovodstvo", 0.20),
    ("pravo", 0.30),
    ("kadrovi", 0.15),
];

// HIGH_RISK_PATTERNS — identično Pythonu; kompajlira se sa (?i).
// Rust regex crate: \b je Unicode word-boundary (kao Python), dok je Go RE2 ASCII.
// Na ovim ulazima razlika ne postoji (dokazano Go PASS-om), a Unicode \b je vjerniji Pythonu.
const HIGH_RISK_PATTERNS: [&str; 30] = [
    r"\bobrisi\b", r"\bdelete\b", r"\bdrop\b", r"\btruncate\b",
    r"\bformatiraj\b", r"\bprebrisi\b", r"\boverwrite\b",
    r"\bplati\b", r"\buplati\b", r"\btransfer\b", r"\bprenos\s+novc",
    r"\bpotpisi\b", r"\bsign\b", r"\bposalji\s+svima\b", r"\bbroadcast\b",
    r"\badmin\b", r"\broot\b", r"\bsudo\b", r"\bprod\b", r"\bdeploy\b",
    r"\bmailing\s+lista\b", r"\bizbrisi\s+bazu\b", r"\buninstall\b",
    r"\brm\s+-rf\b", r"\bshutdown\b", r"\breboot\b", r"\bpassword\b",
    r"\bsifra\b", r"\bprivatni\s+kljuc\b", r"\bprivate\s+key\b",
];

const MULTI_DOMAIN_MARKERS: [&str; 14] = [
    " i ", " te ", " zatim ", " nakon ", " kao i ", " plus ", " uz to ",
    "korak 1", "korak 2", "prvo", "drugo", "treće", "takođe", "pored",
];

// ---------------------------------------------------------------------------
// Pomoćne lookup funkcije (bez HashMap — determinizam)
// ---------------------------------------------------------------------------
fn agents_for(domain: &str) -> &'static [&'static str] {
    for (d, a) in DOMAIN_AGENTS.iter() {
        if *d == domain {
            return a;
        }
    }
    &["agent_general"]
}

fn sensitive_for(domain: &str) -> f64 {
    for (d, v) in SENSITIVE_DOMAINS.iter() {
        if *d == domain {
            return *v;
        }
    }
    0.0
}

// hit — stem/prefix match (identično Python _hit).
// Napomena: ključne riječi su čist ASCII, pa je len() u bajtima == broj znakova.
fn hit(kw: &str, txt: &str) -> bool {
    if txt.contains(kw) {
        return true;
    }
    for &l in [6usize, 5, 4].iter() {
        if kw.len() >= l {
            if let Some(prefix) = kw.get(..l) {
                if txt.contains(prefix) {
                    return true;
                }
            }
        }
    }
    false
}

fn first_n<'a>(s: &'a [&'a str], n: usize) -> &'a [&'a str] {
    if s.len() <= n {
        s
    } else {
        &s[..n]
    }
}

fn contains(v: &[String], x: &str) -> bool {
    v.iter().any(|s| s.as_str() == x)
}

// sliceSafe — safe[lo:hi] kao Python (clamp, prazno ako lo>=hi).
fn slice_safe(s: &[String], lo: usize, hi: usize) -> &[String] {
    let lo = lo.min(s.len());
    let hi = hi.min(s.len());
    if lo >= hi {
        return &[];
    }
    &s[lo..hi]
}

fn round4(x: f64) -> f64 {
    (x * 10000.0).round() / 10000.0
}

// ---------------------------------------------------------------------------
// Klasifikacija
// ---------------------------------------------------------------------------
struct Classification {
    domain: String,
    confidence: f64,
    scores: Vec<(String, f64)>, // uređeno po domainOrder (kao Python dict insertion)
    #[allow(dead_code)]
    matched_keywords: Vec<String>,
    multi_domain: bool,
}

fn classify(task: &str) -> Classification {
    let lowered = task.to_lowercase();
    let text = lowered.trim();
    if text.is_empty() {
        return Classification {
            domain: "opste".into(),
            confidence: 0.10,
            scores: vec![("opste".into(), 0.10)],
            matched_keywords: Vec::new(),
            multi_domain: false,
        };
    }

    let mut raw: Vec<(String, f64)> = Vec::new();
    let mut matched: Vec<(String, Vec<String>)> = Vec::new();

    for (domain, keywords) in DOMAIN_KEYWORDS.iter() {
        let mut hit_list: Vec<&str> = Vec::new();
        for kw in keywords.iter() {
            if hit(kw, text) {
                hit_list.push(kw);
            }
        }
        if !hit_list.is_empty() {
            let mut weight = 0.0f64;
            for (idx, _) in hit_list.iter().enumerate() {
                weight += 1.0 / (1.0 + 0.15 * idx as f64);
            }
            let sum_len: usize = hit_list.iter().map(|k| k.len()).sum();
            weight += 0.10 * sum_len as f64 / 10.0;
            raw.push(((*domain).to_string(), weight));
            matched.push((
                (*domain).to_string(),
                hit_list.iter().map(|k| (*k).to_string()).collect(),
            ));
        }
    }

    if raw.is_empty() {
        return Classification {
            domain: "opste".into(),
            confidence: 0.20,
            scores: vec![("opste".into(), 0.20)],
            matched_keywords: Vec::new(),
            multi_domain: false,
        };
    }

    let total: f64 = raw.iter().map(|(_, v)| *v).sum();
    let scores: Vec<(String, f64)> = raw.iter().map(|(d, v)| (d.clone(), v / total)).collect();

    // best_domain — deterministički tie-break po domainOrder (prvi max).
    let mut best_domain = String::new();
    let mut best_score = -1.0f64;
    for (d, s) in scores.iter() {
        if *s > best_score {
            best_score = *s;
            best_domain = d.clone();
        }
    }

    // runner-up (2. najveći)
    let mut vals: Vec<f64> = scores.iter().map(|(_, v)| *v).collect();
    vals.sort_by(|a, b| b.partial_cmp(a).unwrap());
    let second = if vals.len() > 1 { vals[1] } else { 0.0 };

    let mut confidence = 0.6 * best_score + 0.4 * (best_score - second) + 0.2;
    if confidence > 1.0 {
        confidence = 1.0;
    }
    if confidence < 0.0 {
        confidence = 0.0;
    }

    let mut marker_hits = 0usize;
    for m in MULTI_DOMAIN_MARKERS.iter() {
        if text.contains(m) {
            marker_hits += 1;
        }
    }
    let multi_domain = marker_hits >= 2 || (scores.len() >= 3 && confidence < PRAH_SINGLE);

    let matched_keywords = matched
        .iter()
        .find(|(d, _)| *d == best_domain)
        .map(|(_, v)| v.clone())
        .unwrap_or_default();

    Classification {
        domain: best_domain,
        confidence,
        scores,
        matched_keywords,
        multi_domain,
    }
}

const T1_PATTERNS: [&str; 12] = [
    r"rm\s+-rf\s*/", r"rm\s+-rf\s+~", r"rm\s+-rf\s+\*", r"format\s+[a-z]:",
    r"\bmkfs\b", r"\bdd\s+if=.*of=/dev/", r"drop\s+(table|database)",
    r"\btruncate\s+table", r"\bshutdown\b", r"\breboot\b",
    r"obrisi\s+(sve|citav|cijeli)", r"izbrisi\s+(sve|bazu|disk)",
];
const T2_PATTERNS: [&str; 12] = [
    r"obrisi\s+(fajl|folder|direktorij|log|datotek)", r"delete\s+(file|folder|all)",
    r"\brm\b", r"\bdrop\b", r"\btruncate\b", r"root\s+(pristup|bez)",
    r"ugasi\s+server", r"stop\s+all", r"killall", r"pkill\s+-9",
    r"chmod\s+777", r"chown\s+-R",
];
fn compiled(patterns: &[&str]) -> Vec<Regex> {
    patterns.iter().map(|p| Regex::new(&format!("(?i){}", p)).expect("regex compile")).collect()
}
fn t1_patterns() -> &'static [Regex] {
    static T1: OnceLock<Vec<Regex>> = OnceLock::new();
    T1.get_or_init(|| compiled(&T1_PATTERNS)).as_slice()
}
fn t2_patterns() -> &'static [Regex] {
    static T2: OnceLock<Vec<Regex>> = OnceLock::new();
    T2.get_or_init(|| compiled(&T2_PATTERNS)).as_slice()
}

// ---------------------------------------------------------------------------
// Rizik
// ---------------------------------------------------------------------------
fn assess_risk(high_risk: &[Regex], task: &str, domain: &str) -> f64 {
    // RISK_V2: T1/T2 + transfer boost; bez translita (Python zlatni standard).
    let text = task.to_lowercase();
    let mut risk: f64 = 0.0;
    for rx in t1_patterns() {
        if rx.is_match(&text) { risk = risk.max(0.9); }
    }
    for rx in t2_patterns() {
        if rx.is_match(&text) { risk = risk.max(0.7); }
    }
    let mut hits = 0usize;
    for rx in high_risk.iter() {
        if rx.is_match(&text) { hits += 1; }
    }
    risk = risk.max((hits as f64 * 0.35).min(0.75));
    risk += sensitive_for(domain);
    if domain == "finansije" && text.contains("transfer") {
        risk += 0.15;
    }
    risk.clamp(0.0, 1.0)
}

// ---------------------------------------------------------------------------
// Rutiranje
// ---------------------------------------------------------------------------
#[derive(Serialize, Clone)]
pub struct RouteResult {
    pub mode: String,
    pub agents: Vec<String>,
    pub reason: String,
    pub domain: String,
    pub confidence: f64,
    pub risk: f64,
    pub blocked: bool,
}

// classify_hint — classify + opcioni domain_hint (kao Python: raw[hint] += 2.0).
fn classify_hint(task: &str, domain_hint: Option<&str>) -> Classification {
    let mut cls = classify(task);
    if let Some(h) = domain_hint {
        if DOMAIN_AGENTS.iter().any(|(d, _)| *d == h) {
            // Dodaj +2.0 na raw skor pa ponovo normalizuj (vjerno Pythonu).
            // Rekonstrukcija: raw[i] = scores[i] * total. Dodaj hint pa normalizuj.
            let total: f64 = 1.0; // scores su već normalizovane; radimo relativno
            let _ = total;
            let mut found = false;
            for (d, s) in cls.scores.iter_mut() {
                if d == h {
                    *s += 2.0;
                    found = true;
                }
            }
            if !found {
                cls.scores.push((h.to_string(), 2.0));
            }
            // Renormalizuj
            let t: f64 = cls.scores.iter().map(|(_, v)| *v).sum();
            if t > 0.0 {
                for (_, v) in cls.scores.iter_mut() {
                    *v /= t;
                }
            }
            // Ponovo odredi best/confidence (isti algoritam kao classify).
            let mut best_domain = String::new();
            let mut best_score = -1.0f64;
            for (d, s) in cls.scores.iter() {
                if *s > best_score {
                    best_score = *s;
                    best_domain = d.clone();
                }
            }
            let mut vals: Vec<f64> = cls.scores.iter().map(|(_, v)| *v).collect();
            vals.sort_by(|a, b| b.partial_cmp(a).unwrap());
            let second = if vals.len() > 1 { vals[1] } else { 0.0 };
            let mut confidence = 0.6 * best_score + 0.4 * (best_score - second) + 0.2;
            confidence = confidence.clamp(0.0, 1.0);
            cls.domain = best_domain;
            cls.confidence = confidence;
        }
    }
    cls
}

// ---------------------------------------------------------------------------
// Router — javni API za CLI i sidecar
// ---------------------------------------------------------------------------
pub struct Router {
    high_risk: Vec<Regex>,
}

impl Router {
    pub fn new() -> Self {
        let high_risk: Vec<Regex> = HIGH_RISK_PATTERNS
            .iter()
            .map(|p| Regex::new(&format!("(?i){}", p)).expect("regex compile"))
            .collect();
        Router { high_risk }
    }

    /// Vrati rezultat kao serde_json::Value (za sidecar NDJSON).
    pub fn route_with(&self, task: &str, domain_hint: Option<&str>, risk: Option<f64>) -> Value {
        let res = route_full(&self.high_risk, task, domain_hint, risk);
        json!({
            "mode": res.mode,
            "agents": res.agents,
            "reason": res.reason,
            "domain": res.domain,
            "confidence": res.confidence,
            "risk": res.risk,
            "blocked": res.blocked,
        })
    }

    /// Vrati tipiziran rezultat (za CLI).
    pub fn route(&self, task: &str) -> RouteResult {
        route(&self.high_risk, task)
    }
}

// rankedDomains — domeni sortirani po skoru opadajuće; tie-break po domainOrder.
// scores je već u domainOrder; Rust sort_by je stabilan => identično Pythonu.
fn ranked_domains(scores: &[(String, f64)]) -> Vec<String> {
    let mut items: Vec<(String, f64)> = scores.to_vec();
    items.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    items.into_iter().map(|(d, _)| d).collect()
}

fn route(high_risk: &[Regex], task: &str) -> RouteResult {
    route_full(high_risk, task, None, None)
}

// route_full — kao Python route(task, embedding, domain_hint, risk).
// domain_hint pojačava domen (+2.0), risk override-uje procjenu.
fn route_full(
    high_risk: &[Regex],
    task: &str,
    domain_hint: Option<&str>,
    risk_override: Option<f64>,
) -> RouteResult {
    let cls = classify_hint(task, domain_hint);
    let risk_val = match risk_override {
        Some(r) => r.clamp(0.0, 1.0),
        None => assess_risk(high_risk, task, &cls.domain).clamp(0.0, 1.0),
    };
    let primary = agents_for(&cls.domain);

    // 1) HARD-BLOCK
    if risk_val >= RISK_HARD_BLOCK {
        return RouteResult {
            mode: "single".into(),
            agents: Vec::new(),
            reason: format!(
                "HARD-BLOCK: rizik={:.2} >= {:.2} (domen={}). Zadr'zano na ljudsku verifikaciju prije izvršenja.",
                risk_val, RISK_HARD_BLOCK, cls.domain
            ),
            domain: cls.domain,
            confidence: round4(cls.confidence),
            risk: round4(risk_val),
            blocked: true,
        };
    }

    // 2) SINGLE
    if cls.confidence >= PRAH_SINGLE {
        return RouteResult {
            mode: "single".into(),
            agents: vec![primary[0].to_string()],
            reason: format!(
                "Visoka pouzdanost={:.2} >= {:.2} za domen={}; jedan nosivi agent je dovoljan.",
                cls.confidence, PRAH_SINGLE, cls.domain
            ),
            domain: cls.domain,
            confidence: round4(cls.confidence),
            risk: round4(risk_val),
            blocked: false,
        };
    }

    // 3) GROUP
    if cls.confidence >= PRAH_GROUP {
        let mut agents: Vec<String> = Vec::new();
        if primary.len() >= 2 {
            agents.push(primary[0].to_string());
            agents.push(primary[1].to_string());
        } else {
            for a in primary.iter() {
                agents.push((*a).to_string());
            }
        }
        if cls.multi_domain && cls.scores.len() > 1 {
            let rk = ranked_domains(&cls.scores);
            if rk.len() > 1 {
                let second_domain = &rk[1];
                let da = agents_for(second_domain);
                for &a in first_n(da, 1) {
                    if !contains(&agents, a) {
                        agents.push(a.to_string());
                    }
                }
            }
        }
        let mut reason = format!(
            "Srednja pouzdanost={:.2} u [{:.2},{:.2}); angažuje se grupa agenata za domen={}",
            cls.confidence, PRAH_GROUP, PRAH_SINGLE, cls.domain
        );
        if cls.multi_domain {
            reason.push_str(" (multi-domen)");
        }
        return RouteResult {
            mode: "group".into(),
            agents,
            reason,
            domain: cls.domain,
            confidence: round4(cls.confidence),
            risk: round4(risk_val),
            blocked: false,
        };
    }

    // 4) SWARM
    let mut agents: Vec<String> = primary.iter().map(|a| (*a).to_string()).collect();
    let ranked = ranked_domains(&cls.scores);
    for d in slice_safe(&ranked, 1, 3) {
        let da = agents_for(d);
        for &a in first_n(da, 1) {
            if !contains(&agents, a) {
                agents.push(a.to_string());
            }
        }
    }
    RouteResult {
        mode: "swarm".into(),
        agents,
        reason: format!(
            "Niska pouzdanost={:.2} < {:.2}; zadatak je neodređen/širok te se pokreće Roj agenata (domen≈{}).",
            cls.confidence, PRAH_GROUP, cls.domain
        ),
        domain: cls.domain,
        confidence: round4(cls.confidence),
        risk: round4(risk_val),
        blocked: false,
    }
}

// (ranije main() — sada je CLI u main.rs, sidecar u sidecar.rs)
