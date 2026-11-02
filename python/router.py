#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
router.py — gamAI Mozak: Router (klasifikacija domena + rutiranje izvršavanja)
=============================================================================

Ovaj modul implementira ``Router`` klasu koja radi dvije stvari:

1. **Klasifikacija** — na osnovu teksta zadatka (``task``) i opcionih signala
   (embedding, keyword hintovi, risk skor) određuje **domen** zadatka.
2. **Rutiranje** — na osnovu klasifikacije i procjene rizika bira **režim
   izvršavanja** (``single`` | ``group`` | ``swarm``) i listu agenata koji će
   zadatak izvršiti.

Pragovi odlučivanja
-------------------
* ``PRAH_SINGLE = 0.62`` — pouzdanost (confidence) iznad ovog praga → jedan agent.
* ``PRAH_GROUP  = 0.38`` — pouzdanost u opsegu ``[0.38, 0.62)`` → grupa agenata.
* pouzdanost ispod ``0.38`` → ``swarm`` (rojem, široka podrška).
* ``RISK_HARD_BLOCK = 0.85`` — ako je ``risk >= 0.85`` zadatak se **hard-blocka**
  (bez izvršavanja dok čovjek ne odobri).

Dizajn je deterministički i bez vanjskih zavisnosti (samo stdlib) da bi bio
lako testiran i predvidiv u produkciji.
"""

from __future__ import annotations

import re
import math
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


# ---------------------------------------------------------------------------
# Konstante / pragovi
# ---------------------------------------------------------------------------

PRAH_SINGLE: float = 0.62
"""Prag pouzdanosti iznad kojeg se zadatak rutira na JEDNOG agenta."""

PRAH_GROUP: float = 0.38
"""Prag pouzdanosti iznad kojeg (a ispod PRAH_SINGLE) se koristi GRUPA agenata."""

RISK_HARD_BLOCK: float = 0.85
"""Ako je procijenjeni rizik >= ove vrijednosti, zadatak se HARD-BLOCKA."""


# ---------------------------------------------------------------------------
# Definicije domena i pripadajućih agenata
# ---------------------------------------------------------------------------

#: Mapa domen -> lista agenata koji su primarni nosioci tog domena.
DOMAIN_AGENTS: Dict[str, List[str]] = {
    "prodaja":        ["agent_prodaja", "agent_ponuda"],
    "nabavka":        ["agent_nabavka", "agent_dobavljac"],
    "finansije":      ["agent_finansije", "agent_fakture", "agent_knjizenje"],
    "racunovodstvo":  ["agent_knjizenje", "agent_pdv", "agent_bilans"],
    "logistika":      ["agent_logistika", "agent_zalihe"],
    "magacin":        ["agent_zalihe", "agent_magacin"],
    "kadrovi":        ["agent_kadrovi", "agent_plate"],
    "it":             ["agent_it", "agent_ops"],
    "kod":            ["agent_kod", "agent_review"],
    "pravo":          ["agent_pravo", "agent_ugovori"],
    "marketing":      ["agent_marketing", "agent_seo"],
    "analitika":      ["agent_analitika", "agent_report"],
    "podrska":        ["agent_podrska", "agent_ticket"],
    "opste":          ["agent_general"],
}

#: Keyword signali po domenu. Težine se sabiraju pri skorovanju.
DOMAIN_KEYWORDS: Dict[str, List[str]] = {
    "prodaja":       ["kupac", "prodaja", "ponuda", "narudzba", "cjenovnik",
                       "popust", "klijent", "lead", "deal", "cijena"],
    "nabavka":       ["nabavka", "dobavljac", "ulazna", "porudzbina", "supplier",
                       "naruciti", "kolicina", "veleprodaja"],
    "finansije":     ["faktura", "racun", "uplata", "isplata", "dugovanje",
                       "likvidnost", "kredit", "kamat", "saldo", "placanje"],
    "racunovodstvo": ["knjizenje", "pdv", "porez", "bilans", "kontiranje",
                       "konto", "amortizacija", "prijava", "obracun"],
    "logistika":     ["dostava", "transport", "vozilo", "ruta", "isporuka",
                       "posiljka", "kamion", "otpremnica"],
    "magacin":       ["magacin", "zaliha", "lager", "skladiste", "inventar",
                       "ulaz", "izlaz", "artikal", "sifra"],
    "kadrovi":       ["radnik", "zaposleni", "kadrovi", "ugovor o radu",
                       "godisnji", "odmor", "plata", "zaposljavanje", "cv"],
    "it":            ["server", "mreza", "baza", "backup", "sistem", "infra",
                       "sigurnost", "login", "pristup", "vpn"],
    "kod":           ["kod", "program", "funkcija", "bug", "debug", "refactor",
                       "python", "api", "skripta", "compile", "test"],
    "pravo":         ["ugovor", "zakon", "pravni", "tuzba", "regulativa",
                       "gdpr", "obaveza", "klauzula", "rok"],
    "marketing":     ["marketing", "kampanja", "seo", "reklama", "brend",
                       "objava", "drustvene mreze", "reels", "tekst oglasa"],
    "analitika":     ["analiza", "izvjestaj", "report", "statistika", "kpi",
                       "trend", "grafikon", "dashboard", "metrika"],
    "podrska":       ["podrska", "ticket", "zalba", "pomoc", "problem",
                       "korisnik pita", "reklamacija", "support"],
}

#: Domeni koji su po prirodi visoko-osjetljivi (podigni risk baseline).
SENSITIVE_DOMAINS: Dict[str, float] = {
    "finansije": 0.25,
    "racunovodstvo": 0.20,
    "pravo": 0.30,
    "kadrovi": 0.15,
}

#: Riječi koje signaliziraju visok rizik (destruktivne / nepovratne akcije).
HIGH_RISK_PATTERNS: List[str] = [
    r"\bobrisi\b", r"\bdelete\b", r"\bdrop\b", r"\btruncate\b",
    r"\bformatiraj\b", r"\bprebrisi\b", r"\boverwrite\b",
    r"\bplati\b", r"\buplati\b", r"\btransfer\b", r"\bprenos\s+novc", 
    r"\bpotpisi\b", r"\bsign\b", r"\bposalji\s+svima\b", r"\bbroadcast\b",
    r"\badmin\b", r"\broot\b", r"\bsudo\b", r"\bprod\b", r"\bdeploy\b",
    r"\bmailing\s+lista\b", r"\bizbrisi\s+bazu\b", r"\buninstall\b",
    r"\brm\s+-rf\b", r"\bshutdown\b", r"\breboot\b", r"\bpassword\b",
    r"\bsifra\b", r"\bprivatni\s+kljuc\b", r"\bprivate\s+key\b",
]

#: RISK_MODEL=v2 — T1 katastrofalno / T2 visoko (usklađeno sa Rust RISK_CALIB_V1).
T1_PATTERNS: List[str] = [
    r"rm\s+-rf\s*/", r"rm\s+-rf\s+~", r"rm\s+-rf\s+\*", r"format\s+[a-z]:",
    r"\bmkfs\b", r"\bdd\s+if=.*of=/dev/", r"drop\s+(table|database)",
    r"\btruncate\s+table", r"\bshutdown\b", r"\breboot\b",
    r"obrisi\s+(sve|citav|cijeli)", r"izbrisi\s+(sve|bazu|disk)",
]
T2_PATTERNS: List[str] = [
    r"obrisi\s+(fajl|folder|direktorij|log|datotek)", r"delete\s+(file|folder|all)",
    r"\brm\b", r"\bdrop\b", r"\btruncate\b", r"root\s+(pristup|bez)",
    r"ugasi\s+server", r"stop\s+all", r"killall", r"pkill\s+-9",
    r"chmod\s+777", r"chown\s+-R",
]

#: Riječi koje signaliziraju da je zadatak kompleksan/multi-domen.
MULTI_DOMAIN_MARKERS: List[str] = [
    " i ", " te ", " zatim ", " nakon ", " kao i ", " plus ", " uz to ",
    "korak 1", "korak 2", "prvo", "drugo", "treće", "takođe", "pored",
]


# ---------------------------------------------------------------------------
# Pomoćne strukture
# ---------------------------------------------------------------------------

@dataclass
class Classification:
    """Rezultat klasifikacije zadatka.

    Attributes:
        domain: Primarni (najvjerovatniji) domen zadatka.
        confidence: Pouzdanost klasifikacije u opsegu ``[0.0, 1.0]``.
        scores: Normalizovani skorovi svih domena.
        matched_keywords: Ključne riječi koje su pogodile primarni domen.
        multi_domain: Da li zadatak dotiče više domena.
    """
    domain: str
    confidence: float
    scores: Dict[str, float] = field(default_factory=dict)
    matched_keywords: List[str] = field(default_factory=list)
    multi_domain: bool = False

    def as_dict(self) -> Dict[str, Any]:
        """Vrati serijalizovanu (JSON-friendly) reprezentaciju."""
        return {
            "domain": self.domain,
            "confidence": round(self.confidence, 4),
            "scores": {k: round(v, 4) for k, v in self.scores.items()},
            "matched_keywords": list(self.matched_keywords),
            "multi_domain": self.multi_domain,
        }


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

class Router:
    """Klasifikuje zadatke po domenu i rutira ih ka agentima.

    Klasa je namjerno bez stanja (stateless) osim konfiguracije pragova, tako
    da je sigurna za paralelno korišćenje.

    Primjer:
        >>> r = Router()
        >>> r.classify("Napravi ponudu za kupca XY i pošalji fakturu")
        Classification(domain='prodaja', ...)
        >>> r.route("Obriši bazu i pošalji svima mail")
        {'mode': 'single', 'agents': [], 'reason': 'hard-block ...'}

    Args:
        prag_single: Prag pouzdanosti za režim ``single`` (default 0.62).
        prag_group: Prag pouzdanosti za režim ``group`` (default 0.38).
        risk_hard_block: Rizik iznad kojeg se zadatak hard-blocka (default 0.85).
    """

    def __init__(
        self,
        prag_single: float = PRAH_SINGLE,
        prag_group: float = PRAH_GROUP,
        risk_hard_block: float = RISK_HARD_BLOCK,
        risk_model: str = "v1",
    ) -> None:
        if not (0.0 <= prag_group <= prag_single <= 1.0):
            raise ValueError(
                "Pragovi moraju zadovoljiti 0 <= prag_group <= prag_single <= 1"
            )
        if not (0.0 <= risk_hard_block <= 1.0):
            raise ValueError("risk_hard_block mora biti u opsegu [0, 1]")

        self.prag_single = float(prag_single)
        self.prag_group = float(prag_group)
        self.risk_hard_block = float(risk_hard_block)
        if risk_model not in ("v1", "v2"):
            raise ValueError("risk_model mora biti 'v1' ili 'v2'")
        self.risk_model = risk_model

        self._high_risk_re = [re.compile(p, re.IGNORECASE) for p in HIGH_RISK_PATTERNS]
        self._t1_re = [re.compile(p, re.IGNORECASE) for p in T1_PATTERNS]
        self._t2_re = [re.compile(p, re.IGNORECASE) for p in T2_PATTERNS]

    # ------------------------------------------------------------------
    # Klasifikacija
    # ------------------------------------------------------------------

    def classify(
        self,
        task: str,
        embedding: Optional[Sequence[float]] = None,
        domain_hint: Optional[str] = None,
    ) -> Classification:
        """Klasifikuj ``task`` i vrati :class:`Classification`.

        Metoda kombinuje tri signala:
          1. keyword pogotke po domenu (težinski),
          2. opcioni ``domain_hint`` (eksplicitna želja korisnika),
          3. opcioni ``embedding`` (rezervisan za semantičku sličnost; ako je
             dat, blago pojačava postojeće skorove proporcionalno normi).

        Args:
            task: Tekst zadatka (prirodni jezik).
            embedding: Opcioni vektor zadatka (npr. iz ``embed`` alata).
            domain_hint: Opcioni eksplicitni domen koji treba pojačati.

        Returns:
            :class:`Classification` sa primarnim domenom i pouzdanošću.
        """
        text = (task or "").lower().strip()
        if not text:
            return Classification(domain="opste", confidence=0.10,
                                  scores={"opste": 0.10})

        raw: Dict[str, float] = {}
        matched: Dict[str, List[str]] = {}

        # Stem/prefix match: "ponudu"/"ponude" pogadja "ponuda" (korijen).
        def _hit(kw, txt):
            if kw in txt:
                return True
            # stem prvih 5 znakova pokriva padeze: ponud(a/u/e/i), kupc(a/e/i), zali(ha/he)
            for L in (6, 5, 4):
                if len(kw) >= L:
                    if kw[:L] in txt:
                        return True
            return False

        for domain, keywords in DOMAIN_KEYWORDS.items():
            hit_list = [kw for kw in keywords if _hit(kw, text)]
            if hit_list:
                # Svaki pogodak nosi težinu; prvi pogoci su najjači signal.
                weight = sum(1.0 / (1.0 + 0.15 * idx) for idx, _ in enumerate(hit_list))
                # Duže (specifičnije) ključne riječi nose veću težinu.
                weight += 0.10 * sum(len(kw) for kw in hit_list) / 10.0
                raw[domain] = raw.get(domain, 0.0) + weight
                matched[domain] = hit_list

        # Blago pojačanje kroz embedding (norma vektora kao proxy za "signal").
        if embedding:
            try:
                norm = math.sqrt(sum(float(x) * float(x) for x in embedding))
                boost = min(0.15, norm / (1.0 + norm) * 0.2)
                if raw:
                    top = max(raw, key=lambda k: raw[k])
                    raw[top] += boost
            except (TypeError, ValueError):
                pass

        # Eksplicitni hint.
        if domain_hint and domain_hint in DOMAIN_AGENTS:
            raw[domain_hint] = raw.get(domain_hint, 0.0) + 2.0

        if not raw:
            return Classification(domain="opste", confidence=0.20,
                                  scores={"opste": 0.20})

        # Normalizacija (softmax-like) da dobijemo pouzdanost u [0,1].
        total = sum(raw.values())
        scores = {d: v / total for d, v in raw.items()}

        best_domain = max(scores, key=lambda k: scores[k])
        best_score = scores[best_domain]
        runner_up = sorted(scores.values(), reverse=True)
        second = runner_up[1] if len(runner_up) > 1 else 0.0

        # Pouzdanost: sam skor + margina nad drugim domenom.
        confidence = min(1.0, 0.6 * best_score + 0.4 * (best_score - second) + 0.2)
        confidence = max(0.0, confidence)

        # Multi-domen detekcija (kompleksnost / više veznika).
        marker_hits = sum(1 for m in MULTI_DOMAIN_MARKERS if m in text)
        multi_domain = (marker_hits >= 2) or (len(scores) >= 3 and confidence < self.prag_single)

        return Classification(
            domain=best_domain,
            confidence=confidence,
            scores=scores,
            matched_keywords=matched.get(best_domain, []),
            multi_domain=multi_domain,
        )

    # ------------------------------------------------------------------
    # Rizik
    # ------------------------------------------------------------------

    def assess_risk(self, task: str, domain: str) -> float:
        """Procijeni rizik zadatka u opsegu ``[0.0, 1.0]``.

        Kombinuje:
          * broj destruktivnih/opasnih obrazaca u tekstu,
          * osjetljivost domena (baseline podizanje).

        Args:
            task: Tekst zadatka.
            domain: Klasifikovani domen.

        Returns:
            Rizik kao float u ``[0.0, 1.0]``.
        """
        text = (task or "").lower()
        hits = sum(1 for rx in self._high_risk_re if rx.search(text))

        if self.risk_model == "v2":
            risk = 0.0
            for rx in self._t1_re:
                if rx.search(text):
                    risk = max(risk, 0.9)
            for rx in self._t2_re:
                if rx.search(text):
                    risk = max(risk, 0.7)
            risk = max(risk, min(0.75, hits * 0.35))
            risk += SENSITIVE_DOMAINS.get(domain, 0.0)
            if domain == "finansije" and "transfer" in text:
                risk += 0.15
            return max(0.0, min(1.0, risk))

        risk = 0.0
        # Svaki destruktivni obrazac nosi značajan rizik.
        risk += min(0.75, hits * 0.35)
        # Osjetljivi domeni podižu baseline.
        risk += SENSITIVE_DOMAINS.get(domain, 0.0)
        # "svima"/"baza"/"brisanje" u kombinaciji → dodatni boost.
        if hits >= 2:
            risk += 0.15

        return max(0.0, min(1.0, risk))

    # ------------------------------------------------------------------
    # Rutiranje
    # ------------------------------------------------------------------

    def route(
        self,
        task: str,
        embedding: Optional[Sequence[float]] = None,
        domain_hint: Optional[str] = None,
        risk: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Rutiraj zadatak i vrati odluku o izvršavanju.

        Logika:
          1. Klasifikuj zadatak → domen + pouzdanost.
          2. Procijeni rizik (osim ako nije eksplicitno zadan).
          3. Ako je ``risk >= risk_hard_block`` → **hard-block** (mode single,
             prazna lista agenata, reason objašnjava blok).
          4. Inače po pragovima:
             - ``confidence >= prag_single`` → ``single`` (1 agent),
             - ``confidence >= prag_group``  → ``group`` (primarni tim),
             - inače                          → ``swarm`` (široki set agenata).

        Args:
            task: Tekst zadatka.
            embedding: Opcioni embedding zadatka.
            domain_hint: Opcioni eksplicitni domen.
            risk: Opcioni unaprijed izračunat rizik (0..1); ako nije dat računa se.

        Returns:
            Dict sa ključevima:
              * ``mode``: ``'single' | 'group' | 'swarm'``
              * ``agents``: lista imena agenata
              * ``reason``: tekstualno objašnjenje odluke
              * ``domain``, ``confidence``, ``risk``: dijagnostika
        """
        cls = self.classify(task, embedding=embedding, domain_hint=domain_hint)
        risk_val = self.assess_risk(task, cls.domain) if risk is None else float(risk)
        risk_val = max(0.0, min(1.0, risk_val))

        primary = DOMAIN_AGENTS.get(cls.domain, DOMAIN_AGENTS["opste"])

        # 1) HARD-BLOCK ----------------------------------------------------
        if risk_val >= self.risk_hard_block:
            return {
                "mode": "single",
                "agents": [],
                "reason": (
                    f"HARD-BLOCK: rizik={risk_val:.2f} >= {self.risk_hard_block:.2f} "
                    f"(domen={cls.domain}). Zadr\'zano na ljudsku verifikaciju prije izvršenja."
                ),
                "domain": cls.domain,
                "confidence": round(cls.confidence, 4),
                "risk": round(risk_val, 4),
                "blocked": True,
            }

        # 2) SINGLE --------------------------------------------------------
        if cls.confidence >= self.prag_single:
            return {
                "mode": "single",
                "agents": [primary[0]],
                "reason": (
                    f"Visoka pouzdanost={cls.confidence:.2f} >= {self.prag_single:.2f} "
                    f"za domen={cls.domain}; jedan nosivi agent je dovoljan."
                ),
                "domain": cls.domain,
                "confidence": round(cls.confidence, 4),
                "risk": round(risk_val, 4),
                "blocked": False,
            }

        # 3) GROUP ---------------------------------------------------------
        if cls.confidence >= self.prag_group:
            agents = list(primary[:2]) if len(primary) >= 2 else list(primary)
            # Ako je multi-domen, dodaj sekundarnog agenta iz 2. najboljeg domena.
            if cls.multi_domain and len(cls.scores) > 1:
                second_domain = sorted(cls.scores, key=lambda d: cls.scores[d],
                                        reverse=True)[1]
                for a in DOMAIN_AGENTS.get(second_domain, [])[:1]:
                    if a not in agents:
                        agents.append(a)
            return {
                "mode": "group",
                "agents": agents,
                "reason": (
                    f"Srednja pouzdanost={cls.confidence:.2f} u [{self.prag_group:.2f},"
                    f"{self.prag_single:.2f}); angažuje se grupa agenata za domen={cls.domain}"
                    + (" (multi-domen)" if cls.multi_domain else "")
                ),
                "domain": cls.domain,
                "confidence": round(cls.confidence, 4),
                "risk": round(risk_val, 4),
                "blocked": False,
            }

        # 4) SWARM ---------------------------------------------------------
        agents = list(primary)
        # U roju dodaj po jednog agenta iz još 2 domena (ako postoje).
        ranked = sorted(cls.scores, key=lambda d: cls.scores[d], reverse=True)
        for d in ranked[1:3]:
            for a in DOMAIN_AGENTS.get(d, [])[:1]:
                if a not in agents:
                    agents.append(a)
        return {
            "mode": "swarm",
            "agents": agents,
            "reason": (
                f"Niska pouzdanost={cls.confidence:.2f} < {self.prag_group:.2f}; "
                f"zadatak je neodređen/širok te se pokreće Roj agenata (domen≈{cls.domain})."
            ),
            "domain": cls.domain,
            "confidence": round(cls.confidence, 4),
            "risk": round(risk_val, 4),
            "blocked": False,
        }

    # ------------------------------------------------------------------
    # Batch pomoćna metoda
    # ------------------------------------------------------------------

    def route_many(self, tasks: Iterable[str]) -> List[Dict[str, Any]]:
        """Rutiraj više zadataka odjednom.

        Args:
            tasks: Iterable tekstova zadataka.

        Returns:
            Lista rezultata :meth:`route`, u istom redu.
        """
        return [self.route(t) for t in tasks]


# ---------------------------------------------------------------------------
# CLI / self-test
# ---------------------------------------------------------------------------

def _demo() -> None:
    """Brzi samotest i demonstracija rada routera."""
    router = Router()
    primjeri: List[str] = [
        "Napravi ponudu za kupca ABC i pošalji fakturu",
        "baci pogled na magacin i reci koliko imamo na lageru",
        "Analiziraj trendove prodaje i napravi izvještaj za KPI dashboard",
        "nešto nejasno i općenito, ne znam tačno šta treba",
        "Obriši bazu podataka i pošalji svima mail sa novom šifrom",
        "Napiši python funkciju koja parsira CSV i napravi unit test",
    ]
    for t in primjeri:
        out = router.route(t)
        print(f"• {t!r}")
        print(f"    → mode={out['mode']} agents={out['agents']} "
              f"domain={out['domain']} conf={out['confidence']} risk={out['risk']}")
        print(f"      reason: {out['reason']}")
        print()


if __name__ == "__main__":
    _demo()
