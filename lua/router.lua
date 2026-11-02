#!/usr/bin/env luajit
-- router.lua — risk-calib hybrid: LuaJIT verzija router.py (vjerna kopija).
--
-- Ulaz:  -in <inputs.json>  (JSON array stringova)  ILI stdin (JSON array / linije)
-- Izlaz: JSON array rezultata route() — isti format kao Python/Go/Rust.
--
-- Rezimi:  luajit router.lua -in fixtures/inputs.json
--          luajit router.lua -bench -n 10000 -in fixtures/inputs.json
--
-- Determinizam: umjesto map-a koristimo uređene liste po DOMAIN_KEYWORDS redu
-- (identicno Python insertion redu), pa su sume i tie-break identicni.

local ffi = nil  -- ne treba; cisti LuaJIT

-- ---------------------------------------------------------------------------
-- JSON mini (bez zavisnosti: dovoljno za nas format)
-- ---------------------------------------------------------------------------
local json = {}

local function escape(s)
  s = s:gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n')
       :gsub('\r', '\\r'):gsub('\t', '\\t')
  return s
end

function json.encode(v)
  local t = type(v)
  if t == "nil" then return "null"
  elseif t == "boolean" then return v and "true" or "false"
  elseif t == "number" then
    if v == math.floor(v) and math.abs(v) < 1e15 then
      return string.format("%d", math.floor(v + 0.5))
    end
    -- izbjegni -0 i tacku-locale
    local s = string.format("%.4f", v)
    -- skini suvisne nule
    s = s:gsub("0+$", ""):gsub("%.$", "")
    if s == "-0" then s = "0" end
    return s
  elseif t == "string" then return '"' .. escape(v) .. '"'
  elseif t == "table" then
    -- niz ili objekt?
    local n = #v
    local is_arr = n > 0
    if n == 0 then
      -- prazna tabela: ako nema kljuceva -> niz [] (kao Python lista)
      local has_keys = false
      for _ in pairs(v) do has_keys = true; break end
      if has_keys then is_arr = false else is_arr = true end
    else
      is_arr = true
    end
    if is_arr then
      local parts = {}
      for i = 1, #v do parts[i] = json.encode(v[i]) end
      return "[" .. table.concat(parts, ",") .. "]"
    else
      -- objekt: sortiraj kljuceve (determinizam)
      local keys = {}
      for k, _ in pairs(v) do keys[#keys + 1] = k end
      table.sort(keys)
      local parts = {}
      for i, k in ipairs(keys) do
        parts[i] = '"' .. escape(tostring(k)) .. '":' .. json.encode(v[k])
      end
      return "{" .. table.concat(parts, ",") .. "}"
    end
  end
  return "null"
end

-- Dekoder (dovoljno za array stringova i nase objekte)
local function skip_ws(s, i)
  while i <= #s do
    local c = s:sub(i, i)
    if c == " " or c == "\t" or c == "\n" or c == "\r" then i = i + 1 else break end
  end
  return i
end

local parse_value

local function parse_string(s, i)
  -- ocekuje se 'i' na '"'
  i = i + 1
  local buf = {}
  while i <= #s do
    local c = s:sub(i, i)
    if c == '"' then return table.concat(buf), i + 1
    elseif c == "\\" then
      local n = s:sub(i + 1, i + 1)
      local map = {n = "\n", t = "\t", r = "\r", ['"'] = '"', ["\\"] = "\\", ["/"] = "/"}
      if n == "u" then
        local hex = s:sub(i + 2, i + 5)
        local code = tonumber(hex, 16)
        -- UTF-8 encode (osnovno)
        if code < 0x80 then buf[#buf + 1] = string.char(code)
        elseif code < 0x800 then
          buf[#buf + 1] = string.char(0xC0 + math.floor(code / 64), 0x80 + code % 64)
        else
          buf[#buf + 1] = string.char(0xE0 + math.floor(code / 4096),
            0x80 + math.floor(code / 64) % 64, 0x80 + code % 64)
        end
        i = i + 6
      else
        buf[#buf + 1] = map[n] or n
        i = i + 2
      end
    else
      buf[#buf + 1] = c
      i = i + 1
    end
  end
  error("unterminated string")
end

parse_value = function(s, i)
  i = skip_ws(s, i)
  local c = s:sub(i, i)
  if c == '"' then return parse_string(s, i)
  elseif c == "[" then
    local arr = {}
    i = i + 1
    i = skip_ws(s, i)
    if s:sub(i, i) == "]" then return arr, i + 1 end
    while true do
      local v; v, i = parse_value(s, i)
      arr[#arr + 1] = v
      i = skip_ws(s, i)
      local ch = s:sub(i, i)
      if ch == "," then i = i + 1
      elseif ch == "]" then return arr, i + 1
      else error("bad array at " .. i) end
    end
  elseif c == "{" then
    local obj = {}
    i = i + 1
    i = skip_ws(s, i)
    if s:sub(i, i) == "}" then return obj, i + 1 end
    while true do
      local k; k, i = parse_string(s, i)
      i = skip_ws(s, i)
      i = i + 1 -- ':'
      local v; v, i = parse_value(s, i)
      obj[k] = v
      i = skip_ws(s, i)
      local ch = s:sub(i, i)
      if ch == "," then i = i + 1
      elseif ch == "}" then return obj, i + 1
      else error("bad object at " .. i) end
    end
  elseif s:sub(i, i + 3) == "true" then return true, i + 4
  elseif s:sub(i, i + 4) == "false" then return false, i + 5
  elseif s:sub(i, i + 3) == "null" then return nil, i + 4
  else
    local num = s:match("^-?%d+%.?%d*[eE]?[-+]?%d*", i)
    if num and #num > 0 then return tonumber(num), i + #num end
    error("bad value at " .. i)
  end
end

function json.decode(s)
  local v, _ = parse_value(s, 1)
  return v
end

-- ---------------------------------------------------------------------------
-- Router (1:1 prema Python/Go/Rust)
-- ---------------------------------------------------------------------------
local PRAH_SINGLE = 0.62
local PRAH_GROUP = 0.38
local RISK_HARD_BLOCK = 0.85

local DOMAIN_KEYWORDS = {
  {"prodaja", {"kupac","prodaja","ponuda","narudzba","cjenovnik","popust","klijent","lead","deal","cijena"}},
  {"nabavka", {"nabavka","dobavljac","ulazna","porudzbina","supplier","naruciti","kolicina","veleprodaja"}},
  {"finansije", {"faktura","racun","uplata","isplata","dugovanje","likvidnost","kredit","kamat","saldo","placanje"}},
  {"racunovodstvo", {"knjizenje","pdv","porez","bilans","kontiranje","konto","amortizacija","prijava","obracun"}},
  {"logistika", {"dostava","transport","vozilo","ruta","isporuka","posiljka","kamion","otpremnica"}},
  {"magacin", {"magacin","zaliha","lager","skladiste","inventar","ulaz","izlaz","artikal","sifra"}},
  {"kadrovi", {"radnik","zaposleni","kadrovi","ugovor o radu","godisnji","odmor","plata","zaposljavanje","cv"}},
  {"it", {"server","mreza","baza","backup","sistem","infra","sigurnost","login","pristup","vpn"}},
  {"kod", {"kod","program","funkcija","bug","debug","refactor","python","api","skripta","compile","test"}},
  {"pravo", {"ugovor","zakon","pravni","tuzba","regulativa","gdpr","obaveza","klauzula","rok"}},
  {"marketing", {"marketing","kampanja","seo","reklama","brend","objava","drustvene mreze","reels","tekst oglasa"}},
  {"analitika", {"analiza","izvjestaj","report","statistika","kpi","trend","grafikon","dashboard","metrika"}},
  {"podrska", {"podrska","ticket","zalba","pomoc","problem","korisnik pita","reklamacija","support"}},
}

local DOMAIN_AGENTS = {
  ["prodaja"]={"agent_prodaja","agent_ponuda"},
  ["nabavka"]={"agent_nabavka","agent_dobavljac"},
  ["finansije"]={"agent_finansije","agent_fakture","agent_knjizenje"},
  ["racunovodstvo"]={"agent_knjizenje","agent_pdv","agent_bilans"},
  ["logistika"]={"agent_logistika","agent_zalihe"},
  ["magacin"]={"agent_zalihe","agent_magacin"},
  ["kadrovi"]={"agent_kadrovi","agent_plate"},
  ["it"]={"agent_it","agent_ops"},
  ["kod"]={"agent_kod","agent_review"},
  ["pravo"]={"agent_pravo","agent_ugovori"},
  ["marketing"]={"agent_marketing","agent_seo"},
  ["analitika"]={"agent_analitika","agent_report"},
  ["podrska"]={"agent_podrska","agent_ticket"},
  ["opste"]={"agent_general"},
}

local SENSITIVE = {finansije=0.25, racunovodstvo=0.20, pravo=0.30, kadrovi=0.15}

-- High-risk pattern — isti kao Python HIGH_RISK_PATTERNS (ukljucuje fraze i \s+).
-- Svaki element: lista alternativa (radi kao Python regex sa \b granicom).
local HIGH_RISK = {
  "obrisi", "delete", "drop", "truncate",
  "formatiraj", "prebrisi", "overwrite",
  "plati", "uplati", "transfer", "prenos novc",
  "potpisi", "sign", "posalji svima", "broadcast",
  "admin", "root", "sudo", "prod", "deploy",
  "mailing lista", "izbrisi bazu", "uninstall",
  "rm -rf", "shutdown", "reboot", "password",
  "sifra", "privatni kljuc", "private key",
}

local MULTI_MARKERS = {" i "," te "," zatim "," nakon "," kao i "," plus "," uz to ",
  "korak 1","korak 2","prvo","drugo","tre\u{0107}e","tako\u{0111}e","pored"}

-- helper: da li riječ (kao cijela) postoji — ASCII aproksimacija \b
local function word_hit(w, text)
  -- granica: non-alnum oko rijeci/fraze (ASCII aproksimacija \b; \s+ -> space)
  -- fraze ("posalji svima", "rm -rf") tretira kao doslovni podstring sa granicama.
  local init = 1
  while true do
    local s, e = text:find(w, init, true)
    if not s then return false end
    local before = (s == 1) and "" or text:sub(s - 1, s - 1)
    local after = (e >= #text) and "" or text:sub(e + 1, e + 1)
    local ok_b = (before == "") or (before:match("[^%w]") ~= nil)
    local ok_a = (after == "") or (after:match("[^%w]") ~= nil)
    if ok_b and ok_a then return true end
    init = e + 1
  end
end

local function hit(kw, text)
  if text:find(kw, 1, true) then return true end
  local lens = {6,5,4}
  for _, L in ipairs(lens) do
    if #kw >= L then
      local pref = kw:sub(1, L)
      if text:find(pref, 1, true) then return true end
    end
  end
  return false
end

local function round4(x)
  return math.floor(x * 10000 + 0.5) / 10000
end

-- classify
local function classify(task)
  local text = (task or ""):lower():gsub("^%s+", ""):gsub("%s+$", "")
  if text == "" then
    return {domain="opste", confidence=0.10, scores={opste=0.10},
            order={"opste"}, multi=false, matched={}}
  end
  local raw = {}   -- {domain=score}
  local raw_order = {}
  local matched = {}

  for _, pair in ipairs(DOMAIN_KEYWORDS) do
    local domain, kws = pair[1], pair[2]
    local hit_list = {}
    for _, kw in ipairs(kws) do
      if hit(kw, text) then hit_list[#hit_list + 1] = kw end
    end
    if #hit_list > 0 then
      local weight = 0
      for idx = 1, #hit_list do weight = weight + 1.0 / (1.0 + 0.15 * (idx - 1)) end
      local sum_len = 0
      for _, kw in ipairs(hit_list) do sum_len = sum_len + #kw end
      weight = weight + 0.10 * sum_len / 10.0
      raw[domain] = weight
      raw_order[#raw_order + 1] = domain
      matched[domain] = hit_list
    end
  end

  if #raw_order == 0 then
    return {domain="opste", confidence=0.20, scores={opste=0.20},
            order={"opste"}, multi=false, matched={}}
  end

  local total = 0
  for _, d in ipairs(raw_order) do total = total + raw[d] end
  local scores = {}
  for _, d in ipairs(raw_order) do scores[d] = raw[d] / total end

  local best_domain, best_score = nil, -1
  for _, d in ipairs(raw_order) do
    if scores[d] > best_score then best_score = scores[d]; best_domain = d end
  end

  local vals = {}
  for _, d in ipairs(raw_order) do vals[#vals + 1] = scores[d] end
  table.sort(vals, function(a, b) return a > b end)
  local second = vals[2] or 0.0

  local confidence = 0.6 * best_score + 0.4 * (best_score - second) + 0.2
  if confidence > 1.0 then confidence = 1.0 end
  if confidence < 0.0 then confidence = 0.0 end

  local mh = 0
  for _, m in ipairs(MULTI_MARKERS) do if text:find(m, 1, true) then mh = mh + 1 end end
  local multi = (mh >= 2) or (#raw_order >= 3 and confidence < PRAH_SINGLE)

  return {domain=best_domain, confidence=confidence, scores=scores,
          order=raw_order, multi=multi, matched=matched[best_domain] or {}}
end

-- risk v2 (T1/T2 + transfer boost; usklađeno sa Python/Rust/Go v2)
local T1 = {"rm -rf /","rm -rf ~","rm -rf *","format c:","format d:","mkfs",
  "drop table","drop database","truncate table","shutdown","reboot",
  "obrisi sve","obrisi citav","obrisi cijeli","izbrisi sve","izbrisi bazu","izbrisi disk"}
local T2 = {"obrisi fajl","obrisi folder","obrisi direktorij","obrisi log",
  "delete file","delete folder","rm","drop","truncate","root pristup","root bez",
  "ugasi server","stop all","killall","pkill -9","chmod 777","chown -r"}

local function assess_risk(task, domain)
  local text = (task or ""):lower()
  local hits = 0
  for _, w in ipairs(HIGH_RISK) do
    if word_hit(w, text) then hits = hits + 1 end
  end
  local risk = 0.0
  for _, p in ipairs(T1) do
    if text:find(p, 1, true) or word_hit(p, text) then risk = math.max(risk, 0.9) end
  end
  if text:match("dd%s+if=.*of=/dev/") then risk = math.max(risk, 0.9) end
  if text:match("format%s+[a-z]:") then risk = math.max(risk, 0.9) end
  for _, p in ipairs(T2) do
    if text:find(p, 1, true) or word_hit(p, text) then risk = math.max(risk, 0.7) end
  end
  local base = math.min(0.75, hits * 0.35)
  if base > risk then risk = base end
  risk = risk + (SENSITIVE[domain] or 0.0)
  if domain == "finansije" and text:find("transfer", 1, true) then risk = risk + 0.15 end
  if risk < 0.0 then risk = 0.0 end
  if risk > 1.0 then risk = 1.0 end
  return risk
end

-- ranked domains (po skoru opadajuce; tie-break po redoslijedu u order = domainOrder).
-- Lua table.sort nije stabilan -> sortiramo po (score desc, index asc).
local function ranked(cls)
  local idx = {}
  for i, d in ipairs(cls.order) do idx[d] = i end
  local out = {}
  for _, d in ipairs(cls.order) do out[#out + 1] = d end
  table.sort(out, function(a, b)
    if cls.scores[a] ~= cls.scores[b] then return cls.scores[a] > cls.scores[b] end
    return idx[a] < idx[b]
  end)
  return out
end

local function contains(arr, x)
  for _, v in ipairs(arr) do if v == x then return true end end
  return false
end

-- route
local function route(task)
  local cls = classify(task)
  local risk = assess_risk(task, cls.domain)
  local primary = DOMAIN_AGENTS[cls.domain] or DOMAIN_AGENTS["opste"]

  -- HARD-BLOCK
  if risk >= RISK_HARD_BLOCK then
    return {mode="single", agents={}, reason=string.format(
      "HARD-BLOCK: rizik=%.2f >= %.2f (domen=%s). Zadr'zano na ljudsku verifikaciju prije izvr\u{0161}enja.",
      risk, RISK_HARD_BLOCK, cls.domain), domain=cls.domain,
      confidence=round4(cls.confidence), risk=round4(risk), ["blocked"]=true}
  end

  -- SINGLE
  if cls.confidence >= PRAH_SINGLE then
    return {mode="single", agents={primary[1]}, reason=string.format(
      "Visoka pouzdanost=%.2f >= %.2f za domen=%s; jedan nosivi agent je dovoljan.",
      cls.confidence, PRAH_SINGLE, cls.domain), domain=cls.domain,
      confidence=round4(cls.confidence), risk=round4(risk), ["blocked"]=false}
  end

  -- GROUP
  if cls.confidence >= PRAH_GROUP then
    local agents = {}
    if #primary >= 2 then agents = {primary[1], primary[2]} else
      for _, a in ipairs(primary) do agents[#agents + 1] = a end
    end
    if cls.multi and #cls.order > 1 then
      local rk = ranked(cls)
      if #rk > 1 then
        local da = DOMAIN_AGENTS[rk[2]] or {}
        if da[1] and not contains(agents, da[1]) then agents[#agents + 1] = da[1] end
      end
    end
    local reason = string.format(
      "Srednja pouzdanost=%.2f u [%.2f,%.2f); anga\u{017e}uje se grupa agenata za domen=%s",
      cls.confidence, PRAH_GROUP, PRAH_SINGLE, cls.domain)
    if cls.multi then reason = reason .. " (multi-domen)" end
    return {mode="group", agents=agents, reason=reason, domain=cls.domain,
            confidence=round4(cls.confidence), risk=round4(risk), ["blocked"]=false}
  end

  -- SWARM
  local agents = {}
  for _, a in ipairs(primary) do agents[#agents + 1] = a end
  local rk = ranked(cls)
  for i = 2, math.min(3, #rk) do
    local da = DOMAIN_AGENTS[rk[i]] or {}
    if da[1] and not contains(agents, da[1]) then agents[#agents + 1] = da[1] end
  end
  return {mode="swarm", agents=agents, reason=string.format(
    "Niska pouzdanost=%.2f < %.2f; zadatak je neodre\u{0111}en/\u{0161}irok te se pokre\u{0107}e Roj agenata (domen\u{2248}%s).",
    cls.confidence, PRAH_GROUP, cls.domain), domain=cls.domain,
    confidence=round4(cls.confidence), risk=round4(risk), ["blocked"]=false}
end

-- ---------------------------------------------------------------------------
-- main
-- ---------------------------------------------------------------------------
local function read_file(path)
  local f = io.open(path, "rb")
  if not f then return nil end
  local s = f:read("*a"); f:close(); return s
end

local function main(args)
  local in_file, bench, n = nil, false, 10000
  local i = 1
  while i <= #args do
    local a = args[i]
    if a == "-in" or a == "--in" then i = i + 1; in_file = args[i]
    elseif a:match("^%-%-?in=") then in_file = a:gsub("^%-%-?in=", "")
    elseif a == "-bench" or a == "--bench" then bench = true
    elseif a == "-n" or a == "--n" then i = i + 1; n = tonumber(args[i]) or 10000
    elseif a:match("^%-%-?n=") then n = tonumber(a:gsub("^%-%-?n=", "")) or 10000
    end
    i = i + 1
  end

  local raw
  if in_file then raw = read_file(in_file) else raw = io.read("*a") end
  if not raw then io.stderr:write("greska citanja\n"); os.exit(1) end

  local trimmed = raw:gsub("^%s+", ""):gsub("%s+$", "")
  local tasks
  if in_file or trimmed:sub(1, 1) == "[" then
    tasks = json.decode(trimmed)
  else
    tasks = {}
    for line in trimmed:gmatch("[^\n]+") do tasks[#tasks + 1] = line end
  end

  if bench then
    local t0 = os.clock()
    local last
    for _ = 1, n do
      last = {}
      for _, t in ipairs(tasks) do last[#last + 1] = route(t) end
    end
    local el = os.clock() - t0
    local total = n * #tasks
    io.stderr:write(string.format(
      "BENCH: %d upita u %.4fs = %.2f us/upit (%.0f upita/s)\n",
      total, el, el * 1e6 / total, total / el))
    print(json.encode(last))
    return
  end

  local results = {}
  for _, t in ipairs(tasks) do results[#results + 1] = route(t) end
  print(json.encode(results))
end

main({...})
