// ---------- helpers ----------
const toHex = (buf) => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");

async function subtleHash(algorithm, message) {
  const data = new TextEncoder().encode(message);
  const buf = await crypto.subtle.digest(algorithm, data);
  return toHex(buf);
}

function jsshaHex(algo, msg, opts) {
  const shaObj = new jsSHA(algo, "TEXT", opts || {});
  shaObj.update(msg);
  return shaObj.getHash("HEX");
}

// ---------- algorithm table ----------
const ALGORITHMS = [
  { name: "MD5", fn: (msg) => Promise.resolve(window.md5(msg)) },
  { name: "SHA-1", fn: (msg) => subtleHash("SHA-1", msg) },
  { name: "SHA-224", fn: (msg) => Promise.resolve(jsshaHex("SHA-224", msg)) },
  { name: "SHA-256", fn: (msg) => subtleHash("SHA-256", msg) },
  { name: "SHA-384", fn: (msg) => subtleHash("SHA-384", msg) },
  { name: "SHA-512", fn: (msg) => subtleHash("SHA-512", msg) },
  { name: "SHA3-224", fn: (msg) => Promise.resolve(jsshaHex("SHA3-224", msg)) },
  { name: "SHA3-256", fn: (msg) => Promise.resolve(jsshaHex("SHA3-256", msg)) },
  { name: "SHA3-384", fn: (msg) => Promise.resolve(jsshaHex("SHA3-384", msg)) },
  { name: "SHA3-512", fn: (msg) => Promise.resolve(jsshaHex("SHA3-512", msg)) }
];

// ---------- UI wiring ----------
const resultsEl = document.getElementById("results");
const tpl = document.getElementById("hash-card-tpl");

const cards = ALGORITHMS.map((alg) => {
  const node = tpl.content.firstElementChild.cloneNode(true);
  node.querySelector(".alg-label").textContent = alg.name + ":";
  const out = node.querySelector("output");
  const btn = node.querySelector(".copy-btn");
  const tim = node.querySelector(".time");
  btn.addEventListener("click", async () => {
    const text = out.textContent.trim();
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      const span = btn.querySelector("span");
      const old = span.textContent;
      span.textContent = "Copied!";
      btn.classList.add("ring-1", "ring-emerald-400");
      setTimeout(() => {
        span.textContent = old;
        btn.classList.remove("ring-emerald-400");
      }, 1200);
    } catch (e) { console.error(e); }
  });
  resultsEl.appendChild(node);
  return { alg, out, btn, tim };
});

const source = document.getElementById("source");
let debounce;
async function computeAll(value) {
  if (!value) {
    for (const c of cards) {
      c.out.textContent = "";
      c.tim.textContent = "";
      c.btn.disabled = true;
    }
    return;
  }
  const runs = cards.map(async (c) => {
    const t0 = performance.now();
    const v = await c.alg.fn(value);
    const secs = (performance.now() - t0) / 1000;
    return { c, v, secs };
  });
  const results = await Promise.all(runs);
  for (const r of results) {
    r.c.out.textContent = r.v;
    r.c.tim.textContent = r.secs.toFixed(3) + " s";
    r.c.btn.disabled = !r.v;
  }
}

source.addEventListener("input", () => {
  clearTimeout(debounce);
  const value = source.value;
  debounce = setTimeout(() => computeAll(value), 120);
});

for (const c of cards) c.btn.disabled = true;

// ---------- self-tests ----------
const KNOWN = {
  md5_empty: "d41d8cd98f00b204e9800998ecf8427e",
  md5_abc: "900150983cd24fb0d6963f7d28e17f72",
  sha1_empty: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
  sha1_abc: "a9993e364706816aba3e25717850c26c9cd0d89d",
  sha256_empty: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  sha256_abc: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
};

function addTestResult(el, name, ok, extra = "") {
  const li = document.createElement("li");
  li.className = ok ? "text-emerald-600" : "text-rose-600";
  li.textContent = (ok ? "[OK] " : "[FAILED] ") + name + (extra ? ` — ${extra}` : "");
  el.appendChild(li);
}

document.getElementById("run-tests").addEventListener("click", async () => {
  const list = document.getElementById("test-results");
  list.innerHTML = "";
  // Digests — strict vectors
  addTestResult(list, "MD5(\"\")", window.md5("") === KNOWN.md5_empty);
  addTestResult(list, "MD5(\"abc\")", window.md5("abc") === KNOWN.md5_abc);
  addTestResult(list, "SHA-1(\"\")", (await subtleHash("SHA-1", "")) === KNOWN.sha1_empty);
  addTestResult(list, "SHA-1(\"abc\")", (await subtleHash("SHA-1", "abc")) === KNOWN.sha1_abc);
  addTestResult(list, "SHA-256(\"\")", (await subtleHash("SHA-256", "")) === KNOWN.sha256_empty);
  addTestResult(list, "SHA-256(\"abc\")", (await subtleHash("SHA-256", "abc")) === KNOWN.sha256_abc);
  // Length checks for other digests
  addTestResult(list, "SHA-224 length (empty)", jsshaHex("SHA-224", "").length === 56, "expect 56 hex chars");
  addTestResult(list, "SHA-384 length (empty)", (await subtleHash("SHA-384", "")).length === 96, "expect 96 hex chars");
  addTestResult(list, "SHA-512 length (empty)", (await subtleHash("SHA-512", "")).length === 128, "expect 128 hex chars");
  addTestResult(list, "SHA3-224 length (empty)", jsshaHex("SHA3-224", "").length === 56, "expect 56 hex chars");
  addTestResult(list, "SHA3-256 length (empty)", jsshaHex("SHA3-256", "").length === 64, "expect 64 hex chars");
  addTestResult(list, "SHA3-384 length (empty)", jsshaHex("SHA3-384", "").length === 96, "expect 96 hex chars");
  addTestResult(list, "SHA3-512 length (empty)", jsshaHex("SHA3-512", "").length === 128, "expect 128 hex chars");
});
