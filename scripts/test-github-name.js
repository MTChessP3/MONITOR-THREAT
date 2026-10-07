// Test GitHub User search with full-name filter
// Usage: GH_TEST=1 node scripts/test-github-name.js

const QUERY = process.argv[2] || "Juan Pérez";

async function ghFetch(q) {
  const headers = { "User-Agent": "MONITOR-THREAT", "Accept": "application/vnd.github.v3+json" };
  const r = await fetch(`https://api.github.com/search/users?q=${encodeURIComponent(q)}&per_page=20`, { headers });
  if (!r.ok) return [];
  const d = await r.json();
  return d.items || [];
}

function nameTokens(name) {
  return name.toLowerCase().split(/\s+/).filter(t => t.length > 1 && !/^(de|del|la|las|los|el|y|van|von|di|da|do|dos|san|sant|santa)$/.test(t));
}

(async () => {
  console.log(`Query: "${QUERY}"`);
  const tokens = nameTokens(QUERY);
  console.log(`Tokens: ${tokens.join(", ")}`);
  console.log("---");

  // Try variants
  const noAccent = QUERY.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
  const variants = noAccent === QUERY ? [QUERY] : [QUERY, noAccent];

  const allItems = new Map();
  for (const v of variants) {
    const queries = tokens.length >= 2
      ? [`fullname:"${v}" in:name`, `"${v}" in:name`]
      : [`${v} in:name`];
    for (const q of queries) {
      console.log(`  >> ${q}`);
      const items = await ghFetch(q);
      for (const u of items) {
        if (!allItems.has(u.html_url)) allItems.set(u.html_url, u);
      }
    }
  }
  console.log(`\nCandidates: ${allItems.size}`);

  // Fetch each profile and filter by full-name match
  const required = nameTokens(QUERY);
  const accentless = required.map(t => t.normalize("NFD").replace(/[\u0300-\u036f]/g, ""));
  const checks = await Promise.all(Array.from(allItems.values()).slice(0, 8).map(async u => {
    try {
      const pr = await fetch(`https://api.github.com/users/${u.login}`, { headers: { "User-Agent": "MONITOR-THREAT" } });
      if (!pr.ok) return { u, name: u.login };
      const pd = await pr.json();
      return { u, name: `${pd.name || ""} ${pd.login || ""} ${pd.bio || ""}` };
    } catch { return { u, name: u.login }; }
  }));

  const filtered = checks.filter(c => {
    const candidate = (c.name || "").toLowerCase();
    const normalized = candidate.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
    return required.every(t => candidate.includes(t)) || accentless.every(t => normalized.includes(t));
  });

  console.log(`\nFiltered (full-name match): ${filtered.length}`);
  for (const c of filtered) {
    console.log(`  - ${c.u.login} -> "${c.name}"`);
  }
})();
