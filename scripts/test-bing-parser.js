// Quick local test of the Bing parser logic
// Run: node /home/z/my-project/scripts/test-bing-parser.js

const fs = require("fs");

function decodeBingUrl(ckAurl) {
  try {
    const decoded = ckAurl.replace(/&amp;/g, "&");
    const m = decoded.match(/u=a1([A-Za-z0-9+/=_-]+)/);
    if (!m) return null;
    let b64 = m[1];
    b64 = decodeURIComponent(b64);
    b64 = b64.replace(/-/g, "+").replace(/_/g, "/");
    b64 += "=".repeat((4 - (b64.length % 4)) % 4);
    const url = Buffer.from(b64, "base64").toString("utf-8");
    if (!url.startsWith("http")) return null;
    return url;
  } catch { return null; }
}

function parseBingHtml(html) {
  const results = [];
  const blockRe = /<h2[^>]*>\s*<a[^>]*href="(https:\/\/www\.bing\.com\/ck\/a\?[^"]+)"[^>]*>([\s\S]*?)<\/a>\s*<\/h2>([\s\S]*?)(?=<h2|<div class="b_pag|<\/div>\s*<div class="b_footer|$)/g;
  let m;
  let count = 0;
  while ((m = blockRe.exec(html)) && count < 30) {
    const ckAurl = m[1];
    const titleHtml = m[2];
    const tail = m[3];
    const url = decodeBingUrl(ckAurl);
    if (!url) continue;
    if (/bing\.com\/(images|videos|maps|news|shop|search)/.test(url)) continue;
    const title = titleHtml.replace(/<[^>]+>/g, "").trim();
    if (!title) continue;
    const pMatch = tail.match(/<p[^>]*>([\s\S]*?)<\/p>/);
    const snippet = (pMatch ? pMatch[1] : "").replace(/<[^>]+>/g, "").trim();
    results.push({ title, url, snippet: snippet.slice(0, 150) });
    count++;
  }
  return results;
}

const html = fs.readFileSync("/tmp/bing_us.html", "utf-8");
const results = parseBingHtml(html);
console.log(`Parsed ${results.length} results:`);
results.forEach((r, i) => {
  console.log(`\n${i + 1}. ${r.title}`);
  console.log(`   URL: ${r.url}`);
  console.log(`   Snippet: ${r.snippet.slice(0, 80)}`);
});
