#!/usr/bin/env python3
"""Test the /api/sandbox/screenshot and /api/sandbox/redirects endpoints
by hitting external services directly to verify they work.

This validates the screenshot API's logic without needing the Next.js
dev server running.
"""
import json
import sys
import urllib.request
import urllib.parse

TEST_URL = "https://tucredisponibleneq.z13.web.core.windows.net"

def test_wordpress_mshots(url):
    """Test WordPress mshots service directly."""
    print(f"\n[1] WordPress mshots: {url}")
    enc = urllib.parse.quote(url, safe="")
    req_url = f"https://s.wordpress.com/mshots/v1/{enc}?w=1280"
    try:
        req = urllib.request.Request(req_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            ct = r.headers.get("Content-Type", "")
            size = len(r.read())
            print(f"    status={r.status} content-type={ct} size={size}")
            return size > 5000 and ct.startswith("image/")
    except Exception as e:
        print(f"    ERROR: {e}")
        return False

def test_thum_io(url):
    """Test thum.io service directly."""
    print(f"\n[2] thum.io: {url}")
    req_url = f"https://image.thum.io/get/width/1280/crop/720/{url}"
    try:
        req = urllib.request.Request(req_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            ct = r.headers.get("Content-Type", "")
            size = len(r.read())
            print(f"    status={r.status} content-type={ct} size={size}")
            return size > 5000 and ct.startswith("image/")
    except Exception as e:
        print(f"    ERROR: {e}")
        return False

def test_microlink(url):
    """Test microlink.io service (2-step: JSON → fetch image URL)."""
    print(f"\n[3] microlink.io: {url}")
    enc = urllib.parse.quote(url, safe="")
    req_url = f"https://api.microlink.io/?url={enc}&screenshot=true&meta=false"
    try:
        req = urllib.request.Request(req_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            j = json.loads(r.read().decode())
            ss_url = j.get("data", {}).get("screenshot", {}).get("url")
            print(f"    JSON response: status={j.get('status')} screenshot_url={ss_url}")
            if not ss_url:
                return False
            req2 = urllib.request.Request(ss_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req2, timeout=10) as r2:
                ct = r2.headers.get("Content-Type", "")
                size = len(r2.read())
                print(f"    image fetch: status={r2.status} content-type={ct} size={size}")
                return size > 5000 and ct.startswith("image/")
    except Exception as e:
        print(f"    ERROR: {e}")
        return False

def test_redirects(url):
    """Test the redirect chain logic by following redirects manually."""
    print(f"\n[4] Redirect chain for {url}")
    current = url
    for i in range(10):
        try:
            req = urllib.request.Request(current, method="GET", headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            })
            # Use NoRedirect to manually follow
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, hdrs, newurl):
                    return None
            opener = urllib.request.build_opener(NoRedirect)
            try:
                r = opener.open(req, timeout=8)
                status = r.status
                location = r.headers.get("Location")
            except urllib.error.HTTPError as e:
                status = e.code
                location = e.headers.get("Location") if e.headers else None
            print(f"    step {i+1}: {status} {current}")
            print(f"      location: {location}")
            if 300 <= status < 400 and location:
                current = urllib.parse.urljoin(current, location)
            else:
                print(f"    ✅ FINAL URL: {current}")
                break
        except Exception as e:
            print(f"    ERROR at step {i+1}: {e}")
            break

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else TEST_URL
    print(f"Testing services with URL: {url}")
    print("=" * 60)
    
    # Test screenshot services
    wp_ok = test_wordpress_mshots(url)
    thum_ok = test_thum_io(url)
    micro_ok = test_microlink(url)
    
    print("\n" + "=" * 60)
    print("SUMMARY:")
    print(f"  WordPress mshots: {'✅' if wp_ok else '❌'}")
    print(f"  thum.io:          {'✅' if thum_ok else '❌'}")
    print(f"  microlink.io:     {'✅' if micro_ok else '❌'}")
    
    # Test redirects
    test_redirects(url)
