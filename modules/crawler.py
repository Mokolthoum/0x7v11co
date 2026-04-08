import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from utils.colors import print_info, print_success, Colors

class Crawler:
    def __init__(self, target_url, session, max_depth=3):
        self.target_url = target_url
        self.session = session
        self.max_depth = max_depth
        self.visited_urls = set()
        self.urls_to_scan = set()
        self.domain = urlparse(target_url).netloc

    def crawl(self, url=None, depth=0):
        if url is None:
            url = self.target_url

        if depth > self.max_depth:
            return

        # Normalize URL (remove trailing slash for dedup, but keep it for requests)
        normalized = url.rstrip('/')
        if normalized in self.visited_urls:
            return

        self.visited_urls.add(normalized)
        
        if depth <= 1:
            print_info(f"Crawling: {url} (Depth: {depth})")

        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
            
            # Track the final URL after redirects
            final_url = response.url
            final_normalized = final_url.rstrip('/')
            if final_normalized not in self.visited_urls:
                self.visited_urls.add(final_normalized)
            
            # Add URL even if redirected (the redirect target is interesting too)
            if response.status_code == 200:
                self.urls_to_scan.add(final_url)
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract links from <a> tags
            for link in soup.find_all('a'):
                href = link.get('href')
                if href:
                    self._process_url(href, url, depth)

            # Extract form actions
            for form in soup.find_all('form'):
                action = form.get('action')
                if action:
                    self._process_url(action, url, depth)
            
            # Extract links from JavaScript (simple regex for common patterns)
            import re
            for script in soup.find_all('script'):
                if script.string:
                    # Find URLs in JavaScript like href="/path" or url: "/path"
                    js_urls = re.findall(r'(?:href|url|src|action)\s*[=:]\s*["\']([^"\']+)["\']', script.string)
                    for js_url in js_urls:
                        self._process_url(js_url, url, depth + 1)

        except Exception as e:
            pass

    def _process_url(self, href, base_url, depth):
        """Process a discovered URL and add it to crawl queue."""
        # Skip fragments and javascript
        if not href or href.startswith('#') or href.startswith('javascript:'):
            return
            
        full_url = urljoin(base_url, href)
        parsed_url = urlparse(full_url)
        
        # Only crawl internal links
        if parsed_url.netloc == self.domain:
            # Avoid static files
            skip_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js', 
                             '.pdf', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot']
            if not any(full_url.lower().endswith(ext) for ext in skip_extensions):
                self.urls_to_scan.add(full_url)
                self.crawl(full_url, depth + 1)

    def get_urls(self):
        print_info(f"Starting Crawler on {self.target_url} (Max Depth: {self.max_depth})...")
        self.crawl()
        print_info(f"Crawler finished. Found {len(self.urls_to_scan)} unique URLs.")
        return list(self.urls_to_scan)
