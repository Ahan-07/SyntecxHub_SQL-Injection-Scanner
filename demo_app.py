from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        params = parse_qs(urlparse(self.path).query)
        q = params.get("q", [""])[0]

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        # Intentionally exposes a SQL-like error for the training scanner.
        if "'" in q or '"' in q:
            body = "<h1>Database Error</h1><p>You have an error in your SQL syntax; MySQL test lab.</p>"
        elif "1'='1" in q or '1"="1' in q:
            body = "<h1>Results</h1><p>3 products found.</p>"
        elif "1'='2" in q or '1"="2' in q:
            body = "<h1>Results</h1><p>0 products found.</p>"
        else:
            body = "<h1>Results</h1><p>1 product found.</p>"

        self.wfile.write(body.encode())

print("Demo app: http://127.0.0.1:8080/search?q=test")
HTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
