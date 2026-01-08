from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("content-length", "0") or "0")
        body = self.rfile.read(length)
        print("--- received POST ---")
        print(self.path)
        print(dict(self.headers))
        print(f"bytes={len(body)}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 9009), Handler)
    print("Receiver listening on http://127.0.0.1:9009/")
    server.serve_forever()
