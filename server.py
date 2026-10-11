"""Explicit loopback-only evidence dashboard. Importing this module starts nothing."""
import argparse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
from preview_adapter import Collector, read_bytes, strict_json

ASSETS = {'/': ('dashboard.html', 'text/html; charset=utf-8'),
          '/dashboard.html': ('dashboard.html', 'text/html; charset=utf-8'),
          '/lab/dashboard.html': ('lab/dashboard.html', 'text/html; charset=utf-8'),
          '/preview.css': ('preview.css', 'text/css; charset=utf-8'),
          '/preview.js': ('preview.js', 'text/javascript; charset=utf-8')}


def make_server(collector, assets, port=0):
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("INVALID_LOOPBACK_PORT")
    assets = Path(assets).absolute()
    class Handler(BaseHTTPRequestHandler):
        def send(self, status, body, mime='text/plain; charset=utf-8'):
            self.send_response(status)
            for k, v in {'Content-Type': mime, 'Content-Length': str(len(body)), 'Cache-Control': 'no-store',
                         'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
                         'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"}.items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != 'HEAD': self.wfile.write(body)

        def do_GET(self):
            if self.headers.get('Host') != '127.0.0.1:' + str(self.server.server_port):
                return self.send(403, b'Loopback host required')
            if self.path == '/api/preview':
                body = json.dumps(collector.collect(), ensure_ascii=False, allow_nan=False).encode()
                return self.send(200, body, 'application/json; charset=utf-8')
            if self.path not in ASSETS: return self.send(404, b'Not found')
            filename, mime = ASSETS[self.path]
            try: body, _ = read_bytes(assets / filename)
            except (OSError, ValueError): return self.send(503, b'Dashboard asset unavailable')
            self.send(200, body, mime)

        def reject(self): self.send(405, b'GET only')
        do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = do_TRACE = do_CONNECT = reject
        def log_message(self, *_): pass

    return HTTPServer(('127.0.0.1', port), Handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path(__file__).absolute().parent / 'dashboard.config.example.json')
    parser.add_argument('--port', type=int, default=None, help='Override config listen_port;0 lets OS choose')
    args = parser.parse_args()
    config = strict_json(read_bytes(args.config.absolute())[0])
    port = config.get('listen_port', 0) if args.port is None else args.port
    server = make_server(Collector(config['sources']), Path(__file__).absolute().parent, port)
    print(json.dumps({'url': f'http://127.0.0.1:{server.server_port}/', 'pid': os.getpid(),
                      'started_at': datetime.now(timezone.utc).isoformat(), 'owner': 'MOBILE-DECISION-DASHBOARD-20261011'}), flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()


if __name__ == '__main__': main()
