from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", 8080), SimpleHTTPRequestHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
