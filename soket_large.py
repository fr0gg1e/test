#!/usr/bin/env python3
# http_get_large.py
# Minimalny HTTP GET klient na socketach dla dużych plików
# Użycie: python http_get_large.py <host> <port> <path> <out_file> <local_ip>

import socket
import sys
import hashlib
import time

BUFFER = 64 * 1024  # 64KB

def recv_until(sock, delim=b'\r\n\r\n', timeout=10):
    sock.settimeout(timeout)
    data = bytearray()
    while True:
        chunk = sock.recv(1024)
        if not chunk:
            break
        data.extend(chunk)
        if delim in data:
            break
    return bytes(data)

def parse_headers(header_bytes):
    text = header_bytes.decode('iso-8859-1')
    head, _, _ = text.partition('\r\n\r\n')
    lines = head.split('\r\n')
    status = lines[0]
    hdrs = {}
    for line in lines[1:]:
        if ':' in line:
            k,v = line.split(':',1)
            hdrs[k.strip().lower()] = v.strip()
    return status, hdrs

def decode_chunked(sock, out_f, progress_callback=None):
    total = 0
    while True:
        # read chunk-size line
        line = bytearray()
        while True:
            ch = sock.recv(1)
            if not ch:
                raise IOError("Connection closed during chunked size")
            line.extend(ch)
            if line.endswith(b'\r\n'):
                break
        size_str = line.strip().split(b';')[0]
        size = int(size_str, 16)
        if size == 0:
            _ = sock.recv(2)  # consume trailing CRLF
            break
        # read exactly size bytes
        remaining = size
        while remaining > 0:
            r = sock.recv(min(BUFFER, remaining))
            if not r:
                raise IOError("Unexpected EOF in chunked encoding")
            out_f.write(r)
            total += len(r)
            remaining -= len(r)
            if progress_callback:
                progress_callback(len(r))
        _ = sock.recv(2)  # trailing CRLF
    # read trailers (best-effort)
    try:
        sock.settimeout(0.1)
        _ = sock.recv(4096)
    except:
        pass
    return total

def read_until_close(sock, out_f, progress_callback=None):
    total = 0
    while True:
        chunk = sock.recv(BUFFER)
        if not chunk:
            break
        out_f.write(chunk)
        total += len(chunk)
        if progress_callback:
            progress_callback(len(chunk))
    return total

def http_get(host, port, path, out_file, local_ip):
    addr = (host, int(port))
    total_downloaded = 0

    def progress(bytes_received):
        nonlocal total_downloaded
        total_downloaded += bytes_received
        print(f"\rDownloaded {total_downloaded/1024/1024:.2f} MB", end='')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((local_ip, 0))
        s.settimeout(10)
        s.connect(addr)

        req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: http-get-large/1.0\r\nConnection: close\r\nAccept: */*\r\n\r\n"
        s.sendall(req.encode('ascii'))

        header_part = recv_until(s)
        if not header_part:
            raise IOError("No response / connection closed")
        status_line, headers = parse_headers(header_part)
        print("Status:", status_line)

        start_time = time.time()
        sha = hashlib.sha256()
        with open(out_file, 'wb') as f:
            if 'content-length' in headers:
                clen = int(headers['content-length'])
                remaining = clen
                while remaining > 0:
                    r = s.recv(min(BUFFER, remaining))
                    if not r:
                        print("\n[!] EOF before Content-Length reached")
                        break
                    f.write(r)
                    sha.update(r)
                    remaining -= len(r)
                    progress(len(r))
            elif headers.get('transfer-encoding','').lower() == 'chunked':
                decode_chunked(s, f, progress_callback=lambda b: [progress(b), sha.update(b)][1])
            else:
                read_until_close(s, f, progress_callback=lambda b: [progress(b), sha.update(b)][1])

        elapsed = time.time() - start_time
        print(f"\nFinished: {total_downloaded/1024/1024:.2f} MB in {elapsed:.2f}s ({(total_downloaded/1024/1024)/elapsed:.2f} MB/s)")
        print("SHA256:", sha.hexdigest())
    return total_downloaded, sha.hexdigest()

if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("Usage: python http_get_large.py <host> <port> <path> <out_file> <local_ip>")
        print("Example: python http_get_large.py 192.168.68.105 8000 /test.txt test.txt 192.168.68.106")
        sys.exit(2)
    host, port, path, out_file, local_ip = sys.argv[1:6]
    try:
        http_get(host, port, path, out_file, local_ip)
    except Exception as e:
        print("Error:", e)
        sys.exit(1)
