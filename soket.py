import socket
import sys
import time
import hashlib

BUFFER = 64 * 1024

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

def recv_exact(sock, n):
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(min(BUFFER, n - len(data)))
        if not chunk:
            raise IOError("Unexpected EOF while receiving exact bytes")
        data.extend(chunk)
    return bytes(data)

def read_until_close(sock):
    data = bytearray()
    while True:
        chunk = sock.recv(BUFFER)
        if not chunk:
            break
        data.extend(chunk)
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

def decode_chunked(sock):
    body = bytearray()
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
            # consume trailing CRLF after final 0 chunk and any trailers (we'll read until \r\n\r\n)
            # read and discard the next CRLF
            _ = recv_exact(sock, 2)
            break
        # read exactly size bytes
        chunk = recv_exact(sock, size)
        body.extend(chunk)
        # read trailing CRLF
        tail = recv_exact(sock, 2)
        if tail != b'\r\n':
            # tolerate but warn
            pass
    # there might be trailers — read until CRLFCRLF (best-effort)
    # try to read a little and ignore
    try:
        sock.settimeout(0.1)
        _ = sock.recv(4096)
    except:
        pass
    return bytes(body)

def http_get(host, port, path, out_file, timeout=10):
    addr = (host, int(port))
    with socket.create_connection(addr, timeout=timeout) as s:
        req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: http-sock-get/1.0\r\nConnection: close\r\nAccept: */*\r\n\r\n"
        s.sendall(req.encode('ascii'))
        # read headers
        header_part = recv_until(s, b'\r\n\r\n', timeout=timeout)
        if not header_part:
            raise IOError("No response / connection closed")
        status_line, headers = parse_headers(header_part)
        # status
        parts = status_line.split(' ',2)
        code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
        print("Status:", status_line)
        # decide how to read body
        content = b''
        if 'content-length' in headers:
            clen = int(headers['content-length'])
            print(f"Content-Length: {clen} bytes")
            content = recv_exact(s, clen)
        elif headers.get('transfer-encoding','').lower() == 'chunked':
            print("Transfer-Encoding: chunked")
            content = decode_chunked(s)
        else:
            # read until close
            print("No Content-Length or chunked — reading until socket close")
            content = read_until_close(s)
        # write to file
        with open(out_file, 'wb') as f:
            f.write(content)
        # print stats
        elapsed = 0  # we aren't measuring incremental time, trivial now
        print(f"Saved {len(content)} bytes to {out_file}")
        # checksum
        sha = hashlib.sha256(content).hexdigest()
        print("SHA256:", sha)
        return code, len(content), sha

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python http_sock_get.py <host> <port> <path> <out_file>")
        print("Example: python http_sock_get.py 192.168.68.105 8000 /test.txt test.txt")
        sys.exit(2)
    host = sys.argv[1]
    port = sys.argv[2]
    path = sys.argv[3]
    out_file = sys.argv[4]
    try:
        http_get(host, port, path, out_file)
    except Exception as e:
        print("Error:", e)
        sys.exit(1)