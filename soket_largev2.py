#!/usr/bin/env python3
# http_sock_get_bind_fixed.py
# Minimalny HTTP GET klient na socketach z bind do lokalnego IP
# Obsługa leftover po nagłówkach (nie traci pierwszych bajtów body)
# Użycie: python http_sock_get_bind_fixed.py <host> <port> <path> <out_file> <local_ip>

import socket
import sys
import hashlib
import time

BUFFER = 64 * 1024

def recv_until(sock, delim=b'\r\n\r\n', timeout=10):
    """Czyta z sock.recv aż do delim (włącznie) lub EOF; zwraca całe co zostało odebrane."""
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

def recv_exact(reader, n):
    """Czyta dokładnie n bajtów z obiektu reader (ma metodę recv(n))."""
    data = bytearray()
    while len(data) < n:
        chunk = reader.recv(min(BUFFER, n - len(data)))
        if not chunk:
            raise IOError("Unexpected EOF while receiving exact bytes")
        data.extend(chunk)
    return bytes(data)

def read_until_close(reader):
    """Czyta aż socket zostanie zamknięty."""
    data = bytearray()
    while True:
        chunk = reader.recv(BUFFER)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)

def parse_headers(header_bytes):
    """Parsuje nagłówki HTTP (header_bytes nie powinien zawierać '\r\n\r\n')."""
    text = header_bytes.decode('iso-8859-1')
    lines = text.split('\r\n')
    status = lines[0]
    hdrs = {}
    for line in lines[1:]:
        if ':' in line:
            k,v = line.split(':',1)
            hdrs[k.strip().lower()] = v.strip()
    return status, hdrs

def decode_chunked(reader):
    """Dekoduje body chunked z reader (czyta chunk-size + dane)."""
    body = bytearray()
    while True:
        # czytamy linię rozmiaru chunku (kończy się \r\n)
        line = bytearray()
        while True:
            ch = reader.recv(1)
            if not ch:
                raise IOError("Connection closed during chunked size")
            line.extend(ch)
            if line.endswith(b'\r\n'):
                break
        size_str = line.strip().split(b';')[0]
        try:
            size = int(size_str, 16)
        except Exception:
            raise IOError("Invalid chunk size")
        if size == 0:
            # po 0-chunku jest CRLF, potem ewentualne trailery; pobierz i zakończ
            _ = recv_exact(reader, 2)  # powinno być \r\n
            # spróbuj odczytać ewentualne trailery (pomijamy - best effort)
            try:
                # zostały jakieś dodatkowe dane przed zamknięciem?
                reader.sock.settimeout(0.05)
                _ = reader.recv(4096)
            except:
                pass
            break
        # czytamy dokładnie size bajtów
        chunk = recv_exact(reader, size)
        body.extend(chunk)
        # czytamy kończące CRLF
        _ = recv_exact(reader, 2)
    return bytes(body)

class Reader:
    """
    Wrapper nad socketem, który najpierw zwraca dane z initial buffer (leftover),
    a potem czyta ze socket.recv.
    Interfejs: reader.recv(n)
    """
    def __init__(self, sock, initial=b''):
        self.sock = sock
        self.buf = bytearray(initial)

    def recv(self, n):
        if len(self.buf) >= n:
            out = self.buf[:n]
            del self.buf[:n]
            return bytes(out)
        elif len(self.buf) > 0:
            out = bytes(self.buf)
            self.buf.clear()
            # dopełnij z sock
            part = self.sock.recv(n - len(out))
            if not part:
                return out
            return out + part
        else:
            return self.sock.recv(n)

def http_get(host, port, path, out_file, local_ip, timeout=10):
    addr = (host, int(port))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # bind do lokalnego IP aby źródłowy adres był określony
        s.bind((local_ip, 0))
        s.settimeout(timeout)
        s.connect(addr)

        req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: http-sock-get/1.0\r\nConnection: close\r\nAccept: */*\r\n\r\n"
        s.sendall(req.encode('ascii'))

        # Odczytaj nagłówki + ewentualne początkowe fragmenty body
        header_part = recv_until(s, b'\r\n\r\n', timeout=timeout)
        if not header_part:
            raise IOError("No response / connection closed")

        # Rozdziel nagłówki i leftover (resztę, która już przyszła)
        header_bytes, sep, leftover = header_part.partition(b'\r\n\r\n')
        status_line, headers = parse_headers(header_bytes)

        parts = status_line.split(' ',2)
        code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
        print("Status:", status_line)

        reader = Reader(s, leftover)

        content = b''
        start_time = time.time()
        if 'content-length' in headers:
            clen = int(headers['content-length'])
            print(f"Content-Length: {clen} bytes")
            # najpierw wykorzystaj leftover, potem resztę
            already = len(leftover)
            if already >= clen:
                content = leftover[:clen]
            else:
                content = leftover + recv_exact(reader, clen - already)
        elif headers.get('transfer-encoding','').lower() == 'chunked':
            print("Transfer-Encoding: chunked")
            content = decode_chunked(reader)
        else:
            print("No Content-Length or chunked — reading until socket close")
            content = read_until_close(reader)

        # zapis do pliku
        with open(out_file, 'wb') as f:
            # zapisujemy porcjami by nie trzymać dużych plików w pamięci (jeśli content duży,
            # tutaj content jest już w pamięci -- dla prostoty; można zmienić streaming)
            f.write(content)

        elapsed = time.time() - start_time
        size = len(content)
        speed = (size / 1024 / 1024) / (elapsed if elapsed > 0 else 1)
        print(f"Saved {size} bytes to {out_file} ({speed:.2f} MB/s)")
        sha = hashlib.sha256(content).hexdigest()
        print("SHA256:", sha)
        return code, size, sha

if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("Usage: python http_sock_get_bind_fixed.py <host> <port> <path> <out_file> <local_ip>")
        print("Example: python http_sock_get_bind_fixed.py 192.168.68.105 8000 /test.txt test.txt 192.168.68.106")
        sys.exit(2)
    host, port, path, out_file, local_ip = sys.argv[1:6]
    try:
        http_get(host, port, path, out_file, local_ip)
    except Exception as e:
        print("Error:", e)
        sys.exit(1)
