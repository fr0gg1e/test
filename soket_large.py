#!/usr/bin/env python3
# http_get_large_fix.py
# Poprawiony HTTP GET na socketach z bind do lokalnego IP
# Obsługa dużych plików, chunked, content-length, oraz zachowanie reszty po nagłówkach.
# Użycie: python http_get_large_fix.py <host> <port> <path> <out_file> <local_ip>

import socket
import sys
import hashlib
import time

BUFFER = 64 * 1024  # 64KB

def recv_until_raw(sock, delim=b'\r\n\r\n', timeout=10):
    """
    Czyta z socketa aż do wystąpienia delim. Zwraca (all_data, index_of_delim)
    all_data zawiera nagłówki + możliwy fragment body. Jeśli połączenie zamknięte,
    zwraca to, co jest.
    """
    sock.settimeout(timeout)
    data = bytearray()
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data.extend(chunk)
        idx = data.find(delim)
        if idx != -1:
            return bytes(data), idx
    return bytes(data), -1

class BufferedSocket:
    """
    Wrapper: najpierw podaje dane z initial_buf, potem czyta z real_sock.
    Ma metody recv(n) i recv1() analogiczne do socket.
    """
    def __init__(self, real_sock, initial_buf=b''):
        self.sock = real_sock
        self.buf = bytearray(initial_buf)

    def recv(self, n):
        if self.buf:
            if len(self.buf) <= n:
                out = bytes(self.buf)
                self.buf.clear()
                return out
            else:
                out = bytes(self.buf[:n])
                del self.buf[:n]
                return out
        return self.sock.recv(n)

    def recv1(self):
        # receive exactly 1 byte (or b'')
        return self.recv(1)

def parse_headers(header_bytes):
    text = header_bytes.decode('iso-8859-1', errors='replace')
    head, _, _ = text.partition('\r\n\r\n')
    lines = head.split('\r\n')
    status = lines[0]
    hdrs = {}
    for line in lines[1:]:
        if ':' in line:
            k,v = line.split(':',1)
            hdrs[k.strip().lower()] = v.strip()
    return status, hdrs

def decode_chunked_bufbuf(bufsock, out_f, progress_callback=None, shaobj=None):
    total = 0
    while True:
        # read chunk-size line
        line = bytearray()
        while True:
            b = bufsock.recv1()
            if not b:
                raise IOError("Connection closed during chunked size")
            line.extend(b)
            if line.endswith(b'\r\n'):
                break
        size_str = line.strip().split(b';')[0]
        try:
            size = int(size_str, 16)
        except Exception:
            raise IOError("Invalid chunk size: %r" % (size_str,))
        if size == 0:
            # consume trailing CRLF after final 0 chunk
            # there may be trailers - read until \r\n\r\n (best-effort)
            # first consume the CRLF after 0 line if present
            # read next two bytes (CRLF) if any
            # then attempt to read until blank line
            # We'll try to consume until we see \r\n\r\n or timeout by reading a few KB
            # consume CRLF
            _ = bufsock.recv(2)
            # try read trailers harmlessly
            try:
                # small non-blocking read attempt
                bufsock.sock.settimeout(0.05)
                _ = bufsock.sock.recv(4096)
            except:
                pass
            break
        remaining = size
        while remaining > 0:
            chunk = bufsock.recv(min(BUFFER, remaining))
            if not chunk:
                raise IOError("Unexpected EOF in chunked encoding")
            out_f.write(chunk)
            if shaobj:
                shaobj.update(chunk)
            remaining -= len(chunk)
            total += len(chunk)
            if progress_callback:
                progress_callback(len(chunk))
        # consume trailing CRLF
        tail = bufsock.recv(2)
        # tolerate missing tail
    return total

def read_until_close_buf(bufsock, out_f, progress_callback=None, shaobj=None):
    total = 0
    while True:
        chunk = bufsock.recv(BUFFER)
        if not chunk:
            break
        out_f.write(chunk)
        if shaobj:
            shaobj.update(chunk)
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

        req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: http-get-large/1.1\r\nConnection: close\r\nAccept: */*\r\n\r\n"
        s.sendall(req.encode('ascii'))

        all_data, delim_idx = recv_until_raw(s, b'\r\n\r\n', timeout=10)
        if delim_idx == -1:
            # brak delimitera — cała odpowiedź przyszła albo zamknięto połączenie przed nagłówkami
            # spróbuj sparsować je w całości (może header + body w all_data)
            headers_part = all_data
            body_remainder = b''
        else:
            headers_part = all_data[:delim_idx+4]  # włącznie z \r\n\r\n
            body_remainder = all_data[delim_idx+4:]

        status_line, headers = parse_headers(headers_part)
        print("Status:", status_line)

        start_time = time.time()
        sha = hashlib.sha256()
        with open(out_file, 'wb') as f:
            bufsock = BufferedSocket(s, initial_buf=body_remainder)
            if 'content-length' in headers:
                try:
                    clen = int(headers['content-length'])
                except:
                    clen = None
                if clen is None:
                    # fallback to read-until-close
                    read_until_close_buf(bufsock, f, progress_callback=lambda b: [progress(b), sha.update(b)][1], shaobj=sha)
                else:
                    remaining = clen
                    # first consume from initial buffer (BufferedSocket does that automatically via recv)
                    while remaining > 0:
                        chunk = bufsock.recv(min(BUFFER, remaining))
                        if not chunk:
                            # EOF before expected length — zapisz to co mieliśmy i zakończ
                            print("\n[!] EOF reached before Content-Length fulfilled")
                            break
                        f.write(chunk)
                        sha.update(chunk)
                        remaining -= len(chunk)
                        progress(len(chunk))
            elif headers.get('transfer-encoding','').lower() == 'chunked':
                try:
                    decode_chunked_bufbuf(bufsock, f, progress_callback=lambda b: [progress(b), sha.update(b)][1], shaobj=sha)
                except Exception as e:
                    print("\n[!] Chunked decode error:", e)
                    # fallback: read until close whatever left
                    read_until_close_buf(bufsock, f, progress_callback=lambda b: [progress(b), sha.update(b)][1], shaobj=sha)
            else:
                # brak Content-Length i chunked -> read until socket close
                read_until_close_buf(bufsock, f, progress_callback=lambda b: [progress(b), sha.update(b)][1], shaobj=sha)

        elapsed = time.time() - start_time
        print(f"\nFinished: {total_downloaded/1024/1024:.2f} MB in {elapsed:.2f}s"
              f" ({(total_downloaded/1024/1024)/(elapsed if elapsed>0 else 1):.2f} MB/s)")
        print("SHA256:", sha.hexdigest())
    return total_downloaded, sha.hexdigest()

if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("Usage: python http_get_large_fix.py <host> <port> <path> <out_file> <local_ip>")
        print("Example: python http_get_large_fix.py 192.168.68.105 8000 /test.txt test.txt 192.168.68.106")
        sys.exit(2)
    host, port, path, out_file, local_ip = sys.argv[1:6]
    try:
        http_get(host, port, path, out_file, local_ip)
    except Exception as e:
        print("Error:", e)
        sys.exit(1)