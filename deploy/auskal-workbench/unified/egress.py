"""Public-network-only proxy. DNS results are validated and connection IPs pinned."""
import http.client, ipaddress, select, socket, socketserver, threading, time, urllib.parse

BIND = '172.30.44.1'
SLOTS = threading.BoundedSemaphore(20)

def public_address(host, port):
    if not host or host.endswith('.local') or host.rstrip('.').lower() == 'localhost':
        raise ValueError('Private destinations are blocked')
    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    ips = list(dict.fromkeys(a[4][0] for a in answers))
    if not ips:raise ValueError('No public address')
    for ip in ips:
        addr = ipaddress.ip_address(ip)
        if not addr.is_global or (isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped):
            raise ValueError('Private, reserved, or mapped destination blocked')
    return ips[0]

def connect_public(host, port):
    return socket.create_connection((public_address(host, port), port), timeout=15)

class Proxy(socketserver.StreamRequestHandler):
    timeout = 20
    def handle(self):
        if not SLOTS.acquire(blocking=False): return
        try: self.process()
        except Exception as exc:
            try: self.wfile.write(b'HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 29\r\n\r\nDestination blocked or failed.')
            except OSError: pass
        finally: SLOTS.release()
    def process(self):
        line = self.rfile.readline(8193)
        if len(line)>8192: raise ValueError('Long request')
        method,target,_ = line.decode('latin1').strip().split(' ',2)
        headers=[]; size=0
        while True:
            line=self.rfile.readline(8193); size+=len(line)
            if size>32768: raise ValueError('Long headers')
            if line in (b'\r\n',b'\n',b''): break
            key,value=line.decode('latin1').split(':',1)
            if key.lower() not in {'proxy-authorization','proxy-connection','connection','upgrade','transfer-encoding','authorization'}:
                headers.append((key,value.strip()))
        if method=='CONNECT':
            parsed=urllib.parse.urlsplit('//'+target)
            if parsed.port!=443 or parsed.username or parsed.password: raise ValueError('Only HTTPS port 443')
            remote=connect_public(parsed.hostname,443)
            self.wfile.write(b'HTTP/1.1 200 Connection Established\r\n\r\n');self.wfile.flush()
            total=0; deadline=time.monotonic()+90
            with remote:
                while time.monotonic()<deadline and total<40*1024*1024:
                    ready,_,_=select.select([self.connection,remote],[],[],10)
                    if not ready: continue
                    for src in ready:
                        data=src.recv(65536)
                        if not data:return
                        total+=len(data)
                        (remote if src is self.connection else self.connection).sendall(data)
            return
        if method not in ('GET','HEAD'): raise ValueError('Passive requests only')
        parsed=urllib.parse.urlsplit(target)
        if parsed.scheme!='http' or parsed.port not in (None,80) or parsed.username or parsed.password:
            raise ValueError('Invalid public HTTP URL')
        remote=connect_public(parsed.hostname,80)
        with remote:
            route=urllib.parse.urlunsplit(('','',parsed.path or '/',parsed.query,''))
            hs=''.join(k+': '+v+'\r\n' for k,v in headers if k.lower()!='host')
            request=f'{method} {route} HTTP/1.1\r\nHost: {parsed.netloc}\r\n{hs}Connection: close\r\n\r\n'
            remote.sendall(request.encode('latin1'))
            total=0
            while total<40*1024*1024:
                data=remote.recv(65536)
                if not data:break
                total+=len(data);self.wfile.write(data)

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True

if __name__=='__main__':
    with Server((BIND,3182),Proxy) as server:
        print('REA public egress guard ready',flush=True)
        server.serve_forever()
