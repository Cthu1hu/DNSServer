# dns_server.py

import socket
import struct
import time
import threading

import dns.message
import dns.name
import dns.rdatatype
import dns.resolver

from cache_utils import forward_cache, reverse_cache, cache_lock, ResourceRecord

class CachedDNSServer:
    def __init__(self, listen_addr='0.0.0.0', port=53):
        self.addr = listen_addr
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.addr, self.port))

        self.root_servers = [
            '198.41.0.4',
            '199.9.14.201',
            '192.33.4.12',
        ]
        self.query_timeout = 2
        self.query_retries = 2

        print(f"[dns_server] Initialized on {self.addr}:{self.port}.")

    def start(self):
        print(f"[dns_server] DNS-сервер запущен и слушает {self.addr}:{self.port} ...")
        while True:
            try:
                data, client_addr = self.sock.recvfrom(4096)
                threading.Thread(
                    target=self.handle_query, args=(data, client_addr), daemon=True
                ).start()
            except Exception as e:
                print(f"[dns_server] Error on recvfrom: {e}")

    def handle_query(self, data: bytes, client_addr):
        try:
            request = dns.message.from_wire(data)
        except Exception:
            return

        qname = request.question[0].name.to_text()
        qtype = request.question[0].rdtype
        qclass = request.question[0].rdclass

        key = (qname, qtype)
        now = time.time()

        with cache_lock:
            found_records = []
            if qtype in (dns.rdatatype.PTR,):
                if qname.endswith('.in-addr.arpa.'):
                    parts = qname.replace('.in-addr.arpa.', '').split('.')
                    ip = '.'.join(parts[::-1])
                    if ip in reverse_cache:
                        for rr in reverse_cache[ip]:
                            if rr.expire > now:
                                found_records.append(rr)
            else:
                if qname in forward_cache:
                    for rr in forward_cache[qname]:
                        if rr.rtype == qtype and rr.expire > now:
                            found_records.append(rr)

        if found_records:
            response = dns.message.Message(id=request.id)
            response.flags |= dns.flags.QR
            response.flags |= dns.flags.RA
            response.set_rcode(dns.rcode.NOERROR)

            for rr in found_records:
                ttl = rr.remaining_ttl()
                try:
                    rdataset = dns.rdataset.from_text(
                        rr.rclass, rr.rtype, ttl, rr.rdata if isinstance(rr.rdata, str) else rr.rdata.decode('utf-8', errors='ignore')
                    )
                except Exception:
                    if rr.rtype == dns.rdatatype.A:
                        rdataset = dns.rdataset.from_rdata(
                            rr.rclass, ttl, dns.rdata.from_text(rr.rclass, rr.rtype, rr.rdata)
                        )
                    else:
                        continue

                response.answer.append(dns.rrset.RRset(rr.name, rr.rtype, rr.rclass, rdataset))

            wire = response.to_wire()
            try:
                self.sock.sendto(wire, client_addr)
            except Exception:
                pass
            return

        full_response = self.recursive_resolve(qname, qtype)
        if full_response is None:
            servfail = dns.message.make_response(request)
            servfail.set_rcode(dns.rcode.SERVFAIL)
            try:
                self.sock.sendto(servfail.to_wire(), client_addr)
            except Exception:
                pass
            return

        full_response.id = request.id
        try:
            self.sock.sendto(full_response.to_wire(), client_addr)
        except Exception:
            pass
        now = time.time()
        with cache_lock:
            for rrset in full_response.answer:
                name = rrset.name.to_text()
                for item in rrset:
                    ttl = rrset.ttl
                    rdata_text = item.to_text()
                    rr_obj = ResourceRecord(name, rrset.rdtype, rrset.rdclass, ttl, rdata_text)
                    forward_cache.setdefault(name, []).append(rr_obj)

                    if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                        ip_str = item.to_text()
                        ptr_name = ip_str
                        ptr_rr = ResourceRecord(ip_str, dns.rdatatype.PTR, rrset.rdclass, ttl, name)
                        reverse_cache.setdefault(ip_str, []).append(ptr_rr)

            for rrset in full_response.authority:
                name = rrset.name.to_text()
                for item in rrset:
                    ttl = rrset.ttl
                    rdata_text = item.to_text()
                    rr_obj = ResourceRecord(name, rrset.rdtype, rrset.rdclass, ttl, rdata_text)
                    forward_cache.setdefault(name, []).append(rr_obj)

            for rrset in full_response.additional:
                name = rrset.name.to_text()
                for item in rrset:
                    ttl = rrset.ttl
                    rdata_text = item.to_text()
                    rr_obj = ResourceRecord(name, rrset.rdtype, rrset.rdclass, ttl, rdata_text)
                    forward_cache.setdefault(name, []).append(rr_obj)
                    if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                        ip_str = item.to_text()
                        ptr_rr = ResourceRecord(ip_str, dns.rdatatype.PTR, rrset.rdclass, ttl, name)
                        reverse_cache.setdefault(ip_str, []).append(ptr_rr)

        try:
            self.sock.sendto(full_response.to_wire(), client_addr)
        except Exception:
            pass

    def recursive_resolve(self, qname: str, qtype: int):
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = self.root_servers
        resolver.timeout = self.query_timeout
        resolver.lifetime = self.query_timeout * self.query_retries

        try:
            answer = resolver.resolve(qname, qtype, raise_on_no_answer=False)
            return answer.response
        except Exception:
            return None

    def print_cache(self):
        print("\n=== FORWARD CACHE (ДОМЕН → IP) ===")
        with cache_lock:
            for domain, rr_list in forward_cache.items():
                for rr in rr_list:
                    if rr.remaining_ttl() > 0:
                        print(f"{domain:<30} → {rr.rdata} (TTL: {rr.remaining_ttl()})")

        print("\n=== REVERSE CACHE (IP → ДОМЕН) ===")
        with cache_lock:
            for ip, rr_list in reverse_cache.items():
                for rr in rr_list:
                    if rr.remaining_ttl() > 0:
                        print(f"{ip:<20} → {rr.rdata} (TTL: {rr.remaining_ttl()})")
