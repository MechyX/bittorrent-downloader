import logging
import random
import socket
import struct
from urllib.parse import urlparse

import bcoding
import requests

logging = logging.getLogger('scrape')


def send_msg(conn, sock, msg, trans_id, action, size, retry_count=0):
    sock.sendto(msg, conn)
    try:
        response = sock.recv(2048)
    except socket.timeout as err:
        logging.debug(err)
        logging.debug("Connecting again...")
        if retry_count < 3:
            return send_msg(conn, sock, msg, trans_id, action, size, retry_count + 1)
        else:
            raise TimeoutError(f"UDP Tracker: '{conn}' failed to respond in the given time limit")
    if len(response) < size:
        logging.debug("Did not get full message. Connecting again...")
        return send_msg(conn, sock, msg, trans_id, action, size)

    if action != response[0:4] or trans_id != response[4:8]:
        logging.debug("Transaction or Action ID did not match. Trying again...")
        return send_msg(conn, sock, msg, trans_id, action, size)

    return response


def make_announce_input(info_hash, conn_id, peer_id):
    action = struct.pack('!i', 1)
    trans_id = struct.pack('!i', random.randrange(0, 255))

    downloaded = struct.pack('!Q', 0)
    left = struct.pack('!Q', 0)
    uploaded = struct.pack('!Q', 0)

    event = struct.pack('!i', 0)
    ip = struct.pack('!i', 0)
    key = struct.pack('!i', 0)
    num_want = struct.pack('!i', -1)
    port = struct.pack('>h', 8000)

    msg = (conn_id + action + trans_id + info_hash + peer_id + downloaded +
           left + uploaded + event + ip + key + num_want + port)

    return msg, trans_id, action


def make_connection_id_request():
    conn_id = struct.pack('!q', 0x41727101980)
    action = struct.pack('!i', 0x0)
    trans_id = struct.pack('!i', random.randrange(0, 255))

    return conn_id + action + trans_id, trans_id, action


def scrape_http(announce, info_hash, peer_id, length):
    params = {'info_hash': info_hash,
              'peer_id': peer_id,
              'uploaded': 0,
              'downloaded': 0,
              'port': 6881,
              'left': str(length).encode('utf-8'),
              'corrupt': 0,
              'event': 'started',
              }

    response = requests.get(announce, params=params)

    if response.status_code > 400:
        message = ("Failed to connect to torrent_dict.\n"
                   "Status Code: %s \n"
                   "Reason: %s") % (response.status_code, response.reason)
        raise RuntimeError(message)

    print(f'Tracker Response : {response}')
    results = bcoding.bdecode(response.content)
    return results['peers']


def scrape_udp(info_hash, announce, peer_id):
    parsed = urlparse(announce)
    ip = socket.gethostbyname(parsed.hostname)
    if ip == '127.0.0.1':
        return False
    try:
        # TODO : Needs verification
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(8)
        conn = (ip, parsed.port)
        msg, trans_id, action = make_connection_id_request()
        response = send_msg(conn, sock, msg, trans_id, action, 16)
        conn_id = response[8:]
        msg, trans_id, action = make_announce_input(info_hash, conn_id, peer_id)
        response = send_msg(conn, sock, msg, trans_id, action, 20)

        payload = bcoding.bdecode(response)
        return payload['peers']
    except TimeoutError:
        return ''
