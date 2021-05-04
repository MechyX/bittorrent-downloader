import hashlib
import logging
import math
import socket
import time
from collections import deque

import bcoding
from bitstring import BitArray

import pieces
import tracker_scraper

logging = logging.getLogger('peer_handler')


def _parse_sock_addr(raw_bytes):
    socks_addr = []

    # socket address : <IP(4 bytes)><Port(2 bytes)>
    # len(socket addr) == 6 bytes
    for i in range(int(len(raw_bytes) / 6)):
        start = i * 6
        end = start + 6
        ip = socket.inet_ntoa(raw_bytes[start:(end - 2)])
        raw_port = raw_bytes[(end - 2):end]
        port = raw_port[1] + raw_port[0] * 256

        socks_addr.append({'ip': ip, 'port': port})

    return socks_addr


class PeersHandler(object):
    """
    Holds the torrent_dict information and the list of ip addresses and ports.


    Params:
    torrent_file_path   --   takes in a .torrent torrent_dict path.

    Instance Variables:
    self.peer_id        --   our peer_id for that torrent_file.
    self.peers          --   list of the currently connected peers, that has the corresponding peer_objs
    self.pieces         --   list of Piece objects that contains the pieces.
    self.torrent_dict   --   decoded torrent file dictionary.
    self.infoHash       --   has the SHA1 hash_bytes of info dict.
    self.num

    """
    HEADER_SIZE = 28

    def __init__(self, torrent_file_path):
        self.peers = []
        self.pieces = deque([])
        self.peer_id = hashlib.sha1(str(time.time()).encode('utf-8')).digest()
        self.torrent_dict = bcoding.bdecode(open(torrent_file_path, 'rb').read())
        bencode_info = bcoding.bencode(self.torrent_dict['info'])
        self.infoHash = hashlib.sha1(bencode_info).digest()
        self.generate_peer_connections()
        self.generate_pieces_objects()
        self.num_pieces_so_far = 0

    def generate_pieces_objects(self):
        logging.info("Initializing... peer lists")
        hashes = self.torrent_dict['info']['pieces']
        piece_length = self.torrent_dict['info']['piece length']
        if 'files' in self.torrent_dict['info']:
            files = self.torrent_dict['info']['files']
            totalLength = sum([file['length'] for file in files])
            self.num_of_pieces = int(math.ceil(float(totalLength) / piece_length))
        else:
            totalLength = self.torrent_dict['info']['length']
            self.num_of_pieces = int(math.ceil(float(totalLength) / piece_length))

        counter = totalLength
        self.total_torrent_length = totalLength
        for i in range(self.num_of_pieces):
            if i == self.num_of_pieces - 1:
                self.pieces.append(pieces.Piece(i, counter, hashes[0:20]))
            else:
                self.pieces.append(pieces.Piece(i, piece_length, hashes[0:20]))
                counter -= piece_length
                hashes = hashes[20:]

        self.current_piece = self.pieces.popleft()

    def generate_peer_connections(self):
        """
        Gets the list of Peers from the trackers and starts connecting to them with a non-blocking sockets and
        add it to the list of peers
        """
        trackers = []
        if 'announce-list' in self.torrent_dict:
            trackers = self.torrent_dict['announce-list']
        else:
            trackers.append([self.torrent_dict['announce']])
        peers_list = None
        for announce in trackers:
            announce_url = announce[0].lower()
            if announce_url.startswith('http'):
                length = str(self.torrent_dict['info']['piece length'])
                peers_list = tracker_scraper.scrape_http(announce_url, self.infoHash, self.peer_id, length)
            elif announce_url.startswith('udp'):
                peers_list = tracker_scraper.scrape_udp(self.infoHash, announce_url, self.peer_id)

            if peers_list:
                break

        for peer_info in peers_list:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(False)
            peer = Peer(peer_info['ip'], peer_info['port'], sock, self.infoHash, self.peer_id)
            self.peers.append(peer)

    def findNextBlock(self, peer):
        """
        Algorithm used to find the next missing block
        """
        # TODO: Can be made more peer_obj specific to make it more faster and efficient
        for block_index in range(self.current_piece.number_of_blocks):
            if not self.current_piece.block_tracker[block_index]:
                if block_index == self.current_piece.number_of_blocks - 1:
                    size = self.current_piece.generate_last_piece_size()
                else:
                    size = pieces.BLOCK_SIZE
                return self.current_piece.piece_index, block_index * pieces.BLOCK_SIZE, size
        return None

    def check_if_finished(self):
        return self.num_pieces_so_far == self.num_of_pieces

    def is_valid_peer(self, peer_obj):
        """
        Check to see if the info hash_bytes from the peer_obj matches with the one we have
        from the .torrent path.
        """
        hash_from_peer = peer_obj.buffer_to_read[self.HEADER_SIZE:self.HEADER_SIZE + len(self.infoHash)]

        if hash_from_peer == self.infoHash:
            peer_obj.handshake_succeeded = True
            peer_obj.buffer_to_read = peer_obj.buffer_to_read[self.HEADER_SIZE + len(self.infoHash) + 20:]
            logging.debug(f"Valid handshake from {peer_obj.ip}:{peer_obj.port}")
            return True
        return False


class Peer(object):
    """
    Peer Object that is used to handle the interactions with a Peer

    self.ip - IP address of this peer_obj.
    self.port - Port number of the peer_obj.
    self.choked - indicates if the peer_obj choked or not
    self.bitField - Bitfield that indicates the what pieces the peer_obj has.
    self.sock - Socket object used to communicate with the peer_obj
    self.buffer_to_write - Buffer that needs to be sent out to the Peer.
    self.buffer_to_read - Buffer that needs to be read and parsed then handled.
    self.handshake_succeeded - Boolean indicating if handshake_succeeded was successful
    """

    def __init__(self, ip, port, sock, infoHash, peer_id):
        self.ip = ip
        self.port = port
        self.choked = False
        self.bitField = None
        self.sentInterested = False
        self.sock = sock
        self.buffer_to_write: bytes = self.generate_handshake_message(infoHash, peer_id)
        self.buffer_to_read: bytes = b''
        self.handshake_succeeded = False

    @staticmethod
    def generate_handshake_message(infoHash, peer_id):
        """
        Generates the handshake message to be sent to the peer_obj
        """
        pstrlen = b'\x13'
        pstr = b'BitTorrent protocol'
        reserved = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        if isinstance(peer_id, str):
            peer_id = peer_id.encode('utf-8')

        handshake = pstrlen + pstr + reserved + infoHash + peer_id
        return handshake

    def set_bit_field(self, payload):
        """
        Sets the bit field of the peer_obj
        """
        self.bitField = BitArray(bytes=payload)

    def fileno(self):
        """
        Used internally by the select module
        """
        return self.sock.fileno()
