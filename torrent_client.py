import logging
import multiprocessing
import select
import socket

from torrent_utils import handle_peer_message, general_write


class TorrentClient(multiprocessing.Process):
    """
    Torrent Client process that will handle all network interactions with trackers and peers and
    keeps looping until the path is fully downloaded.
    """

    def __init__(self, threadID, name, peer_handler, shared_mem, debug_mode=False, info_mode=True):
        multiprocessing.Process.__init__(self)
        self.name = name
        self.thread_id = threadID
        self.shared_memory = shared_mem
        if debug_mode:
            logging.basicConfig(level=logging.DEBUG)
        elif info_mode:
            logging.basicConfig(level=logging.INFO)
        self.peer_handler = peer_handler

    def connect(self):
        for peer in self.peer_handler.peers:
            try:
                peer.sock.connect((peer.ip, peer.port))
            except socket.error:
                pass
            # Ignore peer_obj in case any errors arise when we connect to it

    def remove_peer(self, peer):
        if peer in self.peer_handler.peers:
            self.peer_handler.peers.remove(peer)

    def run(self):
        """
        The main loop that will perform all the activities
        """
        self.connect()
        while not self.peer_handler.check_if_finished():
            write = [x for x in self.peer_handler.peers if x.buffer_to_write != '']
            read = self.peer_handler.peers[:]
            read_list, write_list, _ = select.select(read, write, [])

            for peer in write_list:
                sendMsg = peer.buffer_to_write
                try:
                    peer.sock.send(sendMsg)
                except socket.error as err:
                    logging.debug(err)
                    self.remove_peer(peer)
                    continue
                peer.buffer_to_write = b''

            for peer in read_list:
                try:
                    peer.buffer_to_read += peer.sock.recv(2048)
                except socket.error as err:
                    logging.debug(err)
                    self.remove_peer(peer)
                    continue
                result = handle_peer_message(peer, self.peer_handler, self.shared_memory)
                if not result:
                    # Peer sent a message that we were not able to handle so we disconnect
                    peer.sock.close()
                    self.remove_peer(peer)

            if len(self.peer_handler.peers) <= 0:
                raise Exception("Peers not enough!")
        general_write(self.peer_handler.torrent_dict['info'], self.shared_memory)
