import sys
from queue import PriorityQueue

from peers import PeersHandler
from torrent_client import TorrentClient


def download_torrent(torrent_file_path):
    s_memory = PriorityQueue()
    peer_handler = PeersHandler(torrent_file_path)
    torrent_client = TorrentClient(1, "Main_Torrent_Process", peer_handler, s_memory, debug_mode=True)
    torrent_client.run()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('ERROR: no torrent file')
        exit(1)

    download_torrent(sys.argv[1])
