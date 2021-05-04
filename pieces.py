import hashlib
import math

from bitstring import BitArray

BLOCK_SIZE = 2 ** 14


class Piece(object):
    """
    A class representing the Piece of a Torrent. Has all the required information for
    checking the status of the current piece.

    self.piece_index          --    index of piece in the torrent.
    self.piece_size           --    has the size of the current piece.
    self.piece_hash           --    has the hash_bytes of this particular piece
    self.finished             --    indicates if this piece was downloaded or not
    self.blocks               --    list that has the actual blocks
    self.number_of_blocks           --    number of block that piece should contain
    self.block_tracker        --    bit array that keep track of what blocks are missing
    self.blocks_downloaded    --    indicates the number of blocks downloaded
    """

    def __init__(self, index, size, hash_bytes):
        self.piece_index = index
        self.piece_size = size
        self.piece_hash = hash_bytes
        self.finished = False
        self.number_of_blocks = int(math.ceil(float(size) / BLOCK_SIZE))
        self.block_tracker = BitArray(self.number_of_blocks)
        self.blocks = [False] * self.number_of_blocks
        self.blocks_downloaded = 0

    def add_new_block(self, offset, data):
        if offset == 0:
            index = 0
        else:
            index = int(offset / BLOCK_SIZE)

        if not self.block_tracker[index]:
            self.blocks_downloaded += 1
            self.blocks[index] = data
            self.block_tracker[index] = True

        if all(self.block_tracker):
            self.finished = True
            return self.check_hash()
        return True

    def generate_last_piece_size(self):
        return self.piece_size - ((self.number_of_blocks - 1) * BLOCK_SIZE)

    def reset_bitfield(self):
        """Reset the piece data when we receive bad data and need to discord it"""
        self.block_tracker = BitArray(self.number_of_blocks)
        self.finished = False

    def check_hash(self):
        allData = b''.join(self.blocks)

        hashed_data = hashlib.sha1(allData).digest()
        if hashed_data == self.piece_hash:
            self.block = allData
            return True
        else:
            self.reset_bitfield()
            return False
