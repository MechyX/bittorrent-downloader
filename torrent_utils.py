import logging
import os
import struct

logging = logging.getLogger('torrent')

RESET_SEQUENCE = "\033[0m"
BLUE = '\033[94m'


def bytes_to_int_converter(data, power):
    size = 0
    for byte in data:
        if not isinstance(byte, int):
            byte = int(ord(byte))
        size += byte * 256 ** power
        power -= 1
    return size


def handle_have(peer_obj, payload):
    logging.debug(f"Handling Have request from {peer_obj.ip}:{peer_obj.port}")
    index = bytes_to_int_converter(payload, 3)
    peer_obj.bitField[index] = True


def generate_interested_message():
    return b'\x00\x00\x00\x01\x02'


def generate_block_request(index, offset, length):
    id_ = b'\x06'
    header = struct.pack('>I', 13)
    index = struct.pack('>I', index)
    offset = struct.pack('>I', offset)
    length = struct.pack('>I', length)
    return header + id_ + index + offset + length


def send_block_request(peer, peer_handler):
    if len(peer.buffer_to_write) > 0:
        return True

    for i in range(10):
        next_block = peer_handler.findNextBlock(peer)
        if not next_block:
            return

        index, offset, length = next_block
        peer.buffer_to_write = generate_block_request(index, offset, length)


def handle_peer_message(peer_obj, peer_handler, shared_mem):
    while len(peer_obj.buffer_to_read) > 3:
        if not peer_obj.handshake_succeeded:
            if not peer_handler.is_valid_peer(peer_obj):
                return False
            elif len(peer_obj.buffer_to_read) < 4:
                return True

        msgSize = bytes_to_int_converter(peer_obj.buffer_to_read[0:4], 3)
        if len(peer_obj.buffer_to_read) == 4:
            # To handle a Keep Alive request
            if msgSize == '\x00\x00\x00\x00':
                return True
            return True

        peer_code = int(ord(peer_obj.buffer_to_read[4:5]))
        payload = peer_obj.buffer_to_read[5:4 + msgSize]
        # Invalid message size
        if len(payload) < msgSize - 1:
            return True
        peer_obj.buffer_to_read = peer_obj.buffer_to_read[msgSize + 4:]
        if not peer_code:
            continue
            # Continue maintaining the connection

        elif peer_code == 0:
            # Peer is Choked
            peer_obj.choked = True
            continue

        elif peer_code == 1:
            # Peer is Un choked
            logging.debug(f"Not choked! Finding block to get from {peer_obj.ip}:{peer_obj.port}")
            peer_obj.choked = False
            send_block_request(peer_obj, peer_handler)

        elif peer_code == 4:
            handle_have(peer_obj, payload)

        elif peer_code == 5:
            peer_obj.set_bit_field(payload)

        elif peer_code == 7:
            index = bytes_to_int_converter(payload[0:4], 3)
            offset = bytes_to_int_converter(payload[4:8], 3)
            data = payload[8:]
            if index != peer_handler.current_piece.piece_index:
                return True

            piece = peer_handler.current_piece
            result = piece.add_new_block(offset, data)

            if not result:
                logging.debug("Not successful adding block. Disconnecting.")
                return False

            if piece.finished:
                peer_handler.num_pieces_so_far += 1
                if peer_handler.num_pieces_so_far < peer_handler.num_of_pieces:
                    peer_handler.current_piece = peer_handler.pieces.popleft()
                shared_mem.put((piece.piece_index, piece.blocks))
                logging.info(BLUE + f"Downloaded piece: {piece.piece_index} {RESET_SEQUENCE}")

            send_block_request(peer_obj, peer_handler)

        if not peer_obj.sentInterested:
            logging.debug("Bitfield initialised. Telling peer we are interested on a piece...")
            peer_obj.buffer_to_write = generate_interested_message()
            peer_obj.sentInterested = True
    return True


def generate_next_data(buffer, s_memory):
    while not s_memory.empty():
        index, data = s_memory.get()
        if not data:
            raise ValueError('Corrupted Piece detected.')
        buffer += ''.join(data)
        yield buffer


def write_to_multiple_files(files, path, peer_handler):
    file_content_iterable = None
    buffer = ''

    for file in files:
        appended_path = path + '/'.join(file['path'])
        if not os.path.exists(os.path.dirname(appended_path)):
            os.makedirs(os.path.dirname(appended_path))
        with open(appended_path, "w") as file_obj:
            length = file['length']
            if not file_content_iterable:
                file_content_iterable = generate_next_data(buffer, peer_handler)

            while length > len(buffer):
                buffer = next(file_content_iterable)

            file_obj.write(buffer[:length])
            buffer = buffer[length:]


def write_to_file(path, length, peer_handler):
    file_obj = open('./' + path, 'wb')
    buffer = ''

    file_content_iterable = generate_next_data(buffer, peer_handler)

    while length > len(buffer):
        buffer = next(file_content_iterable)

    file_obj.write(buffer[:length])
    file_obj.close()


def general_write(info, peer_handler):
    if 'files' in info:
        path = './' + info['name'] + '/'
        write_to_multiple_files(info['files'], path, peer_handler)
    else:
        write_to_file(info['name'], info['length'], peer_handler)
