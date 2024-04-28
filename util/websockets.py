import base64
import hashlib

def compute_accept(websocket_key):
    GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
    hash = hashlib.sha1((websocket_key + GUID).encode())
    return base64.b64encode(hash.digest()).decode()

class WebSocketFrame:
    def __init__(self, fin_bit, opcode, payload_length, payload):
        self.fin_bit = fin_bit
        self.opcode = opcode
        self.payload_length = payload_length
        self.payload = payload

    def __str__(self):
        return (f"WebSocketFrame(fin_bit={self.fin_bit}, opcode={self.opcode}, "
                f"payload_length={self.payload_length}, payload={self.payload})")

def parse_ws_frame(frame):
    if len(frame) < 2:
        print("ERROR: Frame is less than 2 bytes in length")
    
    #print("frame recieved to parse:",frame)
    fin_bit = (frame[0] & 0x80) >> 7 # getting fin bit, AND mask and then change position
    opcode = frame[0] & 0x0F # 0001 for text, 0010 for binary, 1000 to close the connection, 0000 for continuation frame
    mask_bit = (frame[1] & 0x80) >> 7 # mask bit, if 1 must unmask
    hasMask = (mask_bit == 1)
    payload_length = frame[1] & 0x7F # initial payload length, used to determine actual length

    header_size = 2

    if payload_length == 126:
        if len(frame) < 4:
            print("ERROR: Length is less than 4")
        payload_length = int.from_bytes(frame[2:4], byteorder='big')
        #masking_key = frame[4:8]
        #payload_start = 8 # start at 8th byte position
        header_size += 2
    elif payload_length == 127:
        if len(frame) < 10:
            print("ERROR: Length is less than 10")
        payload_length = int.from_bytes(frame[2:10], byteorder='big')
        #masking_key = frame[10:14]
        #payload_start = 14
        header_size += 8
        
    if hasMask:
        if len(frame) < header_size + 4:
            print("ERROR: incomplete masking key")
        masking_key = frame[header_size:header_size + 4]
        #print("mask found")
        header_size += 4
    else:
        masking_key = None

    #print("payload length:", payload_length)
    #print("header size", header_size)
    total_frame_size = header_size + payload_length
    #if len(frame) < total_frame_size:
        #print("ERROR: incomplete frame data")
        #print("length of recieved frame is ", len(frame))
        #print("length of total frame", total_frame_size)

    
    payload_start = header_size
    
    if hasMask:
        decoded_payload = bytearray()
        for i in range(payload_length):
            #print("i =", i)
            #print("start =", payload_start)
            #print("end =", (payload_start + payload_length))
            frame_index = payload_start + i
            mask_index = i % 4
            # need to do them byte by byte, not in groups of 4 since it can give oob error
            #print("mask index", mask_index)
            decoded_byte = frame[frame_index] ^ masking_key[mask_index]
            decoded_payload.append(decoded_byte)
    else:
        decoded_payload = frame[payload_start:payload_start + payload_length]

    return WebSocketFrame(fin_bit, opcode, payload_length, decoded_payload)

def generate_ws_frame(data, opcode="0x81"):
    frame = bytearray()

    if opcode == "0x81":  # text frame
        frame.append(0x81)  # bx10000001
    elif opcode == "0x8":  # close frame
        frame.append(0x88)  # bx10001000
    else:
        frame.append(int(opcode, 16))
    
    print("data length", len(data))
    if len(data) < 126:
        print("small data", data)
        frame.append(len(data))
    elif len(data) < 65536:
        print("medium data", data)
        frame.append(126)
        frame.extend(len(data).to_bytes(2, byteorder='big'))
    else:
        print("big data", data)
        frame.append(127)
        frame.extend(len(data).to_bytes(8, byteorder='big'))
    
    frame.extend(data)
    print("regular frame:",frame)
    print("byte frame:",bytes(frame))
    return bytes(frame)


# Tests
# key = "dGhlIHNhbXBsZSBub25jZQ=="
# print("Computed Accept:", compute_accept(key))

# message = b"Hello WebSocket"
# print("Generate frame: ", generate_ws_frame(message))

# masked_frame = bytearray([0x81, 0x85, 0x01, 0x02, 0x03, 0x04, 0x49, 0x67, 0x6F, 0x68, 0x6E])
# parsed_frame = parse_ws_frame(masked_frame)
# print("Parsed frame:", parsed_frame)


