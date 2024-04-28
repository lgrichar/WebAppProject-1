import socketserver
import pymongo
import json
import re
import bcrypt
import os
import hashlib
from util.request import Request
from util.auth import extract_credentials, validate_password
from util.multipart import parse_multipart
from util.websockets import compute_accept, parse_ws_frame, generate_ws_frame
from pymongo import MongoClient
from bson.json_util import dumps


mongo = MongoClient('mongo')
db = mongo["cse312"]
chat_collection = db["chat"]
user_collection = db["users"]
token_collection = db["tokens"]
active_connections = []

class MyTCPHandler(socketserver.BaseRequestHandler):
    username = "Guest"
    def handle(self):
        received_data = self.request.recv(2048)
        
        if not received_data:
            return
        
        print(self.client_address)
        print("--- received data ---")
        print(received_data)
        print("--- end of data ---\n\n")
        request = Request(received_data)
        #print(request.headers)
        #print(request.path)
        #print(request.body)

        if not request:
            return

        # TODO: Parse the HTTP request and use self.request.sendall(response) to send your response
        
        # get which type of request it is
        
        if request.headers.get("Upgrade", "").lower() == "websocket" and request.path == "/websocket":
            print("Websocket upgrade request initiated")
            self.handle_websocket_handshake(request)
            return
        
        match = re.match(r'/chat-messages/(\d+)$', request.path)
        if request.method == 'DELETE' and match:
            message_id = match.group(1)
            self.handle_delete_chat_message(request, message_id)
            return
        
        if request.method == 'POST' :
            if request.path == '/chat-messages':
                self.handle_post_chat_messages(request)
            if request.path == '/image-upload':
                self.handle_post_image_messages(request)
            if request.path == '/login':
                self.handle_login(request)
            if request.path == '/register':
                self.handle_registration(request)
    
        elif request.method == 'GET':
            # see if single message
            match = re.match(r'/chat-messages/(\d+)', request.path) # use re library to evaluate regular expression
            if match: 
                message_id = match.group(1)
                self.handle_get_single_chat_message(message_id)
            elif request.path == '/chat-messages':
                self.handle_get_chat_messages(request)
            elif request.path == '/logout':
                self.handle_logout(request)
            elif request.path == '/login':
                self.handle_normal(request)
            else:
                self.handle_normal(request)
        # else:
        #     self.handle_normal(request)
    
    def handle_websocket_handshake(self, request):
        key = request.headers.get('Sec-WebSocket-Key')
        if not key:
            print("no key found")
            self.send_error(400, 'bad request: no Sec-WebSocket-Key')
            return
        #print("ket found", key)
    
        username = self.get_username_from_token(request)
        self.username = username
    
        accept_val = compute_accept(key)
        #print("doing accept_val", accept_val)
        response_headers = [
            'HTTP/1.1 101 Switching Protocols',
            'Upgrade: websocket',
            'Connection: Upgrade',
            f'Sec-WebSocket-Accept: {accept_val}',
            '\r\n'
        ]
        #print("sending handshake response")
        #print(response_headers)
        self.request.sendall('\r\n'.join(response_headers).encode())

        # after handshake, enter a loop to read and handle WebSocket frames
        self.handle_websocket_communication(username)
    
    def handle_websocket_communication(self, username):
        #print("handlding websocket communication")
        active_connections.append(self)
        #print("active_connections now contains", active_connections)
        buffer = bytearray()
        message_buffer = bytearray()
        current_opcode = None
        self.update_user_list()
        try:
            while active_connections.__contains__(self): #maybe should be true, the goal of this is to go while the connection is active
                #print("getting more data")
                self.update_user_list()
                data = self.request.recv(4096) # get more bytes from socket
                if not data:
                    break  # no more data connection closed

                buffer.extend(data) # add new data onto buffer

                while True:
                    if len(buffer) < 2:  # not enough data to read even the smallest frame header
                        #print("buffer too small")
                        break

                    length = buffer[1] & 0x7F
                    #print("length:", length)
                    if length == 126:
                        #print("length is 126")
                        if len(buffer) < 4:
                            break  # not enough data for extended length
                        length = int.from_bytes(buffer[2:4], byteorder='big')
                        header_size = 8
                    elif length == 127:
                        #print("length is 127")
                        if len(buffer) < 10:
                            break # wont be able to read ahead not enough data
                        length = int.from_bytes(buffer[2:10], byteorder='big')
                        header_size = 14
                    else:
                        #print("header size 6") # add masking byte
                        header_size = 6

                    total_size = header_size + length
                    #print("total size", total_size)
                    if len(buffer) < total_size:
                        #print("not enough data for full frame, breaking")
                        break  # not enough data for the full frame

                    frame_data = buffer[:total_size]
                    buffer = buffer[total_size:]  # remove this frame data from buffer

                    frame = parse_ws_frame(frame_data) # using what we made earlier to get frame object
                    # self.process_frame(frame) #check if final message opcode
                    if frame.opcode == 0x1 or frame.opcode == 0x2:
                        #print("current opcode", frame.opcode)
                        current_opcode = frame.opcode  # set current opcode for new message
                    elif frame.opcode == 0x0 and current_opcode is not None:
                        pass 
                        
                    message_buffer.extend(frame.payload)
                    if frame.fin_bit == 1:  # this is the final piece
                        #print("processing complete message", username)
                        self.process_complete_message(message_buffer, username)
                        current_opcode = None
                        message_buffer.clear()  # clear the message buffer for the next message
                        
                    if frame.opcode == 0x8:  # check if final message opcode and close if so
                        #print("closing connection")
                        self.close_connection()
                        return
                        # if fin_bit == 0 do nothing just continue to accumulate

        except Exception as e:
            print(f"WebSocket communication error: {e}")
        finally:
            if self in active_connections:
                self.close_connection

    def process_complete_message(self, message, username):
        try:
            message_text = message.decode('utf-8')
            message_data = json.loads(message_text)
            
            #print("processing message text:", message_text)
        
            #print("complete message received:", message_data)

            # process the message based on its type
            if message_data.get('messageType') == 'chatMessage':
                #print("type is chat message")
                self.handle_tcp_chat_message(message_data, username)
            else:
                print("Received an unknown message type", message_data.get('messageType'))

        except json.JSONDecodeError:
            print("Failed to decode JSON from message")
        except Exception as e:
            print(f"Error processing complete message: {e}")

    def handle_tcp_chat_message(self, message, username):
        #print("posting a message")
        self.update_user_list()
        try:
            message_text = self.escape_html(message.get('message'))
            id = str(chat_collection.count_documents({}) + 1)
            # insert the chat message
            chat_message = {
                "message": message_text,
                "username": username,
                "id": id
            }
            
            print("inserting chat message", chat_message)

            chat_collection.insert_one(chat_message)  # insert document into db
            # self.send_response(201, dumps(chat_message), 'application/json')
            broadcast_chat_message = {
                'messageType': 'chatMessage',
                'username': username,
                'message': message_text,
                'id': id
            }
            #print("broadcasting message")
            #print(broadcast_chat_message)
            self.broadcast_message(json.dumps(broadcast_chat_message)) #send to everyone, including the sender
            

        except Exception as e:
            print("Error: ", e)  # debug
            self.send_error(500, 'Internal Server Error')
    
    def broadcast_message(self, message): # send message to all connections, closing any that dont work correctly
        message_frame = generate_ws_frame(bytes(message, 'utf-8'))
        print("broadcasting to ",len(active_connections),"active connections")
        print("active connections:", active_connections)
        closed_connections = []
        
        for connection in active_connections:
            try:
                if connection.request.fileno() != -1: # socket is still valid
                    #print("sending message", connection.client_address)
                    connection.request.sendall(message_frame)
                else:
                    #print("socket already closed for", connection.client_address)
                    closed_connections.append(connection)
            except Exception as e:
                #print(f"Failed to send message to {connection.client_address}: {e}")
                closed_connections.append(connection)
        
        for conn in closed_connections:
            active_connections.remove(conn)
            conn.close_connection()
    
    def close_connection(self):
        try:
            if self.request.fileno() != -1: # only attempt to close the connection if it hasn't already been closed
                status_code = 1000
                reason = "normal closure"
                payload = status_code.to_bytes(2, 'big') + reason.encode('utf-8')
                close_frame = generate_ws_frame(payload, opcode="0x8")
                self.request.sendall(close_frame)
                self.request.close()
        except Exception as e:
            print("error closing connection:", e)
        finally:
            self.update_user_list()
            if self in active_connections:
                active_connections.remove(self)
            print("closed websocket connection for", self.client_address)
    
    def handle_post_image_messages(self, request):
        #print("handling post image")
        try:
            # print("made it to try statement")
            boundary = request.headers.get('Content-Type', '').split('boundary=')[1]
            final_boundary = f"--{boundary}--\r\n".encode()
            received_data = b''
            received_data += request.body # getting initial data
            
            #count = 0
            while not received_data.endswith(final_boundary): # buffering all the data before parsing and storing in db
                #print("recieving more data", count)
                packet = self.request.recv(4096)
                if not packet:
                    #print("breaking")
                    #print("received data:",received_data)
                    break
                received_data += packet
                
            request.body = received_data
            #print("request is now",request)
        
            username = "Guest"

            # Security STUFFFFF
            # get and validate the auth token
            token = self.get_auth_token(request)
            if token:
                #print("getting token")
                token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
                token_entry = token_collection.find_one({"token": token_hash})
            
                # if auth token is valid, check for XSRF token
                if token_entry:
                    #print("found token")
                    username = token_entry['username']
            
            #print("parsing data")
            parsed_data = parse_multipart(request)

            for part in parsed_data.parts:
                #print("going through parts")
                if part.name == 'upload':
                    #print("in upload part")
                    
                    file_extension = 'jpg' if part.content[:3] == b'\xFF\xD8\xFF' else 'mp4'
                    media_tag = '<img width="400"' if file_extension == 'jpg' else '<video width = \'400\' controls autoplay muted>'

                    # Determine the new filename
                    file_number = len(os.listdir('public/media')) + 1
                    filename = f"media{file_number}.{file_extension}"
                    filepath = os.path.join('public/media/', filename)
                        
                    file_number = len(os.listdir('public/media')) + 1
                    filename = f"media{file_number}.{file_extension}"
                    filepath = os.path.join('public/media/', filename)

                    with open(filepath, 'wb') as f:
                        #print("writing file contents")
                        f.write(part.content)

                    # generate chat message with image or video
                    if media_tag == '<video width = \'400\' controls autoplay muted>':
                        chat_message = f'{media_tag}<source src="/public/media/{filename}" type="video/mp4" alt="Uploaded {file_extension}"/></video>'
                    else:
                        chat_message = f'{media_tag} src="/public/media/{filename}" type="image/jpeg" alt="Uploaded {file_extension}"/></img>'

                    # insert chat message/image into database
                    chat_collection.insert_one({"message": chat_message, "username": username, "id": str(chat_collection.count_documents({}) + 1)})
            self.send_response(302, 'Redirect', additional_headers={'Location': '/'})
        
        except Exception as e:
            print("Error: ", e) #debugging
            self.send_error(500, 'Internal Server Error')
    
    def handle_post_chat_messages(self, request):  # put messages in db
        print("posting a message")
        try:
            content_type = request.headers.get('Content-Type', '')
            
            
            data = json.loads(request.body.decode('utf-8'))  # decoding from bytes to str
            message = self.escape_html(data['message'])
        
            # default username is 'Guest'
            username = "Guest"
        
            # get and validate the auth token
            token = self.get_auth_token(request)
            if token:
                token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
                token_entry = token_collection.find_one({"token": token_hash})
            
                # if auth token is valid, check for XSRF token
                if token_entry:
                    xsrf_token = data['xsrfToken']
                    # xsrf_token = request.headers.get('xsrfToken', '')
                    #print("post chat: xsrf found: ", xsrf_token)
                
                    # validate XSRF token
                    if 'xsrf_token' in token_entry and token_entry['xsrf_token'] == xsrf_token:
                        username = token_entry['username']
                    else:
                        # if XSRF token does not match, send a 403 error
                        self.send_error(403, 'Invalid XSRF token')
                        return
        
            # insert the chat message
            chat_message = {
                "message": message,
                "username": username,
                "id": str(chat_collection.count_documents({}) + 1)
            }
        
            chat_collection.insert_one(chat_message)  # insert document into db
            # self.send_response(201, dumps(chat_message), 'application/json')
            # now is the part where we do socket stuff instead
            
            # send the chat message to everyone, with the correct format
            

        except Exception as e:
            print("Error: ", e)  # debug
            self.send_error(500, 'Internal Server Error')

    def validate_xsrf_token(self, request):
        xsrf_token = request.headers.get('X-XSRF-Token')  # Assuming XSRF token is sent in custom header
        if not xsrf_token:
            return False  # No XSRF token provided

        token = self.get_auth_token(request)
        if token:
            token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
            token_entry = token_collection.find_one({"token": token_hash})
            return token_entry and 'xsrf_token' in token_entry and token_entry['xsrf_token'] == xsrf_token

        return False  # No valid auth token or XSRF token mismatch

    def get_username_from_token(self, request):
        username = "Guest"  # default username
        token = self.get_auth_token(request)
        if token:
            token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
            token_entry = token_collection.find_one({"token": token_hash})
            if token_entry:
                username = token_entry['username']
        return username
        
    def handle_get_chat_messages(self, request): # retrieve msg from db
        #print("getting chat messages")
        try:
            messages = list(chat_collection.find({}, {'_id': 0})) # this was throwing not serializable errors for some reason
            response_body = dumps(messages)
            self.send_response(200, response_body, 'application/json')
            
        except Exception as e:
            print("Error: ",e) # debugging
            self.send_error(500, 'Internal Server Error')
        except BrokenPipeError as e:
            print("Error: ",e) # debugging
            self.send_error(500, 'Broken Pipe Error: Client closed TCP connection')
            
    def handle_delete_chat_message(self, request, message_id):
        #print("deleting a message")
        # get the auth token from the request
        token = self.get_auth_token(request)
        if not token:
            self.send_error(401, 'Unauthorized')
            return
    
        # get the auth token and retrieve the corresponding username
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
        token_entry = token_collection.find_one({"token": token_hash})
        if not token_entry:
            self.send_error(401, 'Unauthorized')
            return

        username = token_entry['username']

        # if the message belongs to the user
        message = chat_collection.find_one({"id": message_id})
        if not message:
            self.send_error(404, 'Message not found')
            return
    
        if message['username'] != username:
            self.send_error(403, 'Forbidden')
            return

        # delete the message
        chat_collection.delete_one({"id": message_id})
        self.send_response(200, 'Message deleted')
    
    def handle_normal(self, request):
        visits = None
        #print("normal hanlding")
        
        base_directory = 'public'
        
        # get file path
        if request.path == '/': # index.html page
            filepath = 'public/index.html'
        else:
            safe_filepath = os.path.normpath(request.path.lstrip('/')) # example /public/image/kitten.jpg
            filepath = safe_filepath # sanitizing filepath to prevent directory traversal
            #print("requested filepath: ",filepath) 
            
            if not filepath.startswith(base_directory): # directory traversal may have occured
                #print("Forbidden: ", filepath)
                self.send_error(403, 'Forbidden')
                return
            
        # get MIME type
        if filepath.endswith('.html'):
            mime_type = 'text/html'
        elif filepath.endswith('.css'):
            mime_type = 'text/css'
        elif filepath.endswith('.js'):
            mime_type = 'text/javascript'
        elif filepath.endswith('.jpg') or filepath.endswith('.jpeg'):
            mime_type = 'image/jpeg'
        elif filepath.endswith('.png'):
            mime_type = 'image/png'
        elif filepath.endswith('.ico'):
            mime_type = 'image/x-icon'
        elif filepath.endswith('.mp4'):
            mime_type = 'video/mp4'
        else:
            mime_type = 'text/plain'
            
        try:
            # start opening in bytes
            with open(filepath, 'rb') as f:
                f.seek(0, os.SEEK_END)
                file_size = f.tell()
                f.seek(0)
                content = f.read()
            
                if mime_type == 'text/html' and request.path == '/': # only if its index.html
                    content = content.decode('utf-8')  # decode to utf8
                    # update visits
                    visits = self.handle_visits(request)
                    content = content.replace('{{visits}}', str(visits))
                
                     # put the XSRF token into the HTML content
                    token = self.get_auth_token(request)
                    if token:
                        #print("Found token: ", token)
                        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
                        token_entry = token_collection.find_one({"token": token_hash})
                        #print("Hashed token: ", token_hash)
                        if token_entry:
                            #print("found token entry")
                            xsrf_token = token_entry.get('xsrf_token', '')
                            content = content.replace('{{xsrf_token}}', xsrf_token)
                        else:
                            print("couldn't find token entry")
                
                    content = content.encode('utf-8')  # encode back to bytes

                # if this is a range request
                range_header = request.headers.get('Range', '')
                if range_header:
                    print("range header found!")
                    _, range_value = range_header.split('=')
                    start_str, end_str = range_value.split('-')
                    start = int(start_str) if start_str else 0
                    end = int(end_str) if end_str else file_size - 1
            
                    f.seek(start)
                    content = f.read(end - start + 1)
            
                    headers = [
                        'HTTP/1.1 206 Partial Content',
                        f'Content-Type: {mime_type}; charset=UTF-8' if mime_type.startswith('text/') else f'Content-Type: {mime_type}',
                        f'Content-Length: {end - start + 1}',
                        f'Content-Range: bytes {start}-{end}/{file_size}',
                        'Accept-Ranges: bytes',
                        'X-Content-Type-Options: nosniff',
                    ]
                else:
                    # create headers
                    headers = [
                        'HTTP/1.1 200 OK',
                        f'Content-Type: {mime_type}; charset=UTF-8' if mime_type.startswith('text/') else f'Content-Type: {mime_type}',
                        f'Content-Length: {len(content)}',
                        'X-Content-Type-Options: nosniff'
                    ]
            
                if visits is not None:
                    headers.append(f'Set-Cookie: visits={visits}; Path=/; Max-Age=14400')
                
                if mime_type == 'video/mp4':
                    headers.append(f'Cache-Control: public, max-age=31536000')

                headers.append('\r\n')

                # send full header and body
                self.request.sendall('\r\n'.join(headers).encode() + content)
                pass

        except BrokenPipeError as e:
            print("Error: ",e) # debugging
            #self.send_error(500, 'Broken Pipe Error: Client closed TCP connection')
        except FileNotFoundError:
            self.send_error('404 Not Found', 'Content not found.')
        except Exception as e:
            print("Error: ",e) # debugging
            self.send_error('500 Internal Server Error', f'An unexpected error occurred: {e}')
    
    def send_error(self, status, message):
        #print("sending error")
        enc_msg = message.encode('utf-8')  #encode message in utf8 to bytes
        response_headers = [
            f'HTTP/1.1 {status}',
            'Content-Type: text/plain; charset=utf-8',
            f'Content-Length: {len(enc_msg)}',
            'X-Content-Type-Options: nosniff',
            '\r\n'
        ]
        response = '\r\n'.join(response_headers).encode('utf-8') + enc_msg
        self.request.sendall(response)

    def handle_visits(self, request):
        #print("handling visits")
        # get the auth token from the request
        token = self.get_auth_token(request)
        username = None
    
        # if token, try to find the corresponding username
        if token:
            token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
            token_entry = token_collection.find_one({"token": token_hash})
            if token_entry:
                username = token_entry['username']
    
        if username:
            # if logged in, find and update their visit count
            user = user_collection.find_one({"username": username})
            if user:
                visits = user.get('visits', 0) + 1
                user_collection.update_one({"username": username}, {"$set": {"visits": visits}})
            else:
                # a default visit count
                visits = 1
        else:
            visits = 1 # more default
        #print("returning visits")
        return visits
    
    def send_response(self, status_code, content, content_type='text/plain', additional_headers=None):
        #print("sending response")
        if isinstance(content, str):  # must be in bytes
            content = content.encode('utf-8')

        # headers
        response_headers = [
            f'HTTP/1.1 {status_code} OK',
            f'Content-Type: {content_type}; charset=UTF-8',
            f'Content-Length: {len(content)}',
            'X-Content-Type-Options: nosniff',]

        # additional headers
        if additional_headers:
            for header, value in additional_headers.items():
                response_headers.append(f'{header}: {value}')

        response_headers.append('\r\n')

        response = '\r\n'.join(response_headers).encode('utf-8') + content
        self.request.sendall(response)

    def escape_html(self, text):
        return text.replace("&", "&amp;") \
                   .replace(">", "&gt;") \
                   .replace("<", "&lt;") \
                   .replace('"', "&quot;") \
                   .replace("'", "&#x27;") 
                   
    def handle_get_single_chat_message(self, message_id):
        #print("getting single message")
        try:
            id = int(message_id)
            message = chat_collection.find_one({"id": str(id)}, {'_id': 0}) # avoid json serializable error
            if message:
                response_body = dumps(message)
                self.send_response(200, response_body, 'application/json')
            else:
                self.send_error(404, 'Not Found') # no message found
        except ValueError: 
            self.send_error(400, 'Bad Request') #invalid int value
        except Exception as e:
            print("Error: ", e) # debug statement
            self.send_error(500, 'Internal Server Error')
    
    def handle_registration(self, request):
        #print("registering")
        username, password = extract_credentials(request)
        if not validate_password(password):
            self.send_error(400, 'Bad Password')
            return
        if user_collection.find_one({"username": username}):
            self.send_error(400, 'Username already exists')
            return
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user_collection.insert_one({"username": username, "password": hashed})
        self.redirect_to_home()

    def handle_login(self, request):
        valid = False
        print("logging in")
        username, password = extract_credentials(request)
        user = user_collection.find_one({"username": username})
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            auth_token = os.urandom(16).hex()
            token_hash = hashlib.sha256(auth_token.encode('utf-8')).hexdigest()
            xsrf_token = os.urandom(16).hex()  # random XSRF token
            token_collection.insert_one({"username": username, "token": token_hash, "xsrf_token": xsrf_token})
            token_collection.update_one({"username": username}, {"$set": {"xsrf_token": xsrf_token}}, upsert=True) #stupid fix
            # self.set_auth_token_cookie(auth_token)
            cookie_value = f'authToken={auth_token}; HttpOnly; Max-Age=7200; Path=/'
            request.xsrf_token = xsrf_token  # store xsrf in request
            #print(username, " logged in xsrf: ", xsrf_token)
            valid = True
            # self.redirect_to_home()
            print("redirecting to home")
            self.username = username
            self.update_user_list()
            self.send_response(302, 'Success', additional_headers={'Location': '/', 'Set-Cookie': cookie_value})
            
            return
        else:
            self.send_error(401, 'Unauthorized')
            return
            
        if valid:
            self.redirect_to_home()

    def handle_logout(self, request):
        print("logging out")
        token = self.get_auth_token(request)
        if token:
            token_collection.delete_one({"token": hashlib.sha256(token.encode('utf-8')).hexdigest()})
        self.clear_auth_token_cookie()
        self.close_connection()
        self.redirect_to_home()
        
    def update_user_list(self):
        print("updating user list")
        active_usernames = []
        print("There are ", len(active_connections))
        for conn in active_connections:
            if hasattr(conn, 'username') and conn.username != "Guest":
                print("logging user",conn.username)
                active_usernames.append(conn.username)
        msg = {
            "messageType": "userListUpdate",
            "action": "update",
            "users": active_usernames
        }
        message_json = json.dumps(msg)
        self.broadcast_message(message_json) 
        
    def redirect_to_home(self):
        #print("redirecting to home")
        self.send_response(302, 'Success', additional_headers={'Location': '/'})

    def set_auth_token_cookie(self, token):
        #print("setting auth token")
        cookie_value = f'authToken={token}; HttpOnly; Max-Age=7200; Path=/'
        self.send_response(200, '', 'text/plain', {'Set-Cookie': cookie_value})

    def clear_auth_token_cookie(self):
        #print("clearing auth token")
        cookie_value = 'authToken=deleted; HttpOnly; Max-Age=0; Path=/'
        self.send_response(200, '', 'text/plain', {'Set-Cookie': cookie_value})

    def get_auth_token(self, request):
        #print("getting auth token")
        cookies = request.headers.get('Cookie', '')
        token = None
        for cookie in cookies.split(';'):
            if 'authToken' in cookie:
                token = cookie.split('=')[1].strip()
                break
        #print("returning auth token")
        return token
    
    def load_homepage(self, request):
        visits = None
        #print("loading homepage")
        # get file path
        filepath = 'public/index.html'
        mime_type = 'text/html'
            
        try:
            # start opening in bytes
            with open(filepath, 'rb') as f:
                content = f.read()
            
            if mime_type == 'text/html' and request.path == '/': # only if its index.html
                content = content.decode('utf-8')  # decode to utf8
                # update visits
                visits = self.handle_visits(request)
                content = content.replace('{{visits}}', str(visits))
                
                 # put the XSRF token into the HTML content
                xsrf_token = getattr(request, 'xsrf_token', None)
                if xsrf_token:
                    #print("adding xsrf token to page")
                    content = content.replace('{{xsrf_token}}', str(xsrf_token))
                
                content = content.encode('utf-8')  # encode back to bytes

            # create headers
            headers = [
                'HTTP/1.1 200 OK',
                f'Content-Type: {mime_type}; charset=UTF-8' if mime_type.startswith('text/') else f'Content-Type: {mime_type}',
                f'Content-Length: {len(content)}',
                'X-Content-Type-Options: nosniff'
            ]
            
            if visits is not None:
                headers.append(f'Set-Cookie: visits={visits}; Path=/; Max-Age=14400')

            headers.append('\r\n')

            # send full header and body
            self.request.sendall('\r\n'.join(headers).encode() + content)
            pass

        except FileNotFoundError:
            self.send_error('404 Not Found', 'Content not found.')
        except Exception as e:
            print("Error: ",e) # debugging
            self.send_error('500 Internal Server Error', f'An unexpected error occurred: {e}')

def main():
    
    host = "0.0.0.0"
    port = 8080

    socketserver.ThreadingTCPServer.allow_reuse_address = True

    server = socketserver.ThreadingTCPServer((host, port), MyTCPHandler)

    print("Listening on port " + str(port))

    server.serve_forever()


if __name__ == "__main__":
    main()
