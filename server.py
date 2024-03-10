import socketserver
import pymongo
import json
import re
import bcrypt
import os
import hashlib
from util.request import Request
from util.auth import extract_credentials, validate_password
from pymongo import MongoClient
from bson.json_util import dumps


mongo = MongoClient('mongo')
db = mongo["cse312"]
chat_collection = db["chat"]
user_collection = db["users"]
token_collection = db["tokens"]

class MyTCPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        received_data = self.request.recv(2048)
        
        if not received_data:
            return
        
        print(self.client_address)
        print("--- received data ---")
        print(received_data)
        print("--- end of data ---\n\n")
        request = Request(received_data)
        print(request.headers)
        print(request.path)
        print(request.body)

        if not request:
            return

        # TODO: Parse the HTTP request and use self.request.sendall(response) to send your response
        
        # get which type of request it is
        
        match = re.match(r'/chat-messages/(\d+)$', request.path)
        if request.method == 'DELETE' and match:
            message_id = match.group(1)
            self.handle_delete_chat_message(request, message_id)
            return
        
        if request.method == 'POST' :
            if request.path == '/chat-messages':
                self.handle_post_chat_messages(request)
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
            else:
                self.handle_normal(request)
        # else:
        #     self.handle_normal(request)
            
    
    def handle_post_chat_messages(self, request): # put messages in db
        print("posting a message")
        try:
            data = json.loads(request.body.decode('utf-8'))  # decoding from bytes to str
            message = self.escape_html(data['message'])
        
            # get XSRF token from the request
            xsrf_token = data.get('xsrfToken', '')

            # default is 'Guest'
            username = "Guest"
            valid_xsrf_token = False

            # get and validate the auth token
            token = self.get_auth_token(request)
            if token:
                token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
                token_entry = token_collection.find_one({"token": token_hash})
                if token_entry and 'xsrf_token' in token_entry and token_entry['xsrf_token'] == xsrf_token:
                    username = token_entry['username']
                    valid_xsrf_token = True  # XSRF token is valid

            if not valid_xsrf_token:
                self.send_error(403, 'Invalid XSRF token')
                return

            # inserting the chat message if the XSRF token is valid
            chat_message = {
                "message": message,
                "username": username,
                "id": str(chat_collection.count_documents({}) + 1)
            }

            chat_collection.insert_one(chat_message)  # insert document into db
            self.send_response(201, dumps(chat_message), 'application/json')

        except Exception as e:
            print("Error: ", e)  # debug
            self.send_error(500, 'Internal Server Error')
    
    def handle_get_chat_messages(self, request): # retrieve msg from db
        print("getting chat messages")
        try:
            messages = list(chat_collection.find({}, {'_id': 0})) # this was throwing not serializable errors for some reason
            response_body = dumps(messages)
            self.send_response(200, response_body, 'application/json')
            
        except Exception as e:
            print("Error: ",e) # debugging
            self.send_error(500, 'Internal Server Error')
            
    def handle_delete_chat_message(self, request, message_id):
        print("deleting a message")
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
        print("normal hanlding")
        # get file path
        if request.path == '/': # index.html page
            filepath = 'public/index.html'
        else:
            filepath = request.path.lstrip('/') # example /public/image/kitten.jpg
            print("requested filepath: ",filepath) 
            
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
        else:
            mime_type = 'text/plain'
            
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
                    content = content.replace('{{xsrf_token}}', '{xsrf_token}')
                
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
    

    def send_error(self, status, message):
        print("sending error")
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
        print("handling visits")
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
        print("returning visits")
        return visits
    
    def send_response(self, status_code, content, content_type='text/plain', additional_headers=None):
        print("sending response")
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
        return text.replace(">", "&gt;") \
                   .replace("<", "&lt;") \
                   .replace("&", "&amp;") \
                   .replace('"', "&quot;") \
                   .replace("'", "&#x27;") 
                   
    def handle_get_single_chat_message(self, message_id):
        print("getting single message")
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
        print("registering")
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
        print("logging in")
        username, password = extract_credentials(request)
        user = user_collection.find_one({"username": username})
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            auth_token = os.urandom(16).hex()
            token_hash = hashlib.sha256(auth_token.encode('utf-8')).hexdigest()
            xsrf_token = os.urandom(16).hex()  # random XSRF token
            token_collection.insert_one({"username": username, "token": token_hash, "xsrf_token": xsrf_token})
            self.set_auth_token_cookie(auth_token)
            request.xsrf_token = xsrf_token  # store xsrf in request
            self.redirect_to_home()
        else:
            self.send_error(401, 'Unauthorized')


    def handle_logout(self, request):
        print("logging out")
        token = self.get_auth_token(request)
        if token:
            token_collection.delete_one({"token": hashlib.sha256(token.encode('utf-8')).hexdigest()})
        self.clear_auth_token_cookie()
        self.redirect_to_home()
        
    def redirect_to_home(self):
        print("redirecting to home")
        self.send_response(302, 'Success', additional_headers={'Location': '/'})

    def set_auth_token_cookie(self, token):
        print("setting auth token")
        cookie_value = f'authToken={token}; HttpOnly; Max-Age=7200; Path=/'
        self.send_response(200, '', 'text/plain', {'Set-Cookie': cookie_value})

    def clear_auth_token_cookie(self):
        print("clearing auth token")
        cookie_value = 'authToken=deleted; HttpOnly; Max-Age=0; Path=/'
        self.send_response(200, '', 'text/plain', {'Set-Cookie': cookie_value})

    def get_auth_token(self, request):
        print("getting auth token")
        cookies = request.headers.get('Cookie', '')
        token = None
        for cookie in cookies.split(';'):
            if 'authToken' in cookie:
                token = cookie.split('=')[1].strip()
                break
        print("returning auth token")
        return token

def main():
    host = "0.0.0.0"
    port = 8080

    socketserver.TCPServer.allow_reuse_address = True

    server = socketserver.TCPServer((host, port), MyTCPHandler)

    print("Listening on port " + str(port))

    server.serve_forever()


if __name__ == "__main__":
    main()
