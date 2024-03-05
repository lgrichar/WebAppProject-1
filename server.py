import socketserver
import pymongo
import json
import re
from util.request import Request
from pymongo import MongoClient
from bson.json_util import dumps


mongo = MongoClient('mongo')
db = mongo["cse312"]
chat_collection = db["chat"]

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

        if not request:
            return

        # TODO: Parse the HTTP request and use self.request.sendall(response) to send your response
        
        # get which type of request it is
        
        if request.method == 'POST' and request.path == '/chat-messages':
            self.handle_post_chat_messages(request)
        elif request.method == 'GET':
            # see if single message
            match = re.match(r'/chat-messages/(\d+)', request.path) # use re library to evaluate regular expression
            if match: 
                message_id = match.group(1)
                self.handle_get_single_chat_message(message_id)
            elif request.path == '/chat-messages':
                self.handle_get_chat_messages(request)
            else:
                self.handle_normal(request)
        else:
            self.handle_normal(request)
        
    
    
    def handle_post_chat_messages(self, request): # put messages in db
        
        try:
            data = json.loads(request.body)
            message = self.escape_html(data['message'])
            chat_message = { # create document with key value pairs
                "message": message,
                "username": "Guest",
                "id": str(chat_collection.count_documents({}) + 1)
            }
            chat_collection.insert_one(chat_message) # insert document into db
            self.send_response(201, dumps(chat_message))
            
        except Exception as e:
            print("Error: ",e) # debug
            self.send_error(500, 'Internal Server Error')
    
    def handle_get_chat_messages(self, request): # retrieve msg from db
        
        try:
            messages = list(chat_collection.find({}, {'_id': 0})) # this was throwing not serializable errors for some reason
            response_body = dumps(messages)
            self.send_response(200, response_body, 'application/json')
            
        except Exception as e:
            print("Error: ",e) # debugging
            self.send_error(500, 'Internal Server Error')
    
    def handle_normal(self, request):
        visits = None
        
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
                visits = self.handle_visits(request.cookies)
                content = content.replace('{{visits}}', str(visits))
                content = content.encode('utf-8')  # Encode back to bytes

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

    def handle_visits(self, cookies):
        visits = 1  # if no cookie is found
        if 'visits' in cookies:
            visits = int(cookies['visits']) + 1
        return visits
    
    def send_response(self, status_code, content, content_type='text/plain'):
        if isinstance(content, str): # must be in bytes
            content = content.encode('utf-8')

        # build headers
        response_headers = [
            f'HTTP/1.1 {status_code} OK',
            f'Content-Type: {content_type}; charset=UTF-8',
            f'Content-Length: {len(content)}',
            'X-Content-Type-Options: nosniff',
            '\r\n'
        ]

        response = '\r\n'.join(response_headers).encode('utf-8') + content
        self.request.sendall(response)
        
    def escape_html(self, text):
        return text.replace(">", "&gt;") \
                   .replace("<", "&lt;") \
                   .replace("&", "&amp;") \
                   .replace('"', "&quot;") \
                   .replace("'", "&#x27;") 
                   
    def handle_get_single_chat_message(self, message_id):
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


def main():
    host = "0.0.0.0"
    port = 8080

    socketserver.TCPServer.allow_reuse_address = True

    server = socketserver.TCPServer((host, port), MyTCPHandler)

    print("Listening on port " + str(port))

    server.serve_forever()


if __name__ == "__main__":
    main()
