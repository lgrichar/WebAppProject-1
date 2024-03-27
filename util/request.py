class Request:

    def __init__(self, request: bytes):
        # TODO: parse the bytes of the request and populate the following instance variables
        self.body = ""
        self.method = ""
        self.path = ""
        self.http_version = ""
        self.headers = {}
        self.cookies = {}
        self.xsrf_token = ""
        
        # decode the request from bytes to string
        request_str = request.decode()
        #print("recieved request_str:", request_str)

        # split decoded request into lines
        lines = request_str.split('\r\n')

        # get method, path, and HTTP version
        #print("headers:", lines[0])
        self.method, self.path, self.http_version = lines[0].split(' ')

        body_started = False
        body_lines = []

        for line in lines[1:]:
            if line == '' and not body_started: # end of headers
                body_started = True
                continue

            if body_started:
                body_lines.append(line)
            else:
                # split each line by first colon to separate key and value
                key, value = line.split(':', 1)
                self.headers[key.strip()] = value.strip()

                if key.lower() == 'cookie': # get cookies
                    cookies = value.split(';')
                    for cookie in cookies:
                        cookie_name, cookie_value = cookie.split('=', 1)
                        self.cookies[cookie_name.strip()] = cookie_value.strip()

        self.body = '\r\n'.join(body_lines).encode()





def test1GET():
    request = Request(b'GET / HTTP/1.1\r\nHost: localhost:8080\r\nConnection: keep-alive\r\n\r\n')
    assert request.method == "GET"
    assert "Host" in request.headers
    assert request.headers["Host"] == "localhost:8080"  # note: The leading space in the header value must be removed
    assert request.body == b""  # There is no body for this request.
    # When parsing POST requests, the body must be in bytes, not str

    # This is the start of a simple way (ie. no external libraries) to test your code.
    # It's recommended that you complete this test and add others, including at least one
    # test using a POST request. Also, ensure that the types of all values are correct


if __name__ == '__main__':
    test1GET()
