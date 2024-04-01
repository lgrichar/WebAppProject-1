class Request:

    def __init__(self, request: bytes):
        # TODO: parse the bytes of the request and populate the following instance variables
        self.method = ""
        self.path = ""
        self.http_version = ""
        self.headers = {}
        self.cookies = {}
        # self.xsrf_token = ""
        
        # split request into header and body parts, added for hw3
        header_part, body_part = request.split(b'\r\n\r\n', 1)

        # header part to utf8 while body stays as bytes
        header_text = header_part.decode('utf-8')
        
        # request lines and headers
        lines = header_text.split('\r\n')
        self.method, self.path, self.http_version = lines[0].split(' ')

        self.headers = {}
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                self.headers[key.strip()] = value.strip()
                
        self.body = body_part
        
        if 'cookie' in self.headers:
            cookie_str = self.headers['cookie']
            cookies = cookie_str.split('; ')
            for cookie in cookies:
                name, value = cookie.split('=', 1)
                self.cookies[name.strip()] = value.strip()


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

