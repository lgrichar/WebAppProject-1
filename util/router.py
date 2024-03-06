import re

class Router:
    def __init__(self):
        self.routes = []

    def add_route(self, method, path, func):
        # Prepend '^' to the path regex to match from the start
        # and ensure it's interpreted as a regular expression
        regex = re.compile("^" + path)
        self.routes.append((method, regex, func))

    def route_request(self, request):
        for method, regex, func in self.routes:
            if request.method == method and regex.match(request.path):
                return func(request)
        # If no route matches, return a 404 response
        return self.not_found_response()

    def not_found_response(self):
        return b'HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nPage not found.'