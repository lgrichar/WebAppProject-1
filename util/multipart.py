import re

class MultipartData:
    def __init__(self, boundary, parts):
        self.boundary = boundary
        self.parts = parts

class Part:
    def __init__(self, headers, name, content):
        self.headers = headers
        self.name = name
        self.content = content

def parse_multipart(request):
    # get boundary from content type header
    content_type = request.headers.get('Content-Type', '')
    #print("headers:", request.headers)
    #print("content type:",content_type)
    boundary_match = re.search(r'boundary=(.*)', content_type)
    if not boundary_match:
        print("error: couldn't find boundary")  
    
    boundary = "--" + boundary_match.group(1)
    actualBoundary = boundary_match.group(1)

    #if not boundary.startswith('--'):
    #    boundary = '--' + boundary

    # split the body into parts
    parts = request.body.split(boundary.encode())[1:-1]
    
    parsed_parts = []

    for part in parts:
        part = part.strip(b'\r\n')

        headers_part, content_part = part.split(b'\r\n\r\n', 1)
        part_headers = {}

        # parse headers
        for header_line in headers_part.split(b'\r\n'):
            header_key, header_value = header_line.decode().split(': ', 1)
            part_headers[header_key] = header_value

        # get name from content disposition header
        content_disposition = part_headers.get('Content-Disposition')
        name_match = re.search(r'name="([^"]+)"', content_disposition)
        if not name_match:
            print("no name found from header")
            
        name = name_match.group(1)

        # add the part as a Part object
        parsed_parts.append(Part(part_headers, name, content_part))

    # return a MultipartData object
    return MultipartData(actualBoundary, parsed_parts)