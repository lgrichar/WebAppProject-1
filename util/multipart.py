import re

def parse_multipart(request):
    # get boundary from content type header
    content_type = request.headers.get('Content-Type', '')
    boundary_match = re.search(r'boundary=(.*)', content_type)
    if not boundary_match:
        print("error: couldn't find boundary")
        raise ValueError('header doesnt have boundary')
    
    boundary = boundary_match.group(1)

    if not boundary.startswith('--'):
        boundary = '--' + boundary

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
            print("No name found from header")
            raise ValueError('No name in Content-Disposition header')

        name = name_match.group(1)

        parsed_parts.append({
            'headers': part_headers,
            'name': name,
            'content': content_part 
        })

    return {
        'boundary': boundary,
        'parts': parsed_parts
    }