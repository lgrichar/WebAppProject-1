import unittest
from util.multipart import parse_multipart, Part, MultipartData
from util.request import Request

class TestMultipartParsing(unittest.TestCase):
    def setUp(self):
        # Example multipart form data with text and file fields
        self.multipart_data = b"""\
POST /form-path HTTP/1.1\r
Content-Length: 252\r
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryfkz9sCA6fR3CAHN4\r
\r
------WebKitFormBoundaryfkz9sCA6fR3CAHN4\r
Content-Disposition: form-data; name="commenter"\r
\r
Jesse\r
------WebKitFormBoundaryfkz9sCA6fR3CAHN4\r
Content-Disposition: form-data; name="comment"\r
\r
Good morning!\r
------WebKitFormBoundaryfkz9sCA6fR3CAHN4--\r
""" #cannot indent/make this look nicer since it will mess with the carriage returns and number of spaces

    def test_multipart_parsing(self):
        request = Request(self.multipart_data)
        parsed = parse_multipart(request)

        # boundary is correctly extracted
        self.assertEqual(parsed.boundary, "----WebKitFormBoundaryfkz9sCA6fR3CAHN4")

        # number of parts
        self.assertEqual(len(parsed.parts), 2)

        # first part text
        text_part = parsed.parts[0]
        self.assertEqual(text_part.name, "commenter")
        self.assertEqual(text_part.headers["Content-Disposition"], 'form-data; name="commenter"')
        self.assertEqual(text_part.content, b"Jesse")

        # second part file
        file_part = parsed.parts[1]
        self.assertEqual(file_part.name, "comment")
        self.assertEqual(file_part.headers["Content-Disposition"], 'form-data; name="comment"')
        #self.assertEqual(file_part['headers']["Content-Type"], "content type goes here if it is a file")
        self.assertEqual(file_part.content, b"Good morning!")

if __name__ == '__main__':
    unittest.main()
