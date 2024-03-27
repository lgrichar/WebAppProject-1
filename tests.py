import unittest
from util.multipart import parse_multipart
from util.request import Request

class TestMultipartParsing(unittest.TestCase):
    def setUp(self):
        # Example multipart form data with text and file fields
        self.multipart_data = b"""\
POST /upload HTTP/1.1\r
Host: localhost\r
Content-Type: multipart/form-data; boundary=bound\r
\r
--bound\r
Content-Disposition: form-data; name="text"\r
\r
sample text\r
--bound\r
Content-Disposition: form-data; name="file"; filename="example.txt"\r
Content-Type: text/plain\r
\r
Hello, world!\r
--bound\r
""" #cannot indent/make this look nicer since it will mess with the carriage returns and number of spaces

    def test_multipart_parsing(self):
        request = Request(self.multipart_data)
        parsed = parse_multipart(request)

        # boundary is correctly extracted
        self.assertEqual(parsed['boundary'], "--bound")

        # number of parts
        self.assertEqual(len(parsed['parts']), 2)

        # first part text
        text_part = parsed['parts'][0]
        self.assertEqual(text_part['name'], "text")
        self.assertEqual(text_part['headers']["Content-Disposition"], 'form-data; name="text"')
        self.assertEqual(text_part['content'], b"sample text")

        # second part file
        file_part = parsed['parts'][1]
        self.assertEqual(file_part['name'], "file")
        self.assertEqual(file_part['headers']["Content-Disposition"], 'form-data; name="file"; filename="example.txt"')
        self.assertEqual(file_part['headers']["Content-Type"], "text/plain")
        self.assertEqual(file_part['content'], b"Hello, world!")

if __name__ == '__main__':
    unittest.main()
