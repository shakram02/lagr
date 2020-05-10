import tempfile
import io
import multiprocessing


class ProcessOutputStream(io.TextIOBase):
    """
    Child process captured output stream.
    """

    def __init__(self):
        self.content = None
        (self.child_conn, self.parent_conn) = multiprocessing.Pipe()

    def write(self, s):
        self.child_conn.send(s)

    def close(self):
        self.child_conn.close()

    def read(self):
        if self.content is not None:
            return self.content

        content = None
        while self.parent_conn.poll():
            if not content:
                content = "\n"
            content += self.parent_conn.recv()

        self.content = content
        return self.content

    def cleanup(self, line_count=32):
        if self.content is None:
            return None
        content = self.content.split("\n")
        content = content[:line_count]
        content = "\n".join(content)

        return content
