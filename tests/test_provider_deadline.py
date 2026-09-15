from __future__ import annotations

import http.client
import threading
import time
import unittest
import urllib.request
from unittest import mock

from autofv import provider_deadline


class ProviderDeadlineTests(unittest.TestCase):
    def test_expiry_at_request_entry_cannot_reconnect_or_transmit(self) -> None:
        entered_request = threading.Event()
        finished_request = threading.Event()
        transmitted = threading.Event()

        class OwnedSocket:
            def __init__(self) -> None:
                self.closed = threading.Event()

            def settimeout(self, _timeout: float) -> None:
                return None

            def shutdown(self, _how: int) -> None:
                self.closed.set()

            def close(self) -> None:
                self.closed.set()

        class PausedConnection:
            instance: PausedConnection | None = None

            def __init__(self, _host: str, _port: int, *, timeout: float):
                self.timeout = timeout
                self.sock: OwnedSocket | None = None
                self.auto_open = True
                self.sockets: list[OwnedSocket] = []
                PausedConnection.instance = self

            def connect(self) -> None:
                self.sock = OwnedSocket()
                self.sockets.append(self.sock)

            def request(self, *_args, **_kwargs) -> None:
                entered_request.set()
                initial = self.sockets[0]
                if not initial.closed.wait(0.5):
                    raise AssertionError("deadline did not close the initial socket")
                if self.sock is None and self.auto_open:
                    self.connect()
                try:
                    if self.sock is None:
                        raise http.client.NotConnected()
                    transmitted.set()
                finally:
                    finished_request.set()

            def getresponse(self):
                raise OSError("no response after deadline")

            def close(self) -> None:
                sock, self.sock = self.sock, None
                if sock is not None:
                    sock.close()

        request = urllib.request.Request(
            "http://127.0.0.1:19085/v1/chat/completions",
            data=b"{}",
            method="POST",
        )
        with mock.patch(
            "autofv.provider_deadline.http.client.HTTPConnection",
            PausedConnection,
        ), self.assertRaises(TimeoutError):
            provider_deadline.open_upstream(
                request,
                timeout=0.1,
                deadline_monotonic_ns=time.monotonic_ns() + 100_000_000,
            )

        self.assertTrue(entered_request.is_set())
        self.assertTrue(finished_request.wait(0.5))
        self.assertFalse(transmitted.is_set())
        connection = PausedConnection.instance
        self.assertIsNotNone(connection)
        assert connection is not None
        self.assertEqual(len(connection.sockets), 1)
        self.assertTrue(all(item.closed.is_set() for item in connection.sockets))


if __name__ == "__main__":
    unittest.main()
