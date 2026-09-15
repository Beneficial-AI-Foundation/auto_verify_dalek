"""Absolute-deadline ownership for one explicitly connected HTTP exchange."""

from __future__ import annotations

import http.client
import socket
import threading
import time
import urllib.parse
import urllib.request
from typing import Any


def _remaining_seconds(deadline_monotonic_ns: int) -> float:
    remaining = (deadline_monotonic_ns - time.monotonic_ns()) / 1_000_000_000
    if remaining <= 0:
        raise TimeoutError("provider deadline expired")
    return min(30.0, remaining)


def reply_socket(reply: Any) -> Any:
    """Find the live socket even after HTTPConnection detached its response."""
    stream = reply
    seen: set[int] = set()
    for _ in range(8):
        if stream is None or id(stream) in seen:
            return None
        seen.add(id(stream))
        sock = getattr(stream, "_sock", None)
        if sock is not None:
            return sock
        stream = getattr(stream, "fp", None) or getattr(stream, "raw", None)
    return None


def set_reply_timeout(reply: Any, timeout: float) -> None:
    sock = reply_socket(reply)
    if sock is not None:
        sock.settimeout(timeout)


def _abort_socket(sock: Any) -> None:
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def _abort_connection(connection: http.client.HTTPConnection) -> None:
    _abort_socket(getattr(connection, "sock", None))
    try:
        connection.close()
    except OSError:
        pass


class _DeadlineController:
    """Own every socket reachable during one absolute-deadline request."""

    def __init__(self, connection: http.client.HTTPConnection, deadline: int):
        self.connection = connection
        self.deadline = deadline
        self.response: Any = None
        self.response_socket: Any = None
        self.stop = threading.Event()
        self.expired = threading.Event()
        self.lock = threading.Lock()
        self.timer = threading.Thread(target=self._close_at_deadline, daemon=True)

    def start(self) -> None:
        self.timer.start()

    def _close_at_deadline(self) -> None:
        wait = max(0.0, (self.deadline - time.monotonic_ns()) / 1_000_000_000)
        if not self.stop.wait(wait):
            self.expire()

    def abort(self) -> None:
        with self.lock:
            response_socket = self.response_socket
        _abort_socket(response_socket)
        _abort_connection(self.connection)

    def expire(self) -> None:
        self.expired.set()
        self.abort()

    def check(self) -> None:
        if self.expired.is_set() or time.monotonic_ns() >= self.deadline:
            self.expire()
            raise TimeoutError("provider deadline expired")

    def register_response(self, response: Any) -> None:
        response_socket = reply_socket(response)
        with self.lock:
            self.response = response
            self.response_socket = response_socket
        self.check()

    def close(self) -> None:
        self.stop.set()
        with self.lock:
            response = self.response
        try:
            if response is not None:
                response.close()
        finally:
            self.abort()
            if self.timer is not threading.current_thread():
                self.timer.join(timeout=0.2)


class DeadlineReply:
    def __init__(self, controller: _DeadlineController, response: Any):
        self.controller = controller
        self.response = response
        self.status = response.status
        self.fp = response

    @property
    def deadline_expired(self) -> bool:
        return self.controller.expired.is_set()

    def read(self, size: int) -> bytes:
        return self.response.read(size)

    def read1(self, size: int) -> bytes:
        return self.response.read1(size)

    def close(self) -> None:
        self.controller.close()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()
        return False


def open_upstream(
    request: urllib.request.Request,
    *,
    timeout: float,
    deadline_monotonic_ns: int | None = None,
) -> DeadlineReply:
    """Open one fixed request and close all transport state at its deadline."""
    deadline = deadline_monotonic_ns or (
        time.monotonic_ns() + int(timeout * 1_000_000_000)
    )
    remaining = _remaining_seconds(deadline)
    parsed = urllib.parse.urlsplit(request.full_url)
    connection_type = (
        http.client.HTTPSConnection
        if parsed.scheme == "https"
        else http.client.HTTPConnection
    )
    connection = connection_type(parsed.hostname, parsed.port, timeout=remaining)
    connection.auto_open = False
    controller = _DeadlineController(connection, deadline)
    completed = threading.Event()
    outcome: dict[str, Any] = {}
    path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))

    def open_request() -> None:
        try:
            connection.connect()
            controller.check()
            if connection.sock is not None:
                connection.sock.settimeout(_remaining_seconds(deadline))
            controller.check()
            connection.request(
                request.get_method(),
                path,
                body=request.data,
                headers=dict(request.header_items()),
            )
            response = connection.getresponse()
            controller.register_response(response)
            outcome["response"] = response
        except BaseException as exc:
            outcome["error"] = exc
        finally:
            if controller.expired.is_set():
                controller.close()
            completed.set()

    controller.start()
    threading.Thread(target=open_request, daemon=True).start()
    wait = max(0.0, (deadline - time.monotonic_ns()) / 1_000_000_000)
    if not completed.wait(wait):
        controller.expire()
        raise TimeoutError("provider deadline expired")
    error = outcome.get("error")
    if error is not None:
        controller.close()
        if controller.expired.is_set():
            raise TimeoutError("provider deadline expired") from error
        raise error
    try:
        controller.check()
    except TimeoutError:
        controller.close()
        raise
    return DeadlineReply(controller, outcome["response"])
