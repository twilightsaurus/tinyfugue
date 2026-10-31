#!/usr/bin/env python3
"""Deterministic loopback regressions for socket reincarnation and nested sends."""

import argparse
import os
from pathlib import Path
import re
import socket
import pty
try:
    import ssl
except ImportError:
    ssl = None
import subprocess
import tempfile
import struct
import threading
import zlib

TIMEOUT = 15
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def recv_or_eof(conn):
    try:
        return conn.recv(4096)
    except ConnectionResetError:
        return b""


def expected_telnet_transports(expected):
    with_msdp = expected[:3] + b"\xff\xfd\x45" + expected[3:]
    return ([expected], [with_msdp])


# Self-signed loopback fixture; this private key has no use outside the tests.


TEST_CERT = """-----BEGIN CERTIFICATE-----
MIIDSTCCAjGgAwIBAgIUOqMXJSibek12Op1VHcFwgcxDFKMwDQYJKoZIhvcNAQEL
BQAwJTEjMCEGA1UEAwwadGYtc29ja2V0LWxpZmV0aW1lLmludmFsaWQwIBcNMjYx
MDE3MTkzNTQ1WhgPMjEyNjA5MjMxOTM1NDVaMCUxIzAhBgNVBAMMGnRmLXNvY2tl
dC1saWZldGltZS5pbnZhbGlkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEA3vaDjvCndccXVuxp8eQ5wW7CI5NF0SRvEClIF6SppItF6wYidfX3xPXjXxed
4+AXHZFa5E7Pf7ANgO6jQeuq1DzyjOlRjgGtol6QVv+/MDOOMLErJRtLlKxcEWcE
6s6l0ApXH4k9ezuh6yAl+M9FMFXJxBKIr7JOY2hikuQAXRgHPe8VsIYzCekxx+f8
N6Wi+/EddNKhJcid3AgjOwM1P25mtDUnO0YmizI4kQzpBXv5Qu+5xAtkmsMvrwRb
uufw0OrXdoRePyGi1XkQWQurzHKo3Fkjs654Kexo9zyiVFRh4t1vaf26ydHcmBNp
iezxsk1aYGm2SF6ZMWc/eVMu9QIDAQABo28wbTAdBgNVHQ4EFgQUthZJxAAd7COf
2j6ev/XZz2YBbVIwHwYDVR0jBBgwFoAUthZJxAAd7COf2j6ev/XZz2YBbVIwDwYD
VR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwDQYJKoZI
hvcNAQELBQADggEBAA90jRoeTvaAa3GbAwfPOQBNR3k2RCjnLmn2+n7B4RY3H2iF
kJXnsyO3wPegX6iryr2/eJB40TRX3AQQt4y2f20F64bX5M4zKc9L1Qm14QWVrgUn
wgHtWtNOv1Xx6GuM3azYqbohNqwNP1Fyn1duvl9OWOFRv1qZEg+POtj3frmxhsxE
oYtDUS+OKuWIhOGROSFgyErROyUemFoEZ1oTrjrCN33gu/XY+fT10Fu13US2MQY+
HDMLpnK/sHQYqFM4gTqLz+BCOamv3ArD2uheoW+f8l3Rh/3sSdedL7l7L7hg0Yo8
GPAGekG/ms+PddgiD4bUq+qXkT2qAekrmdYcQms=
-----END CERTIFICATE-----
"""

TEST_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDe9oOO8Kd1xxdW
7Gnx5DnBbsIjk0XRJG8QKUgXpKmki0XrBiJ19ffE9eNfF53j4BcdkVrkTs9/sA2A
7qNB66rUPPKM6VGOAa2iXpBW/78wM44wsSslG0uUrFwRZwTqzqXQClcfiT17O6Hr
ICX4z0UwVcnEEoivsk5jaGKS5ABdGAc97xWwhjMJ6THH5/w3paL78R100qElyJ3c
CCM7AzU/bma0NSc7RiaLMjiRDOkFe/lC77nEC2Sawy+vBFu65/DQ6td2hF4/IaLV
eRBZC6vMcqjcWSOzrngp7Gj3PKJUVGHi3W9p/brJ0dyYE2mJ7PGyTVpgabZIXpkx
Zz95Uy71AgMBAAECggEAITo2HWt+XVZEA2t8l3Smac4Ohxw3y6UFGzC3wnRC5tdt
nkqeAJvdJqBpV97OZCsdbsXeeIdJM5OCU6xcrqKHJRWHJRpRUdssq/WxR5HaBX4t
atLAZgmFED1GhD5o1HBi9BfSZ4v9mlum9AIovoVvH3ateLe1YI+vUG+6Pv9VEYpP
sEt+yOVZWR9S2co3TOYMmoGwLG3HQkAMdAob0tGxUIUFy0gvmK6vmZiwWW9B+/I5
P+sfOWeE7I7CQEopddivWtn9EirIFgqGeZdqui24LYUwwTXv15zKasksB023tCQC
kgVwEEhoQHtzs+IoLMMR1H+pgXKFy8PQshYQvGUrOQKBgQD1Lc36chMPJEtnevzY
O2l7xRFsxyUCSfh/NgY+s2AdQtdv5s0wl4E/CZcWtS8Utl/BoeLlWEiWY8pF3Utw
O8eaynf1TuMMZTRjaM7rmMujiexsqCcD5PMJEkFhIlRbA2qy5bIqJDuIl7ahwtgz
wQIlTWK6R4x4M6/ZGZ/aQizIfQKBgQDozbLEfLRwgcrZKnftE3SlK/L4b4GN5i2V
jCr7jUdWVoZ0rlv35r0G5m1SnzQ7EL3JIZ0eo0UxJceHkjbl+pdZnyq7aQm4Nhv4
F/wrlvLtv1BKn2vpky0qE20SXoluuNeG0bXZEpua/48V+I+1HzEsblBA2u67cucv
O1I8M8PB2QKBgQCmTF891EohJxkOI1mEwSeXD9/1zE3J86pdfqNVvA0hS8kc2Yur
vdeojjSw7kv03I6uo8NmlC8H8r+sC6Gzipik4VfkR5GxQqP6GYjgPE9DqbV3Lcbo
2U4PhRZbcBGPeg3RMgNamiDXUTBLIAHNeMifzJF+kDEzBrvroXnPbLs7cQKBgQCr
Kjnq32lnYvZ6rw/XvjtACc0tvgY6B2eykYk0xI4Tu7BF78Bsxzhp71enrKghWVDA
pbc4xIBl/0nxsp4sfw9ydGVdv3/G8fmkcjYU8noQNV5aT1ZvOKe3TOsf22QehUbp
uByEynqf/o/8bnFykMl9ymm1FYL7TSMPBgWTf9fJGQKBgHt22p9EPvyYreCu2Kyt
he4eT6FscD1rtnq2YlSr3ES1kzE949yNG9lnJazqZHBI+YkMTCXAvblFtZ3wiLYO
Dg1XOTA9+lIXjdZzOh96mE9E/P2jJmTVuH5LCzpu3Ofk8Fgkk3oDVIZaInhr1b20
JucfXGi4/Z66JWDgs9Js94Cq
-----END PRIVATE KEY-----
"""


class LoopbackServer:
    def __init__(self, handler, connection_count=1):
        self.handler = handler
        self.errors = []
        self.active = None
        self.stopping = False
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(connection_count)
        self.listener.settimeout(TIMEOUT)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback):
        if exc_type is not None:
            self.cancel()
        self.thread.join(2)
        did_not_terminate = self.thread.is_alive()
        if did_not_terminate:
            self.cancel()
            self.thread.join(2)
        if exc_type is None:
            if self.thread.is_alive():
                raise AssertionError("loopback server did not terminate")
            if did_not_terminate:
                raise AssertionError("loopback server required cancellation")
            if self.errors:
                raise AssertionError(f"loopback server failed: {self.errors}")
        return False

    def accept(self):
        conn, _ = self.listener.accept()
        conn.settimeout(TIMEOUT)
        self.active = conn
        return conn

    def track(self, conn):
        self.active = conn
        return conn

    def release(self, conn):
        if self.active is conn:
            self.active = None

    def cancel(self):
        self.stopping = True
        for sock in (self.active, self.listener):
            if sock is None:
                continue
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    def _run(self):
        try:
            self.handler(self)
        except Exception as exc:
            if not self.stopping:
                self.errors.append(repr(exc))
        finally:
            self.active = None
            self.listener.close()


class ScriptedServer(LoopbackServer):
    def __init__(self, payloads):
        self.payloads = payloads
        self.connections = []
        super().__init__(self._serve, len(payloads))

    def _serve(self, server):
        for payload in self.payloads:
            conn = server.accept()
            received = bytearray()
            with conn:
                if payload:
                    conn.sendall(payload)
                while True:
                    data = recv_or_eof(conn)
                    if not data:
                        break
                    received.extend(data)
            server.release(conn)
            self.connections.append(bytes(received))


class ReleaseServer(LoopbackServer):
    def __init__(self, released):
        self.released = released
        self.connections = []
        super().__init__(self._serve)

    def _serve(self, server):
        conn = server.accept()
        received = bytearray()
        with conn:
            while True:
                data = recv_or_eof(conn)
                if not data:
                    break
                received.extend(data)
                if b"RELEASE" in received:
                    self.released.set()
        server.release(conn)
        self.connections.append(bytes(received))


class GatedAcceptServer(LoopbackServer):
    def __init__(self, released, payloads):
        self.released = released
        self.payloads = payloads
        self.connections = []
        super().__init__(self._serve, len(payloads))
        self.listener.listen(0)
        self.blocker = socket.create_connection(
            ("127.0.0.1", self.port), timeout=TIMEOUT
        )

    def cancel(self):
        self.released.set()
        try:
            self.blocker.close()
        except OSError:
            pass
        super().cancel()

    def _serve(self, server):
        if not self.released.wait(TIMEOUT):
            raise AssertionError("pending-connect release was not signalled")
        blocker_peer = server.accept()
        blocker_peer.close()
        server.release(blocker_peer)
        self.blocker.close()
        # The blocker forced EINPROGRESS; now permit reincarnations to queue.
        server.listener.listen(len(self.payloads))

        for payload in self.payloads:
            conn = server.accept()
            received = bytearray()
            with conn:
                if payload:
                    conn.sendall(payload)
                while True:
                    data = recv_or_eof(conn)
                    if not data:
                        break
                    received.extend(data)
            server.release(conn)
            self.connections.append(bytes(received))


class RequestGatedServer(LoopbackServer):
    def __init__(self, request, payload, connection_count=2):
        self.request = request
        self.payload = payload
        self.connection_count = connection_count
        self.connections = []
        super().__init__(self._serve, connection_count)

    def _drain(self, server, conn, received):
        with conn:
            while True:
                data = recv_or_eof(conn)
                if not data:
                    break
                received.extend(data)
        server.release(conn)
        self.connections.append(bytes(received))

    def _serve(self, server):
        conn = server.accept()
        received = bytearray()
        while self.request not in received:
            data = conn.recv(4096)
            if not data:
                raise AssertionError(
                    f"connection closed before request {self.request!r}"
                )
            received.extend(data)
        conn.sendall(self.payload)
        self._drain(server, conn, received)

        for _ in range(1, self.connection_count):
            conn = server.accept()
            self._drain(server, conn, bytearray())

class EofOnRequestServer(LoopbackServer):
    def __init__(self, request):
        self.request = request
        self.connections = []
        super().__init__(self._serve)

    def _serve(self, server):
        conn = server.accept()
        received = bytearray()
        with conn:
            while self.request not in received:
                data = conn.recv(4096)
                if not data:
                    raise AssertionError(
                        f"connection closed before request {self.request!r}"
                    )
                received.extend(data)
        server.release(conn)
        self.connections.append(bytes(received))


def pad_config_read_boundaries(data):
    if not data.endswith(b"\n"):
        data += b"\n"
    padded = bytearray()
    for line in data.splitlines(keepends=True):
        if len(line) > 1024:
            raise AssertionError("fixture command exceeds tfio input buffer")
        remaining = 1024 - len(padded) % 1024
        if remaining < 1024 and len(line) > remaining:
            filler = (b"\n" if remaining == 1 else
                      b";" + b" " * (remaining - 2) + b"\n")
            padded.extend(filler)
        padded.extend(line)
    return bytes(padded)


def run_tf(binary, script, files=None, keep_stdin_open=False, stdin_data=None,
           visual_terminal=False, interactive_terminal=False):
    with tempfile.TemporaryDirectory(prefix="tf-socket-lifetime-") as temp:
        root = Path(temp)
        libdir = root / "lib"
        libdir.mkdir()
        (libdir / "stdlib.tf").write_text("", encoding="utf-8")
        for name, content in (files or {}).items():
            (root / name).write_text(content, encoding="utf-8")
        config = root / "test.tf"
        config_data = script.replace("{ROOT}", str(root)).encode("utf-8")
        config.write_bytes(pad_config_read_boundaries(config_data))
        suppressions = root / "lsan.supp"
        suppressions.write_text(
            "leak:ch_visual\nleak:hwrite\nleak:init_ssl\nleak:redraw_window\n",
            encoding="ascii",
        )
        env = os.environ.copy()
        env["LC_ALL"] = "C.UTF-8"
        env["TERM"] = "xterm"
        lsan_options = env.get("LSAN_OPTIONS", "")
        env["LSAN_OPTIONS"] = (
            lsan_options + (":" if lsan_options else "") +
            f"suppressions={suppressions}"
        )
        try:
            command = [
                str(binary), f"-L{libdir}", f"-f{config}", "-n", "-v"
            ]
            if visual_terminal or interactive_terminal:
                master, slave = pty.openpty()
                chunks = []

                def read_terminal():
                    while True:
                        try:
                            chunks.append(os.read(master, 4096))
                        except OSError:
                            break

                child = subprocess.Popen(
                    command,
                    stdin=slave if interactive_terminal else subprocess.DEVNULL,
                    stdout=slave,
                    stderr=slave,
                    env=env,
                )
                os.close(slave)
                reader = threading.Thread(target=read_terminal, daemon=True)
                reader.start()
                try:
                    child.wait(timeout=TIMEOUT)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
                    reader.join(TIMEOUT)
                    raise AssertionError(
                        "tf timed out\noutput:\n" +
                        b"".join(chunks).decode("utf-8", "replace")
                    )
                reader.join(TIMEOUT)
                if reader.is_alive():
                    os.close(master)
                    reader.join(TIMEOUT)
                else:
                    os.close(master)
                proc = subprocess.CompletedProcess(
                    command,
                    child.returncode,
                    b"".join(chunks).decode("utf-8", "replace"),
                    "",
                )
            elif keep_stdin_open:
                with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as out:
                    with tempfile.TemporaryFile(
                            mode="w+", encoding="utf-8") as err:
                        child = subprocess.Popen(
                            command,
                            stdin=subprocess.PIPE,
                            stdout=out,
                            stderr=err,
                            text=True,
                            encoding="utf-8",
                            errors="replace",
                            env=env,
                        )
                        if stdin_data:
                            child.stdin.write(stdin_data)
                            child.stdin.flush()
                        try:
                            child.wait(timeout=TIMEOUT)
                        except subprocess.TimeoutExpired:
                            child.kill()
                            child.wait()
                            out.seek(0)
                            err.seek(0)
                            raise AssertionError(
                                "tf timed out\nstdout:\n"
                                f"{out.read()}\nstderr:\n{err.read()}"
                            )
                        child.stdin.close()
                        out.seek(0)
                        err.seek(0)
                        proc = subprocess.CompletedProcess(
                            command, child.returncode, out.read(), err.read()
                        )
            else:
                proc = subprocess.run(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=TIMEOUT,
                    encoding="utf-8",
                    errors="replace",
                    env=env,
                )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or b""
            stderr = exc.stderr or b""
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", "replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", "replace")
            raise AssertionError(
                f"tf timed out\nstdout:\n{stdout}\nstderr:\n{stderr}"
            ) from exc

    diagnostics = proc.stdout + "\n" + proc.stderr
    if "ERROR: AddressSanitizer:" in diagnostics:
        raise AssertionError(diagnostics)
    if "runtime error:" in diagnostics:
        raise AssertionError(diagnostics)
    if "ERROR: LeakSanitizer:" in diagnostics:
        raise AssertionError(diagnostics)
    if proc.returncode < 0:
        raise AssertionError(
            f"tf terminated by signal {-proc.returncode}\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    if proc.returncode:
        raise AssertionError(
            f"tf exited {proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc


def assert_contains(output, text):
    if text not in output:
        raise AssertionError(f"missing {text!r} in output:\n{output}")


def normalized_output(output):
    return " ".join(ANSI_ESCAPE.sub("", output).split())


def assert_contains_normalized(output, text):
    if normalized_output(text) not in normalized_output(output):
        raise AssertionError(f"missing {text!r} in output:\n{output}")


def assert_not_contains(output, text):
    if normalized_output(text) in normalized_output(output):
        raise AssertionError(f"unexpected {text!r} in output:\n{output}")


def output_lines(output):
    return ANSI_ESCAPE.sub("", output).splitlines()


def assert_line(output, text, count=1):
    actual = output_lines(output).count(text)
    if actual != count:
        raise AssertionError(
            f"expected {count} line(s) {text!r}, found {actual}:\n{output}"
        )


def probe_features(binary):
    proc = run_tf(binary, '''/test echo(strcat("FEATURE_SSL=", features("ssl")))
/test echo(strcat("FEATURE_MCCP=", features("MCCPv2")))
/def -hOPTION102 __feature_option102 =
/quit -y
''')
    lines = output_lines(proc.stdout)
    result = {}
    for name in ("SSL", "MCCP"):
        disabled = f"FEATURE_{name}=0"
        enabled = f"FEATURE_{name}=1"
        if lines.count(disabled) + lines.count(enabled) != 1:
            raise AssertionError(
                f"could not determine {name} support:\n{proc.stdout}"
            )
        result[name.lower()] = enabled in lines
    result["ssl"] = result["ssl"] and ssl is not None
    result["option102"] = "invalid hook" not in proc.stdout
    return result


def write_tls_fixture(root):
    cert = root / "cert.pem"
    key = root / "key.pem"
    cert.write_text(TEST_CERT, encoding="ascii")
    key.write_text(TEST_KEY, encoding="ascii")
    key.chmod(0o600)
    return cert, key


def tf_byte_string(data):
    return "strcat(" + ", ".join(f"char({byte})" for byte in data) + ")"


def synthetic_reincarnation(binary):
    with ScriptedServer([b"", b""]) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/set default_charset=ISO-8859-1
/set telopt=on
/set secho=off
/test addworld("life", "", "127.0.0.1", "{server.port}", "", "", "", "e")
/connect -b life
/def -i reconnect_life = /connect -b life%; /test echo(strcat("SYNTHETIC_RESULT=", probe_result))%; /test echo(strcat("REPLACEMENT_OPEN=", is_open("life")))%; /quit -y
/def -1 -hBGTEXT reincarnate = /repeat -0 1 /reconnect_life%; /dc life
/test probe_result := send("ÿñ", "life", "f")
''')
    assert_contains(proc.stdout, "SYNTHETIC_RESULT=0")
    assert_contains(proc.stdout, "REPLACEMENT_OPEN=1")
    if server.connections != [b"", b""]:
        raise AssertionError(
            f"old synthetic send reached a transport: {server.connections!r}"
        )


def queued_reincarnation(binary):
    with ScriptedServer([b"", b"NEW_C\n"]) as server:
        queued = tf_byte_string(b"OLD_A\nOLD_B\n")
        proc = run_tf(binary, f'''/set connect=blocking
/test addworld("queue", "", "127.0.0.1", "{server.port}")
/def -i reconnect_queue = /connect -b queue
/def -1 -F -p100 -wqueue -mglob -t"OLD_A" reconnect = /test echo("SAW_OLD_A")%; /repeat -0 1 /reconnect_queue%; /dc queue
/def -F -p0 -wqueue -mglob -t"OLD_A" stale_same = /test echo("STALE_OLD_A_CALLBACK")
/def -1 -wqueue -mglob -t"NEW_C" replacement = /test echo("SAW_NEW_C")%; /quit -y
/connect -b queue
/test fake_recv({queued}, "queue", "r")
''')
    assert_contains(proc.stdout, "SAW_OLD_A")
    assert_contains(proc.stdout, "SAW_NEW_C")
    if "STALE_OLD_A_CALLBACK" in proc.stdout:
        raise AssertionError("retired trigger continued its matched callback list")
    if "SAW_OLD_B" in proc.stdout or "\nOLD_B\n" in proc.stdout:
        raise AssertionError("stale queued line reached the replacement socket")
    if server.connections != [b"", b""]:
        raise AssertionError(f"unexpected client data: {server.connections!r}")


def retired_queue_draining(binary):
    with ScriptedServer([b""]) as server:
        queued = tf_byte_string(b"RETIRED_A\nRETIRED_B\n")
        proc = run_tf(binary, f'''/set connect=blocking
/test addworld("retired", "", "127.0.0.1", "{server.port}")
/def -1 -wretired -mglob -t"RETIRED_A" retire = /test echo("SAW_RETIRED_A")%; /dc retired
/def -1 -wretired -mglob -t"RETIRED_B" drain = /test echo("SAW_RETIRED_B")%; /quit -y
/connect -b retired
/test fake_recv({queued}, "retired", "r")
''')
    assert_contains(proc.stdout, "SAW_RETIRED_A")
    assert_contains(proc.stdout, "SAW_RETIRED_B")
    if server.connections != [b""]:
        raise AssertionError(f"unexpected client data: {server.connections!r}")


def mccp_reincarnation(binary):
    compressed = zlib.compress(
        b"MCCP_OLD_A\n\xff\xfa\x18\x01\xff\xf0MCCP_OLD_B\n"
    )
    negotiation = (
        b"\xff\xfb\x56"
        b"\xff\xfa\x56\xff\xf0"
        + compressed
    )
    payload = tf_byte_string(negotiation)
    with ScriptedServer([b"", b"MCCP_NEW\n"]) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/set telopt=on
/test addworld("mccp", "", "127.0.0.1", "{server.port}")
/def -i reconnect_mccp = /connect -b mccp
/def -1 -wmccp -mglob -t"MCCP_OLD_A" reconnect = /test echo("SAW_MCCP_OLD_A")%; /repeat -0 1 /reconnect_mccp%; /dc mccp
/def -wmccp -mglob -t"MCCP_OLD_B" stale = /test echo("SAW_MCCP_OLD_B")
/def -1 -wmccp -mglob -t"MCCP_NEW" replacement = /test echo("SAW_MCCP_NEW")%; /quit -y
/connect -b mccp
/test fake_recv({payload}, "mccp", "r")
''')
    assert_line(proc.stdout, "SAW_MCCP_OLD_A")
    assert_line(proc.stdout, "SAW_MCCP_NEW")
    if "SAW_MCCP_OLD_B" in proc.stdout or "\nMCCP_OLD_B\n" in proc.stdout:
        raise AssertionError("stale compressed line reached replacement socket")
    if len(server.connections) != 2 or b"\xff\xfd\x56" not in \
            server.connections[0] or server.connections[1]:
        raise AssertionError(
            f"unexpected MCCP transport data: {server.connections!r}"
        )


def mccp_reincarnation_network(binary):
    compressed = zlib.compress(
        b"MCCP_OLD_A\n\xff\xfa\x18\x01\xff\xf0MCCP_OLD_B\n"
    )
    negotiation = (
        b"\xff\xfb\x56"
        b"\xff\xfa\x56\xff\xf0"
        + compressed
    )
    with ScriptedServer([negotiation, b"MCCP_NEW\n"]) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/set telopt=on
/test addworld("mccp", "", "127.0.0.1", "{server.port}")
/def -i reconnect_mccp = /connect -b mccp
/def -1 -wmccp -mglob -t"MCCP_OLD_A" reconnect = /test echo("SAW_MCCP_OLD_A")%; /repeat -0 1 /reconnect_mccp%; /dc mccp
/def -wmccp -mglob -t"MCCP_OLD_B" stale = /test echo("SAW_MCCP_OLD_B")
/def -1 -wmccp -mglob -t"MCCP_NEW" replacement = /test echo("SAW_MCCP_NEW")%; /quit -y
/connect -b mccp
''')
    assert_line(proc.stdout, "SAW_MCCP_OLD_A")
    assert_line(proc.stdout, "SAW_MCCP_NEW")
    if "SAW_MCCP_OLD_B" in proc.stdout or "\nMCCP_OLD_B\n" in proc.stdout:
        raise AssertionError("stale compressed line reached replacement socket")
    if len(server.connections) != 2 or b"\xff\xfd\x56" not in \
            server.connections[0] or server.connections[1]:
        raise AssertionError(
            f"unexpected MCCP transport data: {server.connections!r}"
        )


def charset_replacement(binary):
    negotiation = (
        b"\xff\xfb\x2a"
        b"\xff\xfa\x2a\x01;ISO-8859-1\xff\xf0"
        b"\xe9\n"
    )
    payload = tf_byte_string(negotiation)
    with ScriptedServer([b""]) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/test addworld("charset", "", "127.0.0.1", "{server.port}")
/def -1 -wcharset -mglob -t"é" charset_ok = /test echo("CHARSET_OK")%; /quit -y
/connect -b charset
/test fake_recv({payload}, "charset", "r")
''')
    assert_contains(proc.stdout, "CHARSET_OK")
    expected = (
        b"\xff\xfb\x1f"
        b"\xff\xfd\x2a"
        b"\xff\xfa\x2a\x02ISO-8859-1\xff\xf0"
    )
    if server.connections not in expected_telnet_transports(expected):
        raise AssertionError(
            f"unexpected CHARSET transport data: {server.connections!r}"
        )


def mccp_charset_replacement(binary):
    charset = b"\xff\xfb\x2a\xff\xfa\x2a\x01;ISO-8859-1\xff\xf0"
    raw = (
        b"\xff\xfb\x56"
        b"\xff\xfa\x56\xff\xf0"
        + zlib.compress(charset)
        + b"\xe9\n"
    )
    payload = tf_byte_string(raw)
    with ScriptedServer([b""]) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/test addworld("mccp_charset", "", "127.0.0.1", "{server.port}")
/def -1 -wmccp_charset -mglob -t"é" converted = /test echo("MCCP_CHARSET_OK")%; /quit -y
/connect -b mccp_charset
/test fake_recv({payload}, "mccp_charset", "r")
''')
    assert_line(proc.stdout, "MCCP_CHARSET_OK")
    expected = (
        b"\xff\xfb\x1f"
        b"\xff\xfd\x56"
        b"\xff\xfd\x2a"
        b"\xff\xfa\x2a\x02ISO-8859-1\xff\xf0"
    )
    if server.connections not in expected_telnet_transports(expected):
        raise AssertionError(
            f"unexpected MCCP/CHARSET transport data: {server.connections!r}"
        )


def nested_sends(binary):
    expected = b"".join(
        f"N{depth}".encode() + b"x" * (depth * 64)
        for depth in range(3, 0, -1)
    ) + b"OUTER"
    with ScriptedServer([b""]) as server, \
            ScriptedServer([b""]) as foreground:
        proc = run_tf(binary, f'''/set connect=blocking
/set secho=on
/test nested_depth := 0
/test addworld("send", "", "127.0.0.1", "{server.port}")
/test addworld("foreground", "", "127.0.0.1", "{foreground.port}")
/connect -b send
/connect -b foreground
/fg foreground
/def -hBGTEXT nested_send = /if (nested_depth < 3) /test ++nested_depth%; /test send(strcat("N", nested_depth, strrep("x", nested_depth * 64)), "send", "f")%; /endif
/test outer_result := send("OUTER", "send", "f")
/test echo(strcat("OUTER_RESULT=", outer_result))
/quit -y
''')
    assert_contains(proc.stdout, "OUTER_RESULT=1")
    if server.connections != [expected] or foreground.connections != [b""]:
        raise AssertionError(
            f"nested sends corrupted bytes:\nexpected={expected!r}\n"
            f"actual={server.connections!r}; foreground={foreground.connections!r}"
        )


def sockecho_retirement(binary):
    proc = run_tf(binary, '''/set connect=blocking
/set secho=off
/test addworld("echo_only", "", "", "", "", "", "", "e")
/connect -b echo_only
/def -1 -wecho_only -mglob -t"ECHO_ONLY" echoed = /test echo("SAW_ECHO_ONLY")%; /quit -y
/test echo_result := send(strcat("ECHO_ONLY", char(10)), "echo_only", "f")
/test echo(strcat("ECHO_ONLY_RESULT=", echo_result))
/test echo(strcat("ECHO_ONLY_OPEN=", is_open("echo_only")))
''')
    assert_line(proc.stdout, "ECHO_ONLY_RESULT=1")
    assert_line(proc.stdout, "ECHO_ONLY_OPEN=1")
    assert_line(proc.stdout, "SAW_ECHO_ONLY")

    with ScriptedServer([b"", b""]) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/test addworld("sockecho", "", "127.0.0.1", "{server.port}", "", "", "", "e")
/def -i reconnect_sockecho = /test retired_result := send(strcat("RETIRED_ECHO", char(10)), "sockecho", "f")%; /test echo(strcat("RETIRED_RESULT=", retired_result))%; /connect -b sockecho%; /test replacement_result := send(strcat("REPLACEMENT_ECHO", char(10)), "sockecho", "f")%; /test echo(strcat("REPLACEMENT_RESULT=", replacement_result))
/def -1 -wsockecho -mglob -t"CONNECTED_ECHO" retire = /test echo("SAW_CONNECTED_ECHO")%; /repeat -0 1 /reconnect_sockecho%; /dc sockecho
/def -wsockecho -mglob -t"RETIRED_ECHO" stale = /test echo("SAW_RETIRED_ECHO")
/def -1 -wsockecho -mglob -t"REPLACEMENT_ECHO" replacement = /test echo("SAW_REPLACEMENT_ECHO")%; /quit -y
/connect -b sockecho
/test connected_result := send(strcat("CONNECTED_ECHO", char(10)), "sockecho", "f")
/test echo(strcat("CONNECTED_RESULT=", connected_result))
''')
    assert_line(proc.stdout, "CONNECTED_RESULT=1")
    assert_line(proc.stdout, "SAW_CONNECTED_ECHO")
    assert_line(proc.stdout, "RETIRED_RESULT=0")
    assert_contains(proc.stdout, "send: Not connected.")
    assert_line(proc.stdout, "REPLACEMENT_RESULT=1")
    assert_line(proc.stdout, "SAW_REPLACEMENT_ECHO")
    if "SAW_RETIRED_ECHO" in proc.stdout:
        raise AssertionError("retired SOCKECHO input reached the replacement")
    expected = [b"CONNECTED_ECHO\n", b"REPLACEMENT_ECHO\n"]
    if server.connections != expected:
        raise AssertionError(
            f"retired SOCKECHO transport mismatch:\n"
            f"expected={expected!r}\nactual={server.connections!r}"
        )


def invalid_utf8_send(binary):
    invalid = b"\xff" * 64
    payload = tf_byte_string(invalid)
    with ScriptedServer([b""]) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/set default_charset=UTF-8
/set secho=off
/test addworld("invalid_utf8", "", "127.0.0.1", "{server.port}")
/connect -b invalid_utf8
/test send_result := send({payload}, "invalid_utf8", "f")
/test echo(strcat("INVALID_UTF8_RESULT=", send_result))
/quit -y
''')
    assert_line(proc.stdout, "INVALID_UTF8_RESULT=1")
    expected = b"&#xFF;" * len(invalid)
    if server.connections != [expected]:
        raise AssertionError(
            f"invalid UTF-8 expansion mismatch:\n"
            f"expected={expected!r}\nactual={server.connections!r}"
        )


def tls_failure_reconnect(binary):
    state = {}
    with tempfile.TemporaryDirectory(prefix="tf-socket-lifetime-tls-") as temp:
        cert, key = write_tls_fixture(Path(temp))

        def serve(server):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)

            first = server.accept()
            try:
                failed_tls = context.wrap_socket(first, server_side=True)
            except ssl.SSLError:
                state["verification_failed"] = True
                server.release(first)
            else:
                server.track(failed_tls).close()
                raise AssertionError("untrusted TLS handshake unexpectedly passed")

            second = server.accept()
            tls = server.track(context.wrap_socket(second, server_side=True))
            with tls:
                state["replacement_data"] = tls.recv(4096)
                tls.sendall(b"TLS_RECONNECTED\n")
            server.release(tls)

        with LoopbackServer(serve, 2) as server:
            proc = run_tf(binary, f'''/set connect=blocking

/set ssl_continue=off
/set ssl_verbose=off
/test verify_count := 0
/test addworld("tls_life", "", "127.0.0.1", "{server.port}", "", "", "", "x")
/load {{ROOT}}/tls-hooks.tf
/test outer_connect_result := eval("/connect -b tls_life")
''', {"tls-hooks.tf": '''/def -i tls_nested_reconnect = /set ssl_continue=on%; /test nested_connect_result := eval("/connect -b tls_life")%; /test nested_open := is_connected("tls_life")%; /test replacement_send := send("TLS_REPLACEMENT", "tls_life", "f")%; /test echo(strcat("TLS_VERIFY_COUNT=", verify_count))%; /test echo(strcat("TLS_NESTED_CONNECT=", nested_connect_result))%; /test echo(strcat("TLS_OUTER_CONNECT=", outer_connect_result))%; /test echo(strcat("TLS_NESTED_OPEN=", nested_open))%; /test echo(strcat("TLS_REPLACEMENT_SEND=", replacement_send))%; /test echo(strcat("TLS_OUTER_OPEN=", is_connected("tls_life")))
/def -hPENDING reconnect = /if (!verify_count & %{1} == 18) /test verify_count := 1%; /test echo("TLS_VERIFY_DEFERRED")%; /repeat -0 1 /tls_nested_reconnect%; /dc tls_life%; /endif
/def -wtls_life -hCONFAIL stale_failure = /test echo("OLD_CONFAIL_ESCAPED")
/def -1 -wtls_life -mglob -t"TLS_RECONNECTED" ready = /test echo("SAW_TLS_RECONNECTED")%; /quit -y
'''})
    assert_line(proc.stdout, "TLS_VERIFY_DEFERRED")
    assert_line(proc.stdout, "TLS_VERIFY_COUNT=1")
    assert_line(proc.stdout, "TLS_NESTED_CONNECT=1")
    assert_line(proc.stdout, "TLS_OUTER_CONNECT=0")
    assert_line(proc.stdout, "TLS_NESTED_OPEN=1")
    assert_line(proc.stdout, "TLS_REPLACEMENT_SEND=1")
    assert_line(proc.stdout, "TLS_OUTER_OPEN=1")
    assert_line(proc.stdout, "SAW_TLS_RECONNECTED")
    if "OLD_CONFAIL_ESCAPED" in proc.stdout:
        raise AssertionError("old TLS failure escaped after reincarnation")
    if not state.get("verification_failed"):
        raise AssertionError(f"certificate verification did not fail: {state!r}")
    if state.get("replacement_data") != b"TLS_REPLACEMENT":
        raise AssertionError(f"replacement TLS data mismatch: {state!r}")


def tls_failure_callback_send(binary):
    marker = b"TLS_CALLBACK_PLAINTEXT"
    state = {}

    def serve(server):
        conn = server.accept()
        received = bytearray()
        with conn:
            received.extend(conn.recv(4096))
            conn.sendall(b"not TLS\n")
            while True:
                try:
                    data = conn.recv(4096)
                except ConnectionResetError:
                    break
                if not data:
                    break
                received.extend(data)
        server.release(conn)
        state["transport"] = bytes(received)

    with LoopbackServer(serve) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/set ssl_verbose=off
/test callback_count := 0
/test addworld("tls_callback", "", "127.0.0.1", "{server.port}", "", "", "", "x")
/def -1 -wtls_callback -hCONFAIL failed_send = /test ++callback_count%; /test callback_send := send("{marker.decode()}", "tls_callback", "f")%; /test echo(strcat("TLS_CALLBACK_COUNT=", callback_count))%; /test echo(strcat("TLS_CALLBACK_SEND=", callback_send))%; /quit -y
/connect -b tls_callback
''')
    assert_line(proc.stdout, "TLS_CALLBACK_COUNT=1")
    assert_line(proc.stdout, "TLS_CALLBACK_SEND=0")
    transport = state.get("transport", b"")
    if not transport:
        raise AssertionError("TLS failure server received no ClientHello")
    if marker in transport:
        raise AssertionError("callback data was sent as plaintext after TLS failure")

def sockecho_charset(binary):
    proc = run_tf(binary, '''/set connect=blocking
/set default_charset=ISO-8859-1
/set secho=off
/test addworld("echo_charset", "", "", "", "", "", "", "e")
/connect -b echo_charset
/def -1 -wecho_charset -mglob -t"é" echoed = /test echo("SOCKECHO_CHARSET_OK")%; /quit -y
/test send(strcat("é", char(10)), "echo_charset", "f")
''')
    assert_line(proc.stdout, "SOCKECHO_CHARSET_OK")



def initialization_mfile_select(binary):
    with ScriptedServer([b""]) as world_a, \
            ScriptedServer([b""]) as world_b:
        proc = run_tf(binary, f'''/set connect=blocking
/test addworld("A", "", "127.0.0.1", "{world_a.port}", "", "", "{{ROOT}}/a.tf")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/def -wA -hCONNECT connected_a = /test echo("CONNECT_A")
/connect -b B
/connect -b A
/test echo(strcat("A_OPEN=", is_connected("A")))
/test echo(strcat("FG=", fg_world()))
/quit -y
''', {"a.tf": '''/fg B
/test send("MFILE_DEFAULT", "", "f")
'''})
    assert_line(proc.stdout, "CONNECT_A")
    assert_line(proc.stdout, "A_OPEN=1")
    assert_line(proc.stdout, "FG=B")
    if world_a.connections != [b""] or \
            world_b.connections != [b"MFILE_DEFAULT"]:
        raise AssertionError(
            f"initialization selection changed the mfile destination: "
            f"A={world_a.connections!r}, B={world_b.connections!r}"
        )


def initialization_mfile_connect(binary):
    with ScriptedServer([b""]) as world_a, \
            ScriptedServer([b""]) as world_b:
        proc = run_tf(binary, f'''/set connect=blocking
/test addworld("A", "", "127.0.0.1", "{world_a.port}", "", "", "{{ROOT}}/a.tf")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/def -wA -hCONNECT connected_a = /test echo("CONNECT_A")
/def -wB -hCONNECT connected_b = /test echo("CONNECT_B")
/connect -b A
/test echo(strcat("A_OPEN=", is_connected("A")))
/test echo(strcat("B_OPEN=", is_connected("B")))
/quit -y
''', {"a.tf": "/connect -b B\n"})
    for marker in ("CONNECT_A", "CONNECT_B", "A_OPEN=1", "B_OPEN=1"):
        assert_line(proc.stdout, marker)
    if world_a.connections != [b""] or world_b.connections != [b""]:
        raise AssertionError("nested initialization sent unexpected data")


def foreground_dead_manual_reconnect(binary):
    with ScriptedServer([b"", b"MANUAL_RECONNECT"]) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/test addworld("A", "", "127.0.0.1", "{server.port}")
/connect A
/def -1 -F -q -wA -hCONNECT finish = /test send("MANUAL_RECONNECT", "A", "f")%; /test echo(strcat("MANUAL_RECONNECT_OPEN=", is_connected("A")))%; /quit -y
/repeat -1 1 /quit -y
/dc A
/input /connect A
/dokey newline
''')
    assert_line(proc.stdout, "MANUAL_RECONNECT_OPEN=1")
    if server.connections != [b"", b"MANUAL_RECONNECT"]:
        raise AssertionError(
            f"manual reconnect from a retired foreground failed: "
            f"{server.connections!r}\n{proc.stdout}"
        )


def foreground_hook_reincarnation(binary):
    with ScriptedServer([b"", b""]) as world_a, \
            ScriptedServer([b""]) as world_b, \
            ScriptedServer([b""]) as world_c:
        proc = run_tf(binary, f'''/set connect=blocking
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/test addworld("C", "", "127.0.0.1", "{world_c.port}")
/connect -b A
/connect -b B
/fg B
/def -i reconnect_fg = /test nested_fg_connect := eval("/connect -b A")%; /fg B%; /test open_result := eval("/connect C")
/def -i reconnect_open = /test nested_open_connect := eval("/connect -b C")%; /test echo(strcat("FG_HOOK_RESULT=", fg_result))%; /test echo(strcat("FG_NESTED_CONNECT=", nested_fg_connect))%; /test echo(strcat("OPEN_HOOK_RESULT=", open_result))%; /test echo(strcat("OPEN_NESTED_CONNECT=", nested_open_connect))%; /test echo(strcat("A_OPEN=", is_connected("A")))%; /test echo(strcat("C_OPEN=", is_connected("C")))%; /quit -y
/def -1 -F -q -wA -hWORLD reincarnate_fg = /repeat -0 1 /reconnect_fg%; /dc A
/def -1 -F -q -wC -hWORLD reincarnate_open = /repeat -0 1 /reconnect_open%; /dc C
/test fg_result := eval("/fg A")
''')
    for marker in (
        "FG_HOOK_RESULT=0", "FG_NESTED_CONNECT=1",
        "OPEN_HOOK_RESULT=0", "OPEN_NESTED_CONNECT=1",
        "A_OPEN=1", "C_OPEN=1",
    ):
        assert_line(proc.stdout, marker)
    if world_a.connections != [b"", b""] or \
            world_b.connections != [b""] or world_c.connections != [b""]:
        raise AssertionError(
            f"foreground callback resumed a retired incarnation: "
            f"A={world_a.connections!r}, B={world_b.connections!r}, "
            f"C={world_c.connections!r}"
        )


def connect_hook_reincarnation(binary):
    with ScriptedServer([b"", b""]) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/test addworld("A", "", "127.0.0.1", "{server.port}", "user", "secret")
/def -i reconnect_a = /test nested_connect_result := eval("/connect -b A")%; /test echo(strcat("NESTED_CONNECT_RESULT=", nested_connect_result))%; /test echo(strcat("OUTER_CONNECT_RESULT=", outer_connect_result))%; /test echo(strcat("LOGIN_COUNT=", login_count))%; /test echo(strcat("A_OPEN=", is_connected("A")))%; /quit -y
/def -1 -F -q -p100 -wA -hCONNECT reconnect = /repeat -0 1 /reconnect_a%; /dc A
/def -F -p0 -wA -hLOGIN login = /test ++login_count%; /test send("LOGIN", "A", "f")
/test login_count := 0
/test outer_connect_result := eval("/connect -b A")
''')
    assert_line(proc.stdout, "LOGIN_COUNT=1")
    assert_line(proc.stdout, "NESTED_CONNECT_RESULT=1")
    assert_line(proc.stdout, "OUTER_CONNECT_RESULT=0")
    assert_line(proc.stdout, "A_OPEN=1")
    if server.connections != [b"", b"LOGIN"]:
        raise AssertionError(
            f"CONNECT reincarnation sent stale login data: {server.connections!r}"
        )


def login_hook_reincarnation(binary):
    with ScriptedServer([b"", b""]) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/test addworld("A", "", "127.0.0.1", "{server.port}", "user", "secret")
/def -i reconnect_a = /test nested_connect_result := eval("/connect -b -l A")%; /test echo(strcat("NESTED_CONNECT_RESULT=", nested_connect_result))%; /test echo(strcat("OUTER_CONNECT_RESULT=", outer_connect_result))%; /test echo(strcat("STALE_LOGIN_COUNT=", stale_count))%; /test echo(strcat("A_OPEN=", is_connected("A")))%; /quit -y
/def -1 -F -q -p100 -wA -hLOGIN reconnect = /repeat -0 1 /reconnect_a%; /dc A
/def -F -p0 -wA -hLOGIN stale = /test ++stale_count%; /test send("OLD_LOGIN", "A", "f")
/test stale_count := 0
/test outer_connect_result := eval("/connect -b A")
''')
    assert_line(proc.stdout, "STALE_LOGIN_COUNT=0")
    assert_line(proc.stdout, "NESTED_CONNECT_RESULT=1")
    assert_line(proc.stdout, "OUTER_CONNECT_RESULT=0")
    assert_line(proc.stdout, "A_OPEN=1")
    if server.connections != [b"", b""]:
        raise AssertionError(
            f"retired LOGIN callback reached replacement: {server.connections!r}"
        )


def send_hook_reincarnation(binary):
    with ScriptedServer([b"", b""]) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/test addworld("A", "", "127.0.0.1", "{server.port}")
/connect -b A
/def -i reconnect_a = /connect -b A%; /test echo(strcat("SEND_RESULT=", send_result))%; /quit -y
/def -1 -q -hSEND reconnect = /repeat -0 1 /reconnect_a%; /dc A
/test send_result := send("OLD", "A", "h")
''')
    assert_line(proc.stdout, "SEND_RESULT=0")
    if server.connections != [b"", b""]:
        raise AssertionError(
            f"retired H_SEND data migrated: {server.connections!r}"
        )


def consumed_send_disconnect(binary):
    with ScriptedServer([b"", b""]) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/test consume_count := 0
/test addworld("A", "", "127.0.0.1", "{server.port}")
/connect -b A
/def -1 -hSEND consume = /test ++consume_count%; /dc A
/test send_result := send("CONSUMED", "A", "h")
/connect -b A
/test send("AFTER_DISCONNECT", "A", "f")
/test echo(strcat("CONSUMED_DISCONNECT=", consume_count, ",", send_result, ",", is_connected("A")))
/quit -y
''')
    assert_line(proc.stdout, "CONSUMED_DISCONNECT=1,0,1")
    if server.connections != [b"", b"AFTER_DISCONNECT"]:
        raise AssertionError(
            f"consumed H_SEND reached the transport: {server.connections!r}"
        )
    assert_not_contains(proc.stdout, "Not connected.")


def consumed_send_reconnect(binary):
    with ScriptedServer([b"", b""]) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/test consume_count := 0
/test addworld("A", "", "127.0.0.1", "{server.port}")
/connect -b A
/def -i reconnect_a = /connect -b A%; /test send("REPLACEMENT_ONLY", "A", "f")%; /test echo(strcat("CONSUMED_RECONNECT=", consume_count, ",", send_result, ",", is_connected("A")))%; /quit -y
/def -1 -hSEND consume = /test ++consume_count%; /repeat -0 1 /reconnect_a%; /dc A%; /test send("STALE", "A", "f")
/test send_result := send("CONSUMED_RECONNECT", "A", "h")
''')
    assert_line(proc.stdout, "CONSUMED_RECONNECT=1,0,1")
    assert_not_contains(proc.stdout, "Not connected.")
    if server.connections != [b"", b"REPLACEMENT_ONLY"]:
        raise AssertionError(
            f"consumed H_SEND resumed stale work: {server.connections!r}"
        )


def unconsumed_send_retirement(binary):
    with ScriptedServer([b"", b""]) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/test quiet_count := 0
/test addworld("A", "", "127.0.0.1", "{server.port}")
/connect -b A
/def -1 -q -hSEND retire = /test ++quiet_count%; /dc A
/test send_result := send("UNCONSUMED", "A", "h")
/connect -b A
/test send("CONTROL_REPLACEMENT", "A", "f")
/test echo(strcat("UNCONSUMED_RETIREMENT=", quiet_count, ",", send_result, ",", is_connected("A")))
/quit -y
''')
    assert_line(proc.stdout, "UNCONSUMED_RETIREMENT=1,0,1")
    assert_contains_normalized(proc.stdout, "Not connected.")
    if server.connections != [b"", b"CONTROL_REPLACEMENT"]:
        raise AssertionError(
            f"retired unconsumed H_SEND reached transport: "
            f"{server.connections!r}"
        )


def consumed_send_connected(binary):
    with ScriptedServer([b""]) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/test consume_count := 0
/test addworld("A", "", "127.0.0.1", "{server.port}")
/connect -b A
/def -1 -hSEND consume = /test ++consume_count
/test send_result := send("CONSUMED", "A", "h")
/test send("INTENDED", "A", "f")
/test echo(strcat("CONSUMED_CONNECTED=", consume_count, ",", send_result, ",", is_connected("A")))
/quit -y
''')
    assert_line(proc.stdout, "CONSUMED_CONNECTED=1,0,1")
    assert_not_contains(proc.stdout, "Not connected.")
    if server.connections != [b"INTENDED"]:
        raise AssertionError(
            f"connected consumed H_SEND reached transport: "
            f"{server.connections!r}"
        )


def ordinary_send_control(binary):
    with ScriptedServer([b""]) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/test addworld("A", "", "127.0.0.1", "{server.port}")
/connect -b A
/test send_result := send("ORDINARY", "A", "h")
/test echo(strcat("ORDINARY_SEND=", send_result, ",", is_connected("A")))
/quit -y
''')
    assert_line(proc.stdout, "ORDINARY_SEND=1,1")
    assert_not_contains(proc.stdout, "Not connected.")
    if server.connections != [b"ORDINARY\r\n"]:
        raise AssertionError(
            f"ordinary H_SEND control changed transport: "
            f"{server.connections!r}"
        )


def cross_world_consumed_send(binary):
    with ScriptedServer([b""]) as world_a:
        with ScriptedServer([b"", b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/test consume_count := 0
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/connect A
/def -i reconnect_b = /connect -b B%; /test send("B_REPLACEMENT", "B", "f")%; /test echo(strcat("CROSS_SEND=", consume_count, ",", cross_result, ",", is_connected("A"), ",", is_connected("B")))%; /quit -y
/def -1 -hSEND consume_b = /test ++consume_count%; /repeat -0 1 /reconnect_b%; /dc B%; /test send("B_STALE", "B", "f")
/def -i caller_a = /test cross_result := send("BLOCKED", "B", "h")%; /test send("A_CONTINUES", "A", "f")
/repeat -wA -S 1 /caller_a
''')
    assert_line(proc.stdout, "CROSS_SEND=1,0,1,1")
    assert_not_contains(proc.stdout, "Not connected.")
    if world_a.connections != [b"A_CONTINUES"] or \
            world_b.connections != [b"", b"B_REPLACEMENT"]:
        raise AssertionError(
            f"cross-world consumed H_SEND leaked cancellation or bytes: "
            f"A={world_a.connections!r}, B={world_b.connections!r}"
        )


def owner_retirement_during_send_hook(binary):
    with ScriptedServer([b""]) as world_a:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/test quiet_count := 0
/test owner_result := -1
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/connect A
/def -i finish = /test send("B_EXPLICIT", "B", "f")%; /test echo(strcat("OWNER_RETIREMENT=", quiet_count, ",", owner_result, ",", is_connected("A"), ",", is_connected("B")))%; /quit -y
/def -1 -q -hSEND retire_owner = /test ++quiet_count%; /repeat -0 1 /finish%; /dc A
/def -i caller_a = /test owner_result := send("STALE_OWNER", "B", "h")%; /test send("STALE_CONTINUATION", "B", "f")
/repeat -wA -S 1 /caller_a
''')
    assert_line(proc.stdout, "OWNER_RETIREMENT=1,-1,0,1")
    assert_not_contains(proc.stdout, "Not connected.")
    if world_a.connections != [b""] or world_b.connections != [b"B_EXPLICIT"]:
        raise AssertionError(
            f"cancelled H_SEND owner emitted stale bytes: "
            f"A={world_a.connections!r}, B={world_b.connections!r}"
        )


def send_hook_foreground(binary):
    with ScriptedServer([b""]) as world_a, \
            ScriptedServer([b""]) as world_b:
        proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/connect -b A
/fg A
/def -1 -q -hSEND switch_explicit = /fg B
/test explicit_result := send("EXPLICIT", "A", "h")
/fg A
/def -1 -q -hSEND switch_default = /fg B
/test default_result := send("DEFAULT", "", "h")
/fg A
/def -1 -q -hSEND switch_direct = /fg B
/test direct_result := eval("DIRECT")
/def -1 -hSEND suppress = /test echo("SUPPRESSED")
/test suppressed_result := send("NOPE", "A", "h")
/test echo(strcat("EXPLICIT_RESULT=", explicit_result))
/test echo(strcat("DEFAULT_RESULT=", default_result))
/test echo(strcat("SUPPRESSED_RESULT=", suppressed_result))
/test echo(strcat("DIRECT_RESULT=", direct_result))
/test echo(strcat("FG=", fg_world()))
/quit -y
''')
    for marker in (
        "SUPPRESSED", "EXPLICIT_RESULT=1", "DEFAULT_RESULT=1",
        "DIRECT_RESULT=1", "SUPPRESSED_RESULT=0", "FG=B",
    ):
        assert_line(proc.stdout, marker)
    if world_a.connections != [b"EXPLICIT\r\nDEFAULT\r\nDIRECT\r\n"] or \
            world_b.connections != [b""]:
        raise AssertionError(
            f"H_SEND redirected data: A={world_a.connections!r}, "
            f"B={world_b.connections!r}"
        )


def recursive_send_hook(binary):
    with ScriptedServer([b""]) as world_a, \
            ScriptedServer([b""]) as world_b:
        proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b A
/connect -b B
/def -1 -q -hSEND nested = /test nested_result := send("INNER", "B", "h")
/test outer_result := send("OUTER", "A", "h")
/test echo(strcat("NESTED_RESULT=", nested_result))
/test echo(strcat("OUTER_RESULT=", outer_result))
/quit -y
''')
    assert_line(proc.stdout, "NESTED_RESULT=1")
    assert_line(proc.stdout, "OUTER_RESULT=1")
    if world_a.connections != [b"OUTER\r\n"] or \
            world_b.connections != [b"INNER\r\n"]:
        raise AssertionError(
            f"recursive H_SEND corrupted destinations: "
            f"A={world_a.connections!r}, B={world_b.connections!r}"
        )


def prompted_process_replacement(binary):
    proc = run_tf(binary, '''/set connect=blocking
/test addworld("A", "", "", "", "", "", "", "e")
/connect -b A
/test prompt_runs := 0
/def prompt_replacer = /test ++prompt_runs%; /if (prompt_runs > 1) /test replace_result := substitute("NEW_PROMPT")%; /test echo(strcat("PROMPT_REPLACE_RESULT=", replace_result))%; /quit -y%; /endif
/repeat -P -wA 2 /prompt_replacer
/test prompt("OLD_PROMPT")
''')
    assert_line(proc.stdout, "PROMPT_REPLACE_RESULT=1")


def bamf_reincarnation(binary):
    with ScriptedServer([b"", b""]) as server:
        line = (
            "#### Please reconnect to A@127.0.0.1 "
            f"(reason) port {server.port} ####"
        )
        proc = run_tf(binary, f'''/set connect=blocking
/set bamf=on
/test addworld("@A", "", "127.0.0.1", "{server.port}")
/test connect_count := 0
/def -F -q -w@A -hCONNECT count_connect = /test ++connect_count
/connect -b @A
/def -i reconnect_a = /connect -b @A%; /test echo(strcat("A_OPEN=", is_connected("@A")))%; /test echo(strcat("CONNECT_COUNT=", connect_count))%; /quit -y
/def -1 -F -q -w@A -hBAMF reconnect = /test echo("BAMF_HOOK")%; /repeat -0 1 /reconnect_a%; /dc @A
/test fake_recv("{line}", "@A", "")
''')
    assert_line(proc.stdout, "BAMF_HOOK")
    assert_line(proc.stdout, "A_OPEN=1")
    assert_line(proc.stdout, "CONNECT_COUNT=2")
    if server.connections != [b"", b""]:
        raise AssertionError(
            f"BAMF resumed a retired operation: {server.connections!r}"
        )


def bamf_portal_handoff(binary):
    with ScriptedServer([b""]) as source, \
            ScriptedServer([b"PORTAL_DESTINATION"]) as destination:
        line = (
            "#### Please reconnect to destination@127.0.0.1 "
            f"(reason) port {destination.port} ####"
        )
        proc = run_tf(binary, f'''/set connect=blocking
/set bamf=on
/set secho=off
/test addworld("source", "", "127.0.0.1", "{source.port}")
/test addworld("@destination", "", "127.0.0.1", "{destination.port}")
/connect -b source
/def -1 -F -q -w@destination -hCONNECT finish = /test send("PORTAL_DESTINATION", "@destination", "f")%; /quit -y
/repeat -1 1 /quit -y
/repeat -wsource -S 1 /test fake_recv("{line}", "source", "")
''')
    if source.connections != [b""] or \
            destination.connections != [b"PORTAL_DESTINATION"]:
        raise AssertionError(
            f"simulated portal handoff failed: "
            f"source={source.connections!r}, "
            f"destination={destination.connections!r}\n{proc.stdout}"
        )


def more_hook_output_preserves_pending_line(binary):
    proc = run_tf(binary, '''/set visual=off
/set secho=off
/set more=off
/set more=on
/eval /repeat -S $[lines()-1] /test echo("PAGER_FILL")
/def -1 -F -q -hMORE output_only = /test echo("MORE_HOOK_OUTPUT")
/test echo("PAGER_PENDING")
/test pager_back := moresize()
/set more=off
/dokey flush
/test echo(strcat("PAGER_BACK=", pager_back))
/quit -y
''')
    assert_line(proc.stdout, "PAGER_PENDING")
    assert_line(proc.stdout, "PAGER_BACK=2")


def nested_charset_replacement(binary):
    will_charset = tf_byte_string(b"\xff\xfb\x2a")
    charset_request = tf_byte_string(
        b"\xff\xfa\x2a\x01;ISO-8859-1\xff\xf0"
    )
    outer = tf_byte_string(b"\xff\xf9\xe9\n")
    with ScriptedServer([b""]) as world_a, \
            ScriptedServer([b""]) as world_b:
        proc = run_tf(binary, f'''/set connect=blocking
/set telopt=on
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b A
/connect -b B
/fg B
/def -1 -wA -mglob -t"é" converted = /test echo("NESTED_CHARSET_OK")%; /quit -y
/test fake_recv({will_charset}, "A", "r")
/def -1 -q -hBGTEXT replace_charset = /test fake_recv({charset_request}, "A", "r")
/test fake_recv({outer}, "A", "r")
''')
    assert_line(proc.stdout, "NESTED_CHARSET_OK")
    expected = (
        b"\xff\xfb\x1f"
        b"\xff\xfd\x2a"
        b"\xff\xfa\x2a\x02ISO-8859-1\xff\xf0"
    )
    if world_a.connections not in expected_telnet_transports(expected) or \
            world_b.connections != [b""]:
        raise AssertionError("nested CHARSET replacement transport mismatch")


def nested_telnet_subnegotiation(binary):
    will = tf_byte_string(b"\xff\xfb\x66")
    outer = tf_byte_string(b"\xff\xfa\x66OUTER\xff\xf0")
    nested = tf_byte_string(b"\xff\xfa\x66INNER\xff\xf0")
    with ScriptedServer([b""]) as world_a, \
            ScriptedServer([b""]) as world_b:
        proc = run_tf(binary, f'''/set connect=blocking
/set telopt=on
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b A
/connect -b B
/fg B
/def -F -hOPTION102 option_seen = /test echo(strcat("OPTION102=", %%1))
/test fake_recv({will}, "A", "r")
/def -1 -q -hBGTEXT nested_parser = /test fake_recv({nested}, "A", "r")
/test fake_recv({outer}, "A", "r")
/quit -y
''')
    assert_line(proc.stdout, "OPTION102=INNER")
    assert_line(proc.stdout, "OPTION102=OUTER")


def overlong_charset(binary):
    payload = (
        b"\xff\xfb\x2a"
        b"\xff\xfa\x2a\x01;" + b"A" * 300 + b"\xff\xf0"
        b"OVERLONG_OK\n"
    )
    with ScriptedServer([payload]) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/set telopt=on
/test addworld("A", "", "127.0.0.1", "{server.port}")
/def -1 -wA -mglob -t"OVERLONG_OK" overlong_seen = /test echo("OVERLONG_SAFE")%; /quit -y
/connect -b A
''')
    assert_line(proc.stdout, "OVERLONG_SAFE")
    expected = b"\xff\xfb\x1f\xff\xfd\x2a\xff\xfa\x2a\x03\xff\xf0"
    if server.connections not in expected_telnet_transports(expected):
        raise AssertionError(
            f"overlong CHARSET response mismatch: {server.connections!r}"
        )


def explicit_fake_recv_target(binary):
    proc = run_tf(binary, f'''/set connect=blocking
/test addworld("A", "", "", "", "", "", "", "e")
/test addworld("B", "", "", "", "", "", "", "e")
/connect -b A
/connect -b B
/fg A
/def -1 -wA -mglob -t"RAW" wrong = /test echo("RAW_AT_A")
/def -1 -wB -mglob -t"RAW" right = /test echo("RAW_AT_B")%; /quit -y
/test fake_recv({tf_byte_string(b"RAW\n")}, "B", "r")
''')
    assert_line(proc.stdout, "RAW_AT_B")
    if "RAW_AT_A" in proc.stdout:
        raise AssertionError("explicit fake_recv input was parsed on xsock")


def repeated_address_failure(binary):
    with ScriptedServer([b""]) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/test addworld("multi", "", "localhost.localdomain", "{server.port}")
/test iconfail_count := 0
/def -F -q -wmulti -hICONFAIL failed_address = /test ++iconfail_count%; /test echo("MULTI_ICONFAIL")
/def -1 -wmulti -hCONNECT connected = /test echo("MULTI_CONNECTED")
/connect -b multi
/test echo(strcat("MULTI_OPEN=", is_connected("multi")))
/test echo(strcat("MULTI_ICONFAIL_COUNT=", iconfail_count))
/quit -y
''')
    assert_line(proc.stdout, "MULTI_CONNECTED")
    assert_line(proc.stdout, "MULTI_OPEN=1")
    assert_line(proc.stdout, "MULTI_ICONFAIL")
    assert_line(proc.stdout, "MULTI_ICONFAIL_COUNT=1")
    if server.connections != [b""]:
        raise AssertionError("multi-address connection sent unexpected data")


def tls_multi_address_fallback(binary):

    ipv6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    ipv4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    errors = []
    state = {}
    with tempfile.TemporaryDirectory(prefix="tf-socket-lifetime-tls-") as temp:
        cert, key = write_tls_fixture(Path(temp))
        try:
            ipv6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ipv6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            ipv6.bind(("::1", 0))
            port = ipv6.getsockname()[1]
            ipv4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ipv4.bind(("127.0.0.1", port))
            for listener in (ipv6, ipv4):
                listener.listen(1)
                listener.settimeout(TIMEOUT)

            def fail_ipv6_tls():
                try:
                    conn, _ = ipv6.accept()
                    with conn:
                        conn.settimeout(TIMEOUT)
                        state["first_transport"] = conn.recv(4096)
                        conn.sendall(b"not tls\n")
                except Exception as exc:
                    errors.append(repr(exc))

            def accept_ipv4_tls():
                try:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(cert, key)
                    raw, _ = ipv4.accept()
                    raw.settimeout(TIMEOUT)
                    with context.wrap_socket(raw, server_side=True) as conn:
                        state["second_data"] = conn.recv(4096)
                except Exception as exc:
                    errors.append(repr(exc))

            threads = [
                threading.Thread(target=fail_ipv6_tls, daemon=True),
                threading.Thread(target=accept_ipv4_tls, daemon=True),
            ]
            for thread in threads:
                thread.start()
            proc = run_tf(binary, f'''/set connect=blocking
/set ssl_continue=on
/set ssl_verbose=off
/set secho=off
/test addworld("tlsmulti", "", "localhost.localdomain", "{port}", "", "", "", "x")
/test iconfail_count := 0
/test confail_count := 0
/test connect_count := 0
/def -F -q -wtlsmulti -hICONFAIL retry = /test ++iconfail_count
/def -F -q -wtlsmulti -hCONFAIL failed = /test ++confail_count
/def -F -q -wtlsmulti -hCONNECT connected = /test ++connect_count
/test connect_result := eval("/connect -b tlsmulti")
/test send_result := send("TLS_MULTI_MARKER", "tlsmulti", "f")
/test echo(strcat("TLS_MULTI_CONNECT_RESULT=", connect_result))
/test echo(strcat("TLS_MULTI_SEND_RESULT=", send_result))
/test echo(strcat("TLS_MULTI_ICONFAIL=", iconfail_count))
/test echo(strcat("TLS_MULTI_CONFAIL=", confail_count))
/test echo(strcat("TLS_MULTI_CONNECT=", connect_count))
/quit -y
''')
            for thread in threads:
                thread.join(2)
        finally:
            ipv6.close()
            ipv4.close()

    if any(thread.is_alive() for thread in threads):
        raise AssertionError("TLS multi-address server did not terminate")
    if errors:
        raise AssertionError(f"TLS multi-address server failed: {errors}")
    assert_line(proc.stdout, "TLS_MULTI_CONNECT_RESULT=1")
    assert_line(proc.stdout, "TLS_MULTI_SEND_RESULT=1")
    assert_line(proc.stdout, "TLS_MULTI_ICONFAIL=1")
    assert_line(proc.stdout, "TLS_MULTI_CONFAIL=0")
    assert_line(proc.stdout, "TLS_MULTI_CONNECT=1")
    first = state.get("first_transport", b"")
    if not first or b"TLS_MULTI_MARKER" in first:
        raise AssertionError(f"invalid first TLS transport: {first!r}")
    if state.get("second_data") != b"TLS_MULTI_MARKER":
        raise AssertionError(f"replacement TLS data mismatch: {state!r}")


def tls_write_failure(binary):
    state = {}
    with tempfile.TemporaryDirectory(prefix="tf-socket-lifetime-tls-") as temp:
        cert, key = write_tls_fixture(Path(temp))

        def serve(server):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            raw = server.accept()
            tls = server.track(context.wrap_socket(raw, server_side=True))
            state["handshake"] = True
            state["data"] = tls.recv(1)
            if state["data"] != b"X":
                raise AssertionError(
                    f"TLS write fixture received no payload: {state['data']!r}"
                )
            tls.setsockopt(
                socket.SOL_SOCKET, socket.SO_LINGER,
                struct.pack("ii", 1, 0),
            )
            tls.close()
            server.release(tls)

        with LoopbackServer(serve) as server:
            # Keep the bulk write larger than the constrained transport buffers.
            server.listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            proc = run_tf(binary, f'''/set connect=blocking
/set ssl_continue=on
/set ssl_verbose=off
/set secho=off
/test addworld("tlswrite", "", "127.0.0.1", "{server.port}", "", "", "", "x")
/test connect_count := 0
/test confail_count := 0
/test disconnect_count := 0
/def -F -q -wtlswrite -hCONNECT connected = /test ++connect_count
/def -F -q -wtlswrite -hCONFAIL connect_failed = /test ++confail_count
/def -F -q -wtlswrite -hDISCONNECT write_failed = /test ++disconnect_count
/test connect_result := eval("/connect -b tlswrite")
/test first := send(strrep("X", 16777216), "tlswrite", "f")
/test second := send("AFTER_FAILURE", "tlswrite", "f")
/test echo(strcat("TLS_CONNECT_RESULT=", connect_result))
/test echo(strcat("TLS_CONNECT_COUNT=", connect_count))
/test echo(strcat("TLS_CONFAIL_COUNT=", confail_count))
/test echo(strcat("TLS_DISCONNECT_COUNT=", disconnect_count))
/test echo(strcat("TLS_WRITE_FIRST=", first))
/test echo(strcat("TLS_WRITE_SECOND=", second))
/quit -y
''')
    if not state.get("handshake"):
        raise AssertionError("TLS write fixture never completed its handshake")
    if state.get("data") != b"X":
        raise AssertionError("TLS write fixture never received application data")
    assert_line(proc.stdout, "TLS_WRITE_FIRST=0")
    assert_line(proc.stdout, "TLS_CONNECT_RESULT=1")
    assert_line(proc.stdout, "TLS_CONNECT_COUNT=1")
    assert_line(proc.stdout, "TLS_CONFAIL_COUNT=0")
    assert_line(proc.stdout, "TLS_DISCONNECT_COUNT=1")
    assert_line(proc.stdout, "TLS_WRITE_SECOND=0")


def async_pending_completion(binary):
    released = threading.Event()
    with ReleaseServer(released) as control:
        with GatedAcceptServer(released, [b""]) as target:
            proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/test addworld("gate", "", "127.0.0.1", "{control.port}")
/test addworld("A", "", "127.0.0.1", "{target.port}", "user", "secret")
/connect -b gate
/set login=on
/set connect=nonblocking
/test pending_count := 0
/test connect_count := 0
/test login_count := 0
/def -F -q -wA -hPENDING count_pending = /test ++pending_count
/def -F -q -wA -hCONNECT count_connect = /test ++connect_count
/def -F -q -wA -hLOGIN finish = /test ++login_count%; /test echo(strcat("ASYNC_PENDING_RESULT=", pending_result))%; /test echo(strcat("ASYNC_PENDING_COUNT=", pending_count))%; /test echo(strcat("ASYNC_CONNECT_COUNT=", connect_count))%; /test echo(strcat("ASYNC_LOGIN_COUNT=", login_count))%; /test echo(strcat("ASYNC_A_OPEN=", is_connected("A")))%; /quit -y
/test pending_result := eval("/connect -b A")
/test release_result := send("RELEASE", "gate", "f")
''')
    for marker in (
        "ASYNC_PENDING_RESULT=2",
        "ASYNC_PENDING_COUNT=1",
        "ASYNC_CONNECT_COUNT=1",
        "ASYNC_LOGIN_COUNT=1",
        "ASYNC_A_OPEN=1",
    ):
        assert_line(proc.stdout, marker)
    if control.connections != [b"RELEASE"] or target.connections != [b""]:
        raise AssertionError(
            f"async pending completion transport mismatch: "
            f"control={control.connections!r}, target={target.connections!r}"
        )


def async_pending_reconnect(binary):
    released = threading.Event()
    with ReleaseServer(released) as control:
        with GatedAcceptServer(released, [b""]) as target:
            proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/test addworld("gate", "", "127.0.0.1", "{control.port}")
/test addworld("A", "", "127.0.0.1", "{target.port}")
/connect -b gate
/set connect=nonblocking
/test pending_count := 0
/test connect_count := 0
/def -F -q -wA -hPENDING count_pending = /test ++pending_count
/def -1 -F -q -wA -hCONNECT finish = /test ++connect_count%; /test echo(strcat("ASYNC_FIRST_RESULT=", first_result))%; /test echo(strcat("ASYNC_SECOND_RESULT=", second_result))%; /test echo(strcat("ASYNC_RECONNECT_PENDING_COUNT=", pending_count))%; /test echo(strcat("ASYNC_RECONNECT_CONNECT_COUNT=", connect_count))%; /test echo(strcat("ASYNC_RECONNECT_OPEN=", is_connected("A")))%; /quit -y
/test first_result := eval("/connect -b A")
/dc A
/test second_result := eval("/connect -b A")
/test release_result := send("RELEASE", "gate", "f")
''')
    for marker in (
        "ASYNC_FIRST_RESULT=2",
        "ASYNC_SECOND_RESULT=2",
        "ASYNC_RECONNECT_PENDING_COUNT=2",
        "ASYNC_RECONNECT_CONNECT_COUNT=1",
        "ASYNC_RECONNECT_OPEN=1",
    ):
        assert_line(proc.stdout, marker)
    if control.connections != [b"RELEASE"] or target.connections != [b""]:
        raise AssertionError(
            f"async pending reconnect transport mismatch: "
            f"control={control.connections!r}, target={target.connections!r}"
        )


def async_connect_hook_reconnect(binary):
    released = threading.Event()
    with ReleaseServer(released) as control:
        with GatedAcceptServer(released, [b"", b""]) as target:
            proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/test addworld("gate", "", "127.0.0.1", "{control.port}")
/test addworld("A", "", "127.0.0.1", "{target.port}")
/connect -b gate
/set connect=nonblocking
/test pending_count := 0
/test connect_count := 0
/test stale_count := 0
/def -F -q -p300 -wA -hPENDING count_pending = /test ++pending_count
/def -F -q -p300 -wA -hCONNECT count_connect = /test ++connect_count
/def -i reconnect_a = /test nested_result := eval("/connect -b A")%; /test echo(strcat("ASYNC_HCONNECT_OUTER_RESULT=", outer_result))%; /test echo(strcat("ASYNC_HCONNECT_NESTED_RESULT=", nested_result))%; /test echo(strcat("ASYNC_HCONNECT_PENDING_COUNT=", pending_count))%; /test echo(strcat("ASYNC_HCONNECT_CONNECT_COUNT=", connect_count))%; /test echo(strcat("ASYNC_HCONNECT_STALE_COUNT=", stale_count))%; /test echo(strcat("ASYNC_HCONNECT_OPEN=", is_connected("A")))%; /quit -y
/def -1 -F -q -p200 -wA -hCONNECT reconnect = /repeat -0 1 /reconnect_a%; /dc A
/def -F -q -p100 -wA -hCONNECT stale = /if (connect_count == 1) /test ++stale_count%; /test send("STALE_CONNECT", "A", "f")%; /endif
/test outer_result := eval("/connect -b A")
/test release_result := send("RELEASE", "gate", "f")
''')
    for marker in (
        "ASYNC_HCONNECT_OUTER_RESULT=2",
        "ASYNC_HCONNECT_NESTED_RESULT=1",
        "ASYNC_HCONNECT_PENDING_COUNT=2",
        "ASYNC_HCONNECT_CONNECT_COUNT=2",
        "ASYNC_HCONNECT_STALE_COUNT=0",
        "ASYNC_HCONNECT_OPEN=1",
    ):
        assert_line(proc.stdout, marker)
    if control.connections != [b"RELEASE"] or \
            target.connections != [b"", b""]:
        raise AssertionError(
            f"async H_CONNECT reincarnation transport mismatch: "
            f"control={control.connections!r}, target={target.connections!r}"
        )


def async_multi_address_fallback(binary):
    with ScriptedServer([b""]) as server:
        proc = run_tf(binary, f'''/set connect=nonblocking
/test addworld("multi", "", "localhost.localdomain", "{server.port}")
/test iconfail_count := 0
/test connect_count := 0
/def -F -q -wmulti -hICONFAIL failed_address = /test ++iconfail_count
/def -F -q -wmulti -hCONNECT connected = /test ++connect_count
/test connect_result := eval("/connect -b multi")
/test echo(strcat("ASYNC_FALLBACK_RESULT=", connect_result))
/test echo(strcat("ASYNC_FALLBACK_ICONFAIL_COUNT=", iconfail_count))
/test echo(strcat("ASYNC_FALLBACK_CONNECT_COUNT=", connect_count))
/test echo(strcat("ASYNC_FALLBACK_OPEN=", is_connected("multi")))
/quit -y
''')
    for marker in (
        "ASYNC_FALLBACK_RESULT=1",
        "ASYNC_FALLBACK_ICONFAIL_COUNT=1",
        "ASYNC_FALLBACK_CONNECT_COUNT=1",
        "ASYNC_FALLBACK_OPEN=1",
    ):
        assert_line(proc.stdout, marker)
    if server.connections != [b""]:
        raise AssertionError("async multi-address fallback sent unexpected data")


def async_pending_foreground_change(binary):
    released = threading.Event()
    with ReleaseServer(released) as world_b:
        with ScriptedServer([b""]) as world_c:
            with GatedAcceptServer(released, [b""]) as world_a:
                proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/test addworld("C", "", "127.0.0.1", "{world_c.port}")
/connect -b B
/connect -b C
/fg B
/set connect=nonblocking
/test pending_count := 0
/test connect_count := 0
/def -F -q -wA -hPENDING count_pending = /test ++pending_count
/def -1 -F -q -wA -hCONNECT finish = /test ++connect_count%; /test echo(strcat("ASYNC_FG_RESULT=", pending_result))%; /test echo(strcat("ASYNC_FG_PENDING_COUNT=", pending_count))%; /test echo(strcat("ASYNC_FG_CONNECT_COUNT=", connect_count))%; /test echo(strcat("ASYNC_FG_AT_CONNECT=", fg_world()))%; /test echo(strcat("ASYNC_FG_A_OPEN=", is_connected("A")))%; /quit -y
/test pending_result := eval("/connect -b A")
/fg C
/test release_result := send("RELEASE", "B", "f")
''')
    for marker in (
        "ASYNC_FG_RESULT=2",
        "ASYNC_FG_PENDING_COUNT=1",
        "ASYNC_FG_CONNECT_COUNT=1",
        "ASYNC_FG_AT_CONNECT=C",
        "ASYNC_FG_A_OPEN=1",
    ):
        assert_line(proc.stdout, marker)
    if world_b.connections != [b"RELEASE"] or \
            world_c.connections != [b""] or world_a.connections != [b""]:
        raise AssertionError(
            f"async foreground transport mismatch: A={world_a.connections!r}, "
            f"B={world_b.connections!r}, C={world_c.connections!r}"
        )


def foreground_null_hook_connect(binary):
    with ScriptedServer([b""]) as world_b:
        proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/test addworld("A", "", "", "", "", "", "", "")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/fg B
/def -1 -F -q -hWORLD connect_from_null = /test hook_connect_result := eval("/connect A")
/test null_result := eval("/fg -n")
/test default_result := send("NO_DEST", "", "f")
/test echo(strcat("FG_NULL_HOOK_CONNECT_RESULT=", hook_connect_result))
/test echo(strcat("FG_NULL_RESULT=", null_result))
/test echo(strcat("FG_NULL_A_OPEN=", is_connected("A")))
/test echo(strcat("FG_NULL_FG=", fg_world()))
/test echo(strcat("FG_NULL_DEFAULT_SEND=", default_result))
/quit -y
''')
    for marker in (
        "FG_NULL_HOOK_CONNECT_RESULT=0",
        "FG_NULL_RESULT=1",
        "FG_NULL_A_OPEN=0",
        "FG_NULL_FG=",
        "FG_NULL_DEFAULT_SEND=0",
    ):
        assert_line(proc.stdout, marker)
    assert_contains(proc.stdout, "illegal reentry")
    if world_b.connections != [b""]:
        raise AssertionError(
            f"rejected nested foreground connect changed transport: "
            f"B={world_b.connections!r}"
        )


def output_reentrancy_ordinary(binary):
    with ScriptedServer([b"", b""]) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set more=on
/set secho=off
/test addworld("output", "", "127.0.0.1", "{server.port}")
/connect -b output
/def -i reconnect_output = /connect -b output%; /test send("MORE_RECONNECTED", "output", "f")%; /quit -y
/def -1 -F -q -hMORE reincarnate = /repeat -0 1 /reconnect_output%; /dc output
/def -F -q -hLOAD stale_one = /test send("STALE_LOAD_1", "output", "f")
/def -F -q -hLOAD stale_two = /test send("STALE_LOAD_2", "output", "f")
/set more=off
/set more=on
/eval /repeat -S $[lines()-1] /test echo("FILL")
/load {{ROOT}}/empty.tf
''', {"empty.tf": ""})
    expected = [b"", b"MORE_RECONNECTED"]
    if server.connections != expected:
        raise AssertionError(
            f"ordinary hook output resumed stale callbacks: "
            f"expected={expected!r}, actual={server.connections!r}\n"
            f"{proc.stdout}"
        )

def output_reentrancy_foreground_change(binary):
    with ScriptedServer([b""]) as world_a:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set wrapsize=10
/set more=on
/set secho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b A
/connect -b B
/fg A
/def -1 -F -q -hMORE switch = /fg B
/def -F -q -hLOAD valid_one = /test send(strcat("VALID_1_FG_", fg_world()), "A", "f")
/def -F -q -hLOAD valid_two = /test send(strcat("VALID_2_FG_", fg_world()), "A", "f")
/set more=off
/set more=on
/eval /repeat -S $[lines()-1] /test echo("FILL")
/load {{ROOT}}/empty.tf
/quit -y
''', {"empty.tf": ""})
    received = world_a.connections[0]
    for marker in (b"VALID_1_FG_B", b"VALID_2_FG_B"):
        if marker not in received:
            raise AssertionError(
                f"foreground-only change suppressed or redirected callback: "
                f"A={world_a.connections!r}, B={world_b.connections!r}\n"
                f"{proc.stdout}"
            )
    if world_b.connections != [b""]:
        raise AssertionError(
            f"foreground-only change redirected callback: "
            f"A={world_a.connections!r}, B={world_b.connections!r}"
        )


def output_reentrancy_alert(binary):
    world = "A"
    with ScriptedServer([b""]) as foreground:
        with ScriptedServer([b""]) as background:
            proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set wrapsize=10
/set more=on
/set secho=off
/test nested := 0
/test addworld("foreground", "", "127.0.0.1", "{foreground.port}")
/test addworld("{world}", "", "127.0.0.1", "{background.port}")
/connect -b foreground
/fg foreground
/def -i reconnect_alert = /connect -b {world}%; /test send("MORE_RECONNECTED", "{world}", "f")%; /test nested := 0%; /quit -y
/def -1 -F -q -hMORE reincarnate = /test nested := 1%; /repeat -0 1 /reconnect_alert%; /dc {world}
/def -F -q -w{world} -hACTIVITY stale_one = /if (!nested) /test send("STALE_ALERT_1", "{world}", "f")%; /endif
/def -F -q -w{world} -hACTIVITY stale_two = /if (!nested) /test send("STALE_ALERT_2", "{world}", "f")%; /endif
/set more=off
/set more=on
/eval /repeat -S $[lines()-1] /test echo("FILL")
/connect -b {world}
''')
    expected = [b"MORE_RECONNECTED"]
    if background.connections != expected:
        raise AssertionError(
            f"alert hook output resumed stale callbacks: "
            f"expected={expected!r}, actual={background.connections!r}\n"
            f"{proc.stdout}"
        )


def output_reentrancy_world_alert(binary):
    world = "A"
    with ScriptedServer([b""]) as foreground:
        with ScriptedServer([b"", b""]) as background:
            proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set wrapsize=10
/set more=on
/set secho=off
/test nested := 0
/test addworld("foreground", "", "127.0.0.1", "{foreground.port}")
/test addworld("{world}", "", "127.0.0.1", "{background.port}")
/connect -b foreground
/fg foreground
/def -ag -q -hPENDING gag_pending =
/def -i reconnect_alert = /connect -b {world}%; /test send("MORE_RECONNECTED", "{world}", "f")%; /test nested := 0%; /quit -y
/def -1 -F -q -hMORE reincarnate = /test nested := 1%; /repeat -0 1 /reconnect_alert%; /dc {world}
/def -aA -F -q -w{world} -hCONNECT stale_one = /if (!nested) /test send("STALE_WORLD_1", "{world}", "f")%; /endif
/def -aA -F -q -w{world} -hCONNECT stale_two = /if (!nested) /test send("STALE_WORLD_2", "{world}", "f")%; /endif
/set more=off
/set more=on
/eval /repeat -S $[lines()-1] /test echo("FILL")
/connect -b {world}
''')
    expected = [b"", b"MORE_RECONNECTED"]
    if background.connections != expected:
        raise AssertionError(
            f"world hook alert resumed stale callbacks: "
            f"expected={expected!r}, actual={background.connections!r}\n"
            f"{proc.stdout}"
        )


def suspended_owner_isolation(binary):
    with ScriptedServer([b""]) as world_a:
        with RequestGatedServer(b"READY\r\n", b"GO\n") as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set wrapsize=10
/set secho=off
/set kecho=off
/set mecho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/connect A
/def -i reconnect_b = /connect -b B%; /test send("RECONNECTED", "B", "f")%; /set more=off%; /dokey flush%; /input reply%; /dokey newline
/def -i -1 -F -q -hMORE retire_b = /repeat -0 1 /reconnect_b%; /dc B
/def -i -1 -F -q -p100 -wB -mglob -t"GO" stale_first = /dokey pause%; /test send("STALE_FIRST", "B", "f")
/def -1 -F -q -p0 -wB -mglob -t"GO" stale_second = /test send("STALE_SECOND", "B", "f")
/set suspended_a_after=0
/set suspended_a_length=-1
/set suspended_a_value=missing
/def -i waiter = /test send("READY", "B")%; /test suspended_a_length := tfread(suspended_a_value)%; /test suspended_a_after := 1
/def -i start_waiter = /input /waiter%; /dokey newline
/def -i report = /set more=off%; /dokey flush%; /set wrapsize=80%; /test echo(strcat("ISOLATION=", suspended_a_after, ",", is_connected("A")))%; /quit -y
/repeat -0 1 /start_waiter
/repeat -0.5 1 /report
''', keep_stdin_open=True)
    if world_a.connections != [b""] or \
            world_b.connections != [b"READY\r\n", b"RECONNECTED"]:
        raise AssertionError(
            f"background B retirement cancelled suspended A: "
            f"A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    assert_line(proc.stdout, "ISOLATION=1,1")


def socketless_owner_isolation(binary):
    with RequestGatedServer(b"READY\r\n", b"GO\n") as world_b:
        proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set secho=off
/set kecho=off
/set mecho=off
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/fg -n
/def -i reconnect_b = /connect -b B%; /test send("RECONNECTED", "B", "f")%; /set more=off%; /dokey flush%; /input reply%; /dokey newline
/def -i -1 -F -q -hMORE retire_b = /repeat -0 1 /reconnect_b%; /dc B
/def -i -1 -F -q -p100 -wB -mglob -t"GO" stale_first = /dokey pause%; /test send("STALE_FIRST", "B", "f")
/def -1 -F -q -p0 -wB -mglob -t"GO" stale_second = /test send("STALE_SECOND", "B", "f")
/set socketless_after=0
/set socketless_length=-1
/set socketless_value=missing
/def -i waiter = /test send("READY", "B")%; /test socketless_length := tfread(socketless_value)%; /test socketless_after := 1
/def -i start_waiter = /input /waiter%; /dokey newline
/def -i report = /set more=off%; /dokey flush%; /set wrapsize=80%; /test echo(strcat("SOCKETLESS=", socketless_after))%; /quit -y
/repeat -0 1 /start_waiter
/repeat -0.5 1 /report
''', keep_stdin_open=True)
    if world_b.connections != [b"READY\r\n", b"RECONNECTED"]:
        raise AssertionError(
            f"background B retirement cancelled socketless execution: "
            f"B={world_b.connections!r}\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    assert_line(proc.stdout, "SOCKETLESS=1")


def cross_world_owner_isolation(binary):
    with ScriptedServer([b""]) as world_a:
        with ScriptedServer([b"", b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set secho=off
/set mecho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/connect A
/def -i reconnect_b = /connect -b B%; /test send("RECONNECTED", "B", "f")
/def -i -1 -F -q -hMORE retire_b = /repeat -0 1 /reconnect_b%; /dc B
/def -i -1 -F -q -p100 -wB -mglob -t"GO" stale_first = /dokey pause%; /test send("STALE_FIRST", "B", "f")
/def -1 -F -q -p0 -wB -mglob -t"GO" stale_second = /test send("STALE_SECOND", "B", "f")
/def -i template = VALUE
/def -i inject_b = /test fake_recv("GO", "B")
/def -i caller_a = /let ignored=$(/inject_b)%; /let expanded=${{template}}%; /echo DATA %| /echo SINK%; /test send(strcat("A_AFTER_", expanded), "A", "f")%; /repeat -0 1 /quit -y
/repeat -wA -0 1 /caller_a
''', keep_stdin_open=True)
    expected_a = [b"A_AFTER_VALUE"]
    expected_b = [b"", b"RECONNECTED"]
    if world_a.connections != expected_a or world_b.connections != expected_b:
        raise AssertionError(
            f"cross-world B cancellation leaked into A: "
            f"expected A={expected_a!r}, B={expected_b!r}; "
            f"actual A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )


def cross_world_echo_owner_isolation(binary):
    with ScriptedServer([b""]) as world_a:
        with ScriptedServer([b"", b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set wrapsize=10
/set secho=off
/set mecho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b A
/connect B
/set more=off
/set more=on
/eval /repeat -S $[lines()-1] /test echo("FILL")
/def -i template = VALUE
/def -i reconnect_b = /connect -b B%; /test send("ECHO_RECONNECTED", "B", "f")%; /quit -y
/def -i -1 -F -q -hMORE retire_b = /set mecho=off%; /set more=off%; /repeat -0 1 /reconnect_b%; /dc B
/def -i -1 -F -q -p100 -wA -mglob -t"START" caller_a = /fg B%; /set mecho=all%; /let expanded=${{template}}%; /test send("A_ECHO_SURVIVED", "A", "f")
/test fake_recv("START", "A")
''')
    expected_a = [b"A_ECHO_SURVIVED"]
    expected_b = [b"", b"ECHO_RECONNECTED"]
    if world_a.connections != expected_a or world_b.connections != expected_b:
        raise AssertionError(
            f"cross-world echo cancellation leaked into A: "
            f"expected A={expected_a!r}, B={expected_b!r}; "
            f"actual A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )


def cross_world_pause_owner_isolation(binary):
    with ScriptedServer([b""]) as world_a:
        with ScriptedServer([b"", b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set secho=off
/set mecho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b A
/connect B
/def -i reconnect_b = /connect -b B%; /test send("PAUSE_RECONNECTED", "B", "f")%; /quit -y
/def -i -1 -F -q -hMORE retire_b = /set more=off%; /repeat -0 1 /reconnect_b%; /dc B
/def -i -1 -F -q -p100 -wA -mglob -t"START" caller_a = /fg B%; /dokey pause%; /test send("A_PAUSE_DEFAULT", "", "f")
/test fake_recv("START", "A")
''')
    expected_a = [b"A_PAUSE_DEFAULT"]
    expected_b = [b"", b"PAUSE_RECONNECTED"]
    if world_a.connections != expected_a or world_b.connections != expected_b:
        raise AssertionError(
            f"cross-world pagination cancellation changed A's destination: "
            f"expected A={expected_a!r}, B={expected_b!r}; "
            f"actual A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )


def indirect_owner_cancellation(binary):
    with ScriptedServer([b"", b""]) as world_a:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set wrapsize=10
/set secho=off
/set mecho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b A
/connect B
/fg B
/def -i reconnect_a = /connect -b A%; /test send("OWNER_RECONNECTED", "A", "f")%; /set mecho=off%; /set more=off%; /quit -y
/def -i -1 -F -q -wA -hSEND retire_a = /repeat -0 1 /reconnect_a%; /dc A
/def -i -1 -F -q -hMORE send_to_a = /test send("PROBE", "A", "h")
/def -i caller_a = /fg B%; /set mecho=all%; /test send("OWNER_STALE", "A", "f")
/set more=off
/set more=on
/eval /repeat -S $[lines()-1] /test echo("FILL")
/repeat -wA -S 1 /caller_a
''')
    expected_a = [b"", b"OWNER_RECONNECTED"]
    expected_b = [b""]
    if world_a.connections != expected_a or world_b.connections != expected_b:
        raise AssertionError(
            f"indirect owner cancellation executed a pending opcode: "
            f"expected A={expected_a!r}, B={expected_b!r}; "
            f"actual A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )


def keyboard_echo_cancellation(binary):
    prefix_chunk = "K" * 800
    prefix_setup = "\n".join(
        f'/test kprefix := strcat(kprefix, "{prefix_chunk}")'
        for _ in range(82)
    )
    with ScriptedServer([b"", b""]) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set wrapsize=10
/set secho=off
/set kecho=off
/set mecho=off
/test addworld("A", "", "127.0.0.1", "{server.port}")
/connect A
/def -i reconnect_a = /connect -b A%; /test send("KEY_RECONNECTED", "A", "f")%; /set kecho=off%; /set more=off%; /quit -y
/def -i -1 -F -q -hMORE retire_a = /repeat -0 1 /reconnect_a%; /dc A
/set more=off
/set more=on
/eval /repeat -S $[lines()-1] /test echo("FILL")
/test kprefix := ""
{prefix_setup}
/set kecho=on
/input /test send("KEY_STALE", "A", "f")
/dokey newline
''')
    expected = [b"", b"KEY_RECONNECTED"]
    if server.connections != expected:
        raise AssertionError(
            f"keyboard echo executed on a replacement incarnation: "
            f"expected={expected!r}, actual={server.connections!r}\n"
            f"{proc.stdout}"
        )


def bound_key_owner_cancellation(binary):
    with ScriptedServer([b"", b""]) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set secho=off
/set mecho=off
/test addworld("A", "", "127.0.0.1", "{server.port}")
/connect A
/def -i reconnect_a = /connect -b A%; /test send("KEYBIND_RECONNECTED", "A", "f")%; /repeat -0.2 1 /quit -y
/def -i -1 -F -q -wA -hSEND retire_a = /repeat -0 1 /reconnect_a%; /dc A
/def -i -b"Z" bound_retirement = /test send("KEYBIND_PROBE", "A", "h")%; /test send("KEYBIND_STALE", "A", "f")
/repeat -2 1 /quit -y
''', keep_stdin_open=True, stdin_data="Z")
    expected = [b"", b"KEYBIND_RECONNECTED"]
    if server.connections != expected:
        raise AssertionError(
            f"bound key resumed on a replacement incarnation: "
            f"expected={expected!r}, actual={server.connections!r}\n"
            f"{proc.stdout}"
        )


def dead_foreground_bound_key_reconnect(binary):
    with ScriptedServer([b"", b"KEYBIND_DEAD_CONTINUES"]) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set secho=off
/set mecho=off
/test addworld("A", "", "127.0.0.1", "{server.port}")
/connect A
/dc A
/def -i -b"Z" reconnect = /connect -b A%; /test send("KEYBIND_DEAD_CONTINUES", "A", "f")%; /quit -y
/repeat -2 1 /quit -y
''', keep_stdin_open=True, stdin_data="Z")
    if server.connections != [b"", b"KEYBIND_DEAD_CONTINUES"]:
        raise AssertionError(
            f"dead-foreground binding stopped during reconnect: "
            f"{server.connections!r}\n{proc.stdout}"
        )




def same_world_suspended_cancellation(binary):
    with RequestGatedServer(b"READY\r\n", b"GO\n") as world_a:
        proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set secho=off
/set kecho=off
/set mecho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/connect A
/def -i reconnect_a = /connect -b A%; /test send("RECONNECTED", "A", "f")%; /set more=off%; /dokey flush%; /dokey dline%; /input reply%; /dokey newline
/def -i -1 -F -q -hMORE retire_a = /repeat -0 1 /reconnect_a%; /dc A
/def -i -1 -F -q -p100 -wA -mglob -t"GO" stale_first = /dokey pause%; /test send("STALE_FIRST", "A", "f")
/def -1 -F -q -p0 -wA -mglob -t"GO" stale_second = /test send("STALE_SECOND", "A", "f")
/set same_after=0
/set same_length=-1
/set same_value=missing
/def -i waiter = /test send("READY", "A")%; /test same_length := tfread(same_value)%; /test same_after := 1
/def -i start_waiter = /input /waiter%; /dokey newline
/def -i report = /set more=off%; /dokey flush%; /set wrapsize=80%; /test echo(strcat("SAME_WORLD=", same_after, ",", same_length, ",", is_connected("A")))%; /quit -y
/repeat -wA -0 1 /start_waiter
/fg -n
/repeat -0.2 1 /report
''', keep_stdin_open=True)
    expected = [b"READY\r\n", b"RECONNECTED"]
    if world_a.connections != expected:
        raise AssertionError(
            f"same-world suspended work survived retirement: "
            f"expected={expected!r}, actual={world_a.connections!r}\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    assert_line(proc.stdout, "SAME_WORLD=0,-1,1")


def foreground_only_nested_execution(binary):
    with ScriptedServer([b""]) as world_a:
        with RequestGatedServer(
                b"READY\r\n", b"GO\n", connection_count=1) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set secho=off
/set kecho=off
/set mecho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/connect A
/def -i -1 -F -q -hMORE switch_only = /fg -n%; /set more=off%; /dokey flush%; /input reply%; /dokey newline
/def -i -1 -F -q -p100 -wB -mglob -t"GO" first = /dokey pause%; /test send("B_FIRST", "B", "f")
/def -1 -F -q -p0 -wB -mglob -t"GO" second = /test send("B_SECOND", "B", "f")
/def -i waiter = /test send("READY", "B")%; /let answer=%; /test tfread(answer)%; /test send(strcat("A_", answer), "A", "f")
/def -i start_waiter = /input /waiter%; /dokey newline%; /quit -y
/repeat -0 1 /start_waiter
''', keep_stdin_open=True)
    expected_a = [b"A_reply"]
    expected_b = [b"READY\r\nB_FIRSTB_SECOND"]
    if world_a.connections != expected_a or world_b.connections != expected_b:
        raise AssertionError(
            f"foreground-only switch cancelled valid execution: "
            f"expected A={expected_a!r}, B={expected_b!r}; "
            f"actual A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )


def sequential_reincarnation_isolation(binary):
    with ScriptedServer([b""]) as world_a:
        with ScriptedServer([b"", b"", b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set secho=off
/set mecho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/connect A
/set retire_count=0
/def -i reconnect_b = /connect -b B%; /test send(strcat("R", retire_count), "B", "f")%; /set more=off%; /dokey flush%; /set more=on
/def -i -F -q -hMORE retire_b = /test ++retire_count%; /repeat -0 1 /reconnect_b%; /dc B
/def -i -F -q -p100 -wB -mglob -t"*" stale = /dokey pause%; /test send("STALE", "B", "f")
/def -i finish = /test send(strcat("A_DONE_", retire_count), "A", "f")%; /quit -y
/def -i second = /set more=on%; /test fake_recv("TWO", "B")%; /repeat -wA -0.1 1 /finish
/def -i first = /set more=on%; /test fake_recv("ONE", "B")%; /repeat -wA -0.1 1 /second
/repeat -wA -0 1 /first
''', keep_stdin_open=True)
    expected_a = [b"A_DONE_2"]
    expected_b = [b"", b"R1", b"R2"]
    if world_a.connections != expected_a or world_b.connections != expected_b:
        raise AssertionError(
            f"sequential B reincarnations affected A or leaked stale work: "
            f"expected A={expected_a!r}, B={expected_b!r}; "
            f"actual A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )


def instruction_dump_reincarnation(binary):
    with ScriptedServer([b"", b""]) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set wrapsize=10
/set secho=off
/set mecho=off
/set iecho=off
/test addworld("A", "", "127.0.0.1", "{server.port}")
/connect -b A
/fg A
/def -i reconnect_a = /connect -b A%; /test send("RECONNECTED", "A", "f")%; /quit -y
/def -i -1 -F -q -hMORE reincarnate = /set iecho=off%; /repeat -0 1 /reconnect_a%; /dc A
/def -i dump = /set iecho=all%; /test send("STALE_DUMP", "A", "f")
/set more=off
/set more=on
/eval /repeat -S $[lines()-1] /test echo("FILL")
/dump
''')
    expected = [b"", b"RECONNECTED"]
    if server.connections != expected:
        raise AssertionError(
            f"instruction dump resumed stale execution: "
            f"expected={expected!r}, actual={server.connections!r}\n"
            f"{proc.stdout}"
        )


def macro_echo_reincarnation(binary):
    with ScriptedServer([b"", b""]) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set wrapsize=10
/set secho=off
/set mecho=off
/test addworld("A", "", "127.0.0.1", "{server.port}")
/connect -b A
/fg A
/def -i reconnect_a = /connect -b A%; /test send("RECONNECTED", "A", "f")%; /quit -y
/def -i -1 -F -q -hMORE reincarnate = /repeat -0 1 /reconnect_a%; /dc A
/def -1 -F -q -wA -mglob -t"GO" stale_body = /test send("STALE_BODY", "A", "f")
/def -i inject = /test fake_recv("GO", "A")
/def -1 -F -q -p100 -wA -mglob -t"START" receive = /set mecho=on%; /let ignored=$(/inject)%; /test send("OUTER_STALE", "A", "f")
/set more=off
/set more=on
/eval /repeat -S $[lines()-1] /test echo("FILL")
/test fake_recv("START", "A")
''')
    expected = [b"", b"RECONNECTED"]
    if server.connections != expected:
        raise AssertionError(
            f"macro echo resumed a stale body: expected={expected!r}, "
            f"actual={server.connections!r}\n{proc.stdout}"
        )


def macro_substitution_echo_reincarnation(binary):
    with ScriptedServer([b"", b""]) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set wrapsize=10
/set secho=off
/set mecho=off
/test addworld("A", "", "127.0.0.1", "{server.port}")
/connect -b A
/fg A
/def -i reconnect_a = /connect -b A%; /test send("RECONNECTED", "A", "f")%; /quit -y
/def -i -1 -F -q -hMORE reincarnate = /repeat -0 1 /reconnect_a%; /dc A
/def -i template = VALUE
/def -1 -F -q -p100 -wA -mglob -t"START" expand_template = /set mecho=all%; /let expanded=${{template}}%; /test send("OUTER_STALE", "A", "f")
/set more=off
/set more=on
/eval /repeat -S $[lines()-1] /test echo("FILL")
/test fake_recv("START", "A")
''')
    expected = [b"", b"RECONNECTED"]
    if server.connections != expected:
        raise AssertionError(
            f"macro substitution echo resumed stale execution: "
            f"expected={expected!r}, actual={server.connections!r}\n"
            f"{proc.stdout}"
        )


def undefined_macro_echo_reincarnation(binary):
    with ScriptedServer([b"", b""]) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set wrapsize=10
/set secho=off
/set mecho=off
/test addworld("A", "", "127.0.0.1", "{server.port}")
/connect -b A
/fg A
/def -i reconnect_a = /connect -b A%; /test send("RECONNECTED", "A", "f")%; /quit -y
/def -i -1 -F -q -hMORE reincarnate = /repeat -0 1 /reconnect_a%; /dc A
/def -1 -F -q -p100 -wA -mglob -t"START" expand_missing = /set mecho=all%; /let expanded=${{missing_lifetime_macro}}%; /test send("OUTER_STALE", "A", "f")
/set more=off
/set more=on
/eval /repeat -S $[lines()-1] /test echo("FILL")
/test fake_recv("START", "A")
''')
    expected = [b"", b"RECONNECTED"]
    assert_not_contains(proc.stdout, "$missing_lifetime_macro -->")
    if server.connections != expected:
        raise AssertionError(
            f"undefined macro output resumed stale expansion: "
            f"expected={expected!r}, actual={server.connections!r}\n"
            f"{proc.stdout}"
        )


def pipeline_echo_reincarnation(binary):
    with ScriptedServer([b"", b""]) as server:
        proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set wrapsize=10
/set secho=off
/set mecho=off
/test addworld("A", "", "127.0.0.1", "{server.port}")
/connect -b A
/fg A
/def -i reconnect_a = /connect -b A%; /test send("RECONNECTED", "A", "f")%; /quit -y
/def -i -1 -F -q -hMORE reincarnate = /repeat -0 1 /reconnect_a%; /dc A
/def -1 -F -q -p100 -wA -mglob -t"START" run_pipe = /set mecho=all%; /echo DATA %| /echo SINK%; /test send("OUTER_STALE", "A", "f")
/set more=off
/set more=on
/eval /repeat -S $[lines()-1] /test echo("FILL")
/test fake_recv("START", "A")
''')
    expected = [b"", b"RECONNECTED"]
    if server.connections != expected:
        raise AssertionError(
            f"pipeline echo resumed stale execution: expected={expected!r}, "
            f"actual={server.connections!r}\n{proc.stdout}"
        )


def foreground_switch_reincarnation(binary):
    with ScriptedServer([b"", b""]) as world_a:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set wrapsize=10
/set secho=off
/set mecho=off
/test mload_count := 0
/test addworld("A", "", "127.0.0.1", "{world_a.port}", "", "", "{{ROOT}}/a.tf")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b A
/connect -b B
/fg B
/eval /repeat -S $[lines()+5] /test fake_recv("FILL", "A")
/set sockmload=on
/def -i reconnect_a = /connect -b A%; /quit -y
/def -i -1 -F -q -hMORE reincarnate = /repeat -0 1 /reconnect_a%; /dc A
/set more=off
/set more=on
/test fg_result := eval("/fg A")
''', {"a.tf": '''/test ++mload_count
/test send(strcat("MLOAD_", mload_count), "A", "f")
'''})
    expected_a = [b"MLOAD_1", b"MLOAD_2"]
    if world_a.connections != expected_a or world_b.connections != [b""]:
        raise AssertionError(
            f"foreground switch resumed stale mfile loading: "
            f"expected A={expected_a!r}, actual A={world_a.connections!r}, "
            f"B={world_b.connections!r}\n{proc.stdout}"
        )


def disconnect_output_reincarnation(binary):
    with ScriptedServer([b"", b""]) as world_a:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set wrapsize=10
/set secho=off
/set mecho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b A
/connect -b B
/fg B
/def -i reconnect_a = /connect -b A%; /test send("RECONNECTED", "A", "f")%; /test send(strcat("STATE_", is_connected("A")), "B", "f")%; /test send("AFTER", "A", "f")%; /quit -y
/def -i -1 -F -q -hMORE reincarnate = /repeat -0 1 /reconnect_a%; /dc A
/set more=off
/set more=on
/eval /repeat -S $[lines()-1] /test echo("FILL")
/dc A
''')
    expected_a = [b"", b"RECONNECTEDAFTER"]
    if world_a.connections != expected_a or \
            world_b.connections != [b"STATE_1"]:
        raise AssertionError(
            f"disconnect output retired the replacement: "
            f"expected A={expected_a!r}, B={[b'STATE_1']!r}; "
            f"actual A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )


def disconnect_output_foreground_change(binary):
    with ScriptedServer([b""]) as world_a:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set wrapsize=10
/set secho=off
/set mecho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/connect -b A
/fg A
/set more=off
/set status_int_more=fg("A")
/set more=on
/eval /repeat -S $[lines()-1] /test echo("FILL")
/dc B
/test send(strcat("STATE_", is_connected("B")), "A", "f")
/quit -y
''')
    if world_a.connections != [b"STATE_0"] or \
            world_b.connections != [b""]:
        raise AssertionError(
            f"disconnect target was lost after a foreground-only callback: "
            f"expected A={[b'STATE_0']!r}, B={[b'']!r}; "
            f"actual A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )


def preactivity_reincarnation(binary):
    with ScriptedServer([b""]) as foreground:
        with ScriptedServer([b"", b""]) as background:
            proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set secho=off
/test addworld("foreground", "", "127.0.0.1", "{foreground.port}")
/test addworld("A", "", "127.0.0.1", "{background.port}")
/def -ag -q -hCONNECT gag_connect =
/connect -b foreground
/connect -b A
/fg A
/fg foreground
/def -i reconnect_a = /connect -b A%; /test send("NEW", "A", "f")%; /quit -y
/def -1 -F -q -wA -hPREACTIVITY reincarnate = /repeat -0 1 /reconnect_a%; /dc A
/def -1 -F -q -wA -hACTIVITY stale_activity = /test send("STALE_ACTIVITY", "A", "f")
/def -1 -F -q -wA -hBGTEXT stale_bgtext = /test send("STALE_BGTEXT", "A", "f")
/test fake_recv("OLD\\n", "A")
''')
    expected = [b"", b"NEW"]
    if background.connections != expected or foreground.connections != [b""]:
        raise AssertionError(
            f"preactivity resumed stale output callbacks: "
            f"expected={expected!r}, actual={background.connections!r}\n"
            f"{proc.stdout}"
        )


def activity_reincarnation(binary):
    with ScriptedServer([b""]) as foreground:
        with ScriptedServer([b"", b""]) as background:
            proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set secho=off
/test nested := 0
/test addworld("foreground", "", "127.0.0.1", "{foreground.port}")
/test addworld("A", "", "127.0.0.1", "{background.port}")
/def -ag -q -hCONNECT gag_connect =
/connect -b foreground
/connect -b A
/fg A
/fg foreground
/def -i reconnect_a = /connect -b A%; /test nested := 0%; /test send("NEW", "A", "f")%; /quit -y
/def -1 -F -q -wA -hACTIVITY reincarnate = /test nested := 1%; /repeat -0 1 /reconnect_a%; /dc A
/def -F -q -wA -hBGTEXT stale_bgtext = /if (!nested) /test send("STALE_BGTEXT", "A", "f")%; /endif
/test fake_recv("OLD\\n", "A")
''')
    expected = [b"", b"NEW"]
    if background.connections != expected or foreground.connections != [b""]:
        raise AssertionError(
            f"activity resumed stale background-text callbacks: "
            f"expected={expected!r}, actual={background.connections!r}\n"
            f"{proc.stdout}"
        )



def output_owner_retirement(binary):
    with ScriptedServer([b"", b""]) as world_a:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set wrapsize=10
/set more=on
/set secho=off
/set mecho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b A
/connect B
/set more=off
/set more=on
/eval /repeat -S $[lines()-1] /test echo("FILL")
/def -i -1 -F -q -hMORE retire_a = /set mecho=off%; /set more=off%; /dc A%; /connect -b A%; /test send("OWNER_RECONNECTED", "A", "f")
/def -i owner_a = /fg B%; /set mecho=all%; /echo PRIME%; /test send("OWNER_STALE", "A", "f")
/repeat -wA -S 1 /owner_a
/quit -y
''')
    expected_a = [b"", b"OWNER_RECONNECTED"]
    if world_a.connections != expected_a or world_b.connections != [b""]:
        raise AssertionError(
            f"output target survival hid owner retirement: "
            f"expected A={expected_a!r}, B={[b'']!r}; "
            f"actual A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )


def socketless_output_retirement(binary):
    padding = "/test ignored := 1%; " * 30
    substitution_padding = "/let expanded=${template}%; " * 25
    variants = {
        "MECHO": f'''/def -i runner = /set mecho=all%; {padding}/test socketless_after := 1%; /test echo(strcat("SOCKETLESS_MECHO_missing=", socketless_after, ",", retired, ",", is_connected("A")))%; /quit -y
''',
        "IECHO": f'''/def -i runner = /set iecho=all%; {padding}/test socketless_after := 1%; /test echo(strcat("SOCKETLESS_IECHO_missing=", socketless_after, ",", retired, ",", is_connected("A")))%; /quit -y
''',
        "SUBSTITUTION": f'''/def -i template = VALUE
/def -i runner = /set mecho=all%; {substitution_padding}/test socketless_value := strlen(expanded)%; /test socketless_after := 1%; /test echo(strcat("SOCKETLESS_SUBSTITUTION_", socketless_value, "=", socketless_after, ",", retired, ",", is_connected("A")))%; /quit -y
''',
    }
    for name, definitions in variants.items():
        with ScriptedServer([b""]) as world_a:
            proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set wrapsize=10
/set more=on
/set secho=off
/set mecho=off
/set iecho=off
/set retired=0
/set socketless_after=0
/set socketless_value=missing
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/connect A
/set more=off
/set more=on
/eval /repeat -S $[lines()-1] /test echo("FILL")
/def -i -1 -F -q -hMORE retire_a = /test retired := 1%; /set mecho=off%; /set iecho=off%; /set more=off%; /dokey flush%; /set wrapsize=80%; /dc A
{definitions}/repeat -2 1 /quit -y
/repeat -S 1 /runner
''')
        if world_a.connections != [b""]:
            raise AssertionError(
                f"socketless {name} changed the retired transport: "
                f"{world_a.connections!r}\n{proc.stdout}"
            )
        value = "5" if name == "SUBSTITUTION" else "missing"
        assert_line(
            proc.stdout,
            f"SOCKETLESS_{name}_{value}=1,1,0",
        )


def ordinary_eof_suspended_owner(binary):
    with EofOnRequestServer(b"READY\r\n") as world_a:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set secho=off
/set kecho=off
/set mecho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/connect A
/set eof_after=0
/set eof_length=-1
/set eof_value=missing
/def -i report = /set more=off%; /dokey flush%; /set wrapsize=80%; /test echo(strcat("OWNER_EOF=", eof_after, ",", eof_length, ",", eof_value, ",", is_connected("A")))%; /quit -y
/def -i -1 -F -q -wA -hDISCONNECT release = /fg -n%; /dokey flush%; /input reply%; /dokey newline
/def -i waiter = /test send("READY", "A")%; /test eof_length := tfread(eof_value)%; /test eof_after := 1%; /test send("EOF_STALE", "A", "f")
/def -i start_waiter = /input /waiter%; /dokey newline
/repeat -wA -0 1 /start_waiter
/fg -n
/repeat -0.2 1 /report
''', keep_stdin_open=True)
    if world_a.connections != [b"READY\r\n"] or world_b.connections != [b""]:
        raise AssertionError(
            f"ordinary EOF resumed suspended owner: "
            f"A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    assert_line(proc.stdout, "OWNER_EOF=0,-1,reply,0")


def unrelated_eof_suspended_owner(binary):
    with ScriptedServer([b""]) as world_a:
        with EofOnRequestServer(b"READY\r\n") as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set secho=off
/set kecho=off
/set mecho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/connect A
/set unrelated_after=0
/set unrelated_length=-1
/set unrelated_value=missing
/def -i -1 -F -q -wB -hDISCONNECT release = /dokey flush%; /input reply%; /dokey newline
/def -i waiter = /test send("READY", "B")%; /test unrelated_length := tfread(unrelated_value)%; /test unrelated_after := 1%; /test send(strcat("A_CONTINUED_", unrelated_after, "_", unrelated_length, "_", unrelated_value), "A", "f")%; /quit -y
/def -i start_waiter = /input /waiter%; /dokey newline
/repeat -wA -0 1 /start_waiter
''', keep_stdin_open=True)
    expected_a = [b"A_CONTINUED_1_5_reply"]
    if world_a.connections != expected_a or \
            world_b.connections != [b"READY\r\n"]:
        raise AssertionError(
            f"unrelated EOF cancelled suspended owner: "
            f"expected A={expected_a!r}, B={[b'READY\\r\\n']!r}; "
            f"actual A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )


def retirement_resource_cleanup(binary):
    with ScriptedServer([b"", b""]) as world_a:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set wrapsize=10
/set more=on
/set secho=off
/set mecho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b A
/connect B
/set more=off
/set more=on
/eval /repeat -S $[lines()-1] /test echo("FILL")
/def -i cleanup_report = /test send("CLEANUP_OK", "A", "f")%; /quit -y
/def -i -1 -F -q -hMORE retire_a = /set mecho=off%; /set more=off%; /dc A%; /connect -b A%; /repeat -0.1 1 /cleanup_report
/def -i template = VALUE
/def -i deepest = /let expanded=${{template}}%; /set mecho=all%; /echo DATA %| /echo SINK%; /result expanded
/def -i middle = /let nested=$(/deepest)%; /result nested
/def -i owner_a = /fg B%; /let ignored=$(/middle)%; /test send("CLEANUP_STALE", "A", "f")
/repeat -wA -S 1 /owner_a
''')
    expected_a = [b"", b"CLEANUP_OK"]
    if world_a.connections != expected_a or world_b.connections != [b""]:
        raise AssertionError(
            f"retirement cleanup leaked stale nested work: "
            f"expected A={expected_a!r}, B={[b'']!r}; "
            f"actual A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )


def repeated_retirement_notification(binary):
    with ScriptedServer([b"", b""]) as world_a:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set wrapsize=10
/set more=on
/set secho=off
/set mecho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b A
/connect B
/set more=off
/set more=on
/eval /repeat -S $[lines()-1] /test echo("FILL")
/def -i -1 -F -q -hMORE retire_twice = /set mecho=off%; /set more=off%; /dc A%; /dc A%; /connect -b A%; /test send("REPLACEMENT_ALIVE", "A", "f")
/def -i owner_a = /fg B%; /set mecho=all%; /echo PRIME%; /test send("REPEATED_STALE", "A", "f")
/repeat -wA -S 1 /owner_a
/quit -y
''')
    expected_a = [b"", b"REPLACEMENT_ALIVE"]
    if world_a.connections != expected_a or world_b.connections != [b""]:
        raise AssertionError(
            f"repeated retirement affected replacement or resumed stale work: "
            f"expected A={expected_a!r}, B={[b'']!r}; "
            f"actual A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )




def foreground_owner_cancellation(binary):
    with ScriptedServer([b""]) as world_a:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/set sockmload=off
/test world_count := 0
/test load_count := 0
/test fg_result := -1
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}", "", "", "{{ROOT}}/b.tf")
/connect -b B
/connect -b A
/fg A
/def -i finish = /test send("B_CONTROL", "B", "f")%; /test echo(strcat("FG_OWNER=", world_count, ",", load_count, ",", fg_result, ",", is_connected("A"), ",", is_connected("B")))%; /quit -y
/def -1 -F -q -wB -hWORLD retire_a = /test ++world_count%; /repeat -0 1 /finish%; /dc A
/def -F -q -wB -hLOAD stale_load = /test ++load_count%; /test send("STALE_LOAD", "B", "f")
/set sockmload=on
/def -i owner = /test fg_result := eval("/fg B")%; /test send("STALE_AFTER", "B", "f")
/repeat -wA -S 1 /owner
''', {"b.tf": ""})
    assert_line(proc.stdout, "FG_OWNER=1,0,-1,0,1")
    if world_a.connections != [b""] or \
            world_b.connections != [b"B_CONTROL"]:
        raise AssertionError(
            f"cancelled foreground caller resumed setup: "
            f"A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )


def foreground_null_owner_cancellation(binary):
    with ScriptedServer([b""]) as world_a:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/test hook_count := 0
/test null_result := -1
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/connect -b A
/fg A
/def -i finish = /test retry_result := eval("/fg B")%; /test send("B_CONTROL", "B", "f")%; /test echo(strcat("FG_NULL_OWNER=", hook_count, ",", null_result, ",", retry_result, ",", is_connected("A"), ",", is_connected("B"), ",", fg_world()))%; /quit -y
/def -1 -F -hWORLD retire_null_owner = /test ++hook_count%; /repeat -0 1 /finish%; /dc A
/def -i owner = /test null_result := eval("/fg -n")%; /test send("STALE_NULL_AFTER", "B", "f")
/repeat -wA -S 1 /owner
''')
    assert_line(proc.stdout, "FG_NULL_OWNER=1,-1,1,0,1,B")
    assert_not_contains(proc.stdout, "illegal reentry")
    if world_a.connections != [b""] or \
            world_b.connections != [b"B_CONTROL"]:
        raise AssertionError(
            f"cancelled null-foreground caller leaked work: "
            f"A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )


def foreground_unrelated_retirement(binary):
    with ScriptedServer([b""]) as world_a:
        with ScriptedServer([b""]) as world_b:
            with ScriptedServer([b""]) as world_c:
                proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/set sockmload=off
/test load_count := 0
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}", "", "", "{{ROOT}}/b.tf")
/test addworld("C", "", "127.0.0.1", "{world_c.port}")
/connect -b B
/connect -b C
/connect -b A
/fg A
/def -1 -F -q -wB -hWORLD retire_c = /dc C
/def -F -q -wB -hLOAD load_b = /test ++load_count%; /test send("B_LOAD", "B", "f")
/set sockmload=on
/def -i owner = /test fg_result := eval("/fg B")%; /test send("A_CONTINUES", "A", "f")%; /test echo(strcat("FG_UNRELATED=", load_count, ",", fg_result, ",", is_connected("A"), ",", is_connected("B"), ",", is_connected("C")))%; /quit -y
/repeat -wA -S 1 /owner
''', {"b.tf": ""})
    assert_line(proc.stdout, "FG_UNRELATED=1,1,1,1,0")
    if world_a.connections != [b"A_CONTINUES"] or \
            world_b.connections != [b"B_LOAD"] or \
            world_c.connections != [b""]:
        raise AssertionError(
            f"unrelated retirement cancelled foreground setup: "
            f"A={world_a.connections!r}, B={world_b.connections!r}, "
            f"C={world_c.connections!r}\n{proc.stdout}"
        )


def foreground_connect_owner_cancellation(binary):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    accepted = threading.Event()
    stop = threading.Event()
    errors = []

    def accept_connection():
        try:
            conn, _ = listener.accept()
            accepted.set()
            conn.settimeout(TIMEOUT)
            with conn:
                if conn.recv(1) == b"\0":
                    accepted.clear()
        except OSError as exc:
            if not stop.is_set():
                errors.append(exc)
        finally:
            listener.close()

    thread = threading.Thread(target=accept_connection, daemon=True)
    thread.start()
    try:
        with ScriptedServer([b""]) as world_a:
            proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{port}")
/connect -b A
/fg A
/def -i finish = /test echo(strcat("CONNECT_OWNER=", is_connected("A"), ",", is_connected("B")))%; /quit -y
/def -1 -F -q -wB -hWORLD retire_owner = /repeat -0.2 1 /finish%; /dc A
/repeat -wA -S 1 /connect B
''')
    finally:
        stop.set()
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1) as conn:
                conn.sendall(b"\0")
        except OSError:
            pass
        thread.join(TIMEOUT)
    if thread.is_alive() or errors:
        raise AssertionError(
            f"foreground connect server failed: alive={thread.is_alive()}, "
            f"errors={errors!r}"
        )
    assert_line(proc.stdout, "CONNECT_OWNER=0,0")
    if accepted.is_set() or world_a.connections != [b""]:
        raise AssertionError(
            f"cancelled foreground connect reached transport: "
            f"accepted={accepted.is_set()}, A={world_a.connections!r}\n"
            f"{proc.stdout}"
        )


def background_recycle_owner_cancellation(binary):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    listener.settimeout(TIMEOUT)
    port = listener.getsockname()[1]
    reconnected = threading.Event()
    stop = threading.Event()
    errors = []

    def accept_connections():
        try:
            first, _ = listener.accept()
            first.settimeout(TIMEOUT)
            with first:
                while first.recv(4096):
                    pass
            second, _ = listener.accept()
            reconnected.set()
            second.settimeout(TIMEOUT)
            with second:
                if second.recv(1) == b"\0":
                    reconnected.clear()
        except OSError as exc:
            if not stop.is_set():
                errors.append(exc)
        finally:
            listener.close()

    thread = threading.Thread(target=accept_connections, daemon=True)
    thread.start()
    try:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/test addworld("A", "", "127.0.0.1", "{port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/connect -b A
/fg B
/def -i report = /test sent := send("B_CONTROL", "B", "f")%; /test echo(strcat("BG_RECYCLE=", is_connected("A"), ",", sent))%; /quit -y
/repeat -wA -0.05 1 /connect -b A
/dc A
/repeat -0.2 1 /report
''')
    finally:
        stop.set()
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1) as conn:
                conn.sendall(b"\0")
        except OSError:
            pass
        thread.join(TIMEOUT)
    if thread.is_alive() or errors:
        raise AssertionError(
            f"background recycle server failed: "
            f"alive={thread.is_alive()}, errors={errors!r}"
        )
    assert_line(proc.stdout, "BG_RECYCLE=0,1")
    if reconnected.is_set() or world_b.connections != [b"B_CONTROL"]:
        raise AssertionError(
            f"cancelled background recycle reached transport: "
            f"reconnected={reconnected.is_set()}, "
            f"B={world_b.connections!r}\n{proc.stdout}"
        )


def disconnect_hook_reconnect(binary):
    connections = []

    def serve(server):
        first = server.accept()
        first.close()
        server.release(first)
        connections.append(b"")

        second = server.accept()
        received = bytearray()
        with second:
            second.sendall(b"READY\n")
            while True:
                data = second.recv(4096)
                if not data:
                    break
                received.extend(data)
        server.release(second)
        connections.append(bytes(received))

    with LoopbackServer(serve, 2) as server:
        run_tf(binary, f'''/set connect=blocking
/set secho=off
/test addworld("A", "", "127.0.0.1", "{server.port}")
/def -1 -F -q -wA -hDISCONNECT nest = /dokey pause
/def -1 -F -q -hMORE reconnect = /connect -b A%; /test send("STALE", "A", "f")
/def -1 -F -q -wA -mglob -t"READY" ready = /test send("REPLACEMENT", "A", "f")%; /quit -y
/connect -b A
''')
    if connections != [b"", b"REPLACEMENT"]:
        raise AssertionError(
            f"disconnect hook failed to preserve only its replacement: "
            f"{connections!r}"
        )


def queued_hook_parent_cancellation(binary):
    with ScriptedServer([b""]) as world_a:
        with ScriptedServer([b""]) as world_b:
            run_tf(binary, f'''/set connect=blocking
/set secho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/connect A
/def -1 -F -q -p100 -wB -mglob -t"GO" retire_parent = /dc A
/def -1 -F -q -p0 -wB -mglob -t"GO" one_shot = /test send("SECOND", "B", "f")
/def -i second = /test fake_recv("GO", "B")%; /repeat -0.1 1 /quit -y
/repeat -wB -0.2 1 /second
/def -i owner = /test fake_recv("GO", "B")%; /test send("STALE", "A", "f")
/repeat -wA -S 1 /owner
''')
    if world_a.connections != [b""] or world_b.connections != [b"SECOND"]:
        raise AssertionError(
            f"cancelled hook queue consumed a one-shot callback: "
            f"A={world_a.connections!r}, B={world_b.connections!r}"
        )


def foreground_restore_activity_and_reader(binary):
    released = threading.Event()
    world_a_connections = []
    queued = tf_byte_string(b"GO\nPENDING\n")

    def serve_a(server):
        conn = server.accept()
        received = bytearray()
        with conn:
            while b"READY" not in received:
                data = conn.recv(4096)
                if not data:
                    raise AssertionError("A closed before foreground switch")
                received.extend(data)
            conn.sendall(b"AFTER\n")
            released.wait(0.2)
            released.set()
            while True:
                try:
                    data = conn.recv(4096)
                except ConnectionResetError:
                    break
                if not data:
                    break
                received.extend(data)
        server.release(conn)
        world_a_connections.append(bytes(received))

    with LoopbackServer(serve_a) as world_a:
        with GatedAcceptServer(released, [b""]) as world_c:
            with ScriptedServer([b""]) as world_b:
                run_tf(binary, f'''/set connect=blocking
/set background=off
/set secho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/test addworld("C", "", "127.0.0.1", "{world_c.port}")
/connect -b B
/connect A
/fg A
/def -i report = /test send(strcat("REPORT=", nactive(), ",", fg_world()), "A", "f")%; /quit -y
/def -1 -F -q -wB -hWORLD retire_target = /test send("READY", "A", "f")%; /connect -b C%; /repeat -0.5 1 /report%; /dc B
/def -1 -F -q -wA -mglob -t"AFTER" restored = /test send(strcat("RESTORE=", nactive(), ",", fg_world()), "A", "f")%; /quit -y
/def -1 -F -q -wA -mglob -t"GO" switch = /fg B
/test fake_recv({queued}, "A", "r")
''')
    if world_a_connections != [b"READYRESTORE=1,A"] or \
            world_b.connections != [b""] or world_c.connections != [b""]:
        raise AssertionError(
            f"foreground recovery lost activity or reader state: "
            f"A={world_a_connections!r}, B={world_b.connections!r}, "
            f"C={world_c.connections!r}"
        )


def foreground_status_state_coherence(binary):
    with ScriptedServer([b""]) as world_a:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/set visual=on
/set status_retire=0
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/connect -b A
/fg A
/def -i retire_status_active = /if ({{status_retire}} & (fg_world() =~ "B") & is_connected("B")) /set status_retire=0%; /dc B%; /endif%; /result nactive()
/set status_fields=@active
/set status_int_active=retire_status_active()
/test fake_recv("FILL", "B")
/set status_retire=1
/fg B
/test send(strcat("A_DEFAULT=", nactive("B") > 0), "", "f")
/quit -y
''', visual_terminal=True)
    if world_a.connections != [b"A_DEFAULT=1"] or \
            world_b.connections != [b""]:
        raise AssertionError(
            f"failed foreground status transition corrupted state: "
            f"A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )


def foreground_status_active_rollback(binary):
    with ScriptedServer([b""]) as world_a:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/set visual=on
/set more=on
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/connect -b A
/fg A
/dokey pause
/test fake_recv("PENDING", "A")
/test active_before := nactive()
/set status_retire=0
/def -i retire_target = /if ({{status_retire}} & (fg_world() =~ "A") & is_connected("B")) /set status_retire=0%; /dc B%; /endif%; /result nactive()
/set status_fields=@active
/set status_int_active=retire_target()
/set status_retire=1
/test fg_result := eval("/fg B")
/test send(strcat("ROLLBACK=", fg_result, ",", fg_world(), ",", active_before, ",", nactive(), ",", is_connected("B")), "A", "f")
/quit -y
''', visual_terminal=True)
    if world_a.connections != [b"ROLLBACK=0,A,1,1,0"] or \
            world_b.connections != [b""]:
        raise AssertionError(
            f"failed foreground switch leaked active state: "
            f"A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )


def foreground_dead_screen_rollback(binary):
    with ScriptedServer([b""]) as world_a, \
            ScriptedServer([b""]) as world_b:
        proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/connect -b A
/fg A
/dc A
/def -i report = /test echo(strcat("DEAD_ROLLBACK=", fg_result, ",", fg_world(), ",", is_connected("B")))%; /quit -y
/def -1 -F -q -wB -hWORLD retire_target = /dc B
/test fg_result := eval("/fg B")
/repeat -0 1 /report
''')
    assert_line(proc.stdout, "DEAD_ROLLBACK=0,A,0")
    if world_a.connections != [b""] or world_b.connections != [b""]:
        raise AssertionError(
            f"failed foreground switch lost the dead-world screen: "
            f"A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )


def foreground_status_target_retirement(binary):
    with ScriptedServer([b""]) as world_a:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set wrapsize=10
/set secho=off
/set mecho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/connect -b A
/fg A
/eval /repeat -S $[lines()+5] /test fake_recv("FILL", "B")
/def -i -1 -F -q -hMORE retire_b = /set more=off%; /dokey flush%; /dc B
/set status_int_more=(!is_connected("B") ? send("STALE_STATUS", "A", "f") : 0)
/set more=off
/set more=on
/def -i owner = /fg B%; /test send("A_CONTROL", "A", "f")%; /quit -y
/repeat -wA -S 1 /owner
''', visual_terminal=True)
    if world_a.connections != [b"A_CONTROL"] or \
            world_b.connections != [b""]:
        raise AssertionError(
            f"foreground status evaluation continued after target retirement: "
            f"A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )

def ownerless_more_retirement(binary):
    with ScriptedServer([b"FILL\n" * 200]) as world_a:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/set visual=on
/set scroll=off
/set background=on
/set more=on
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/connect -b A
/fg A
/set more_count=0
/def -i -1 -F -q -hMORE retire_a = /test ++more_count%; /set more=off%; /dc A
/set status_fields=@more
/set status_int_more=(!is_connected("A") ? send("STALE_STATUS", "B", "f") : 0)
/def -i report = /test send(strcat("B_CONTROL_", more_count), "B", "f")%; /quit -y
/repeat -1 1 /report
''', interactive_terminal=True)
    if world_a.connections != [b""] or \
            world_b.connections != [b"B_CONTROL_1"]:
        raise AssertionError(
            f"ownerless More output resumed after socket retirement: "
            f"A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )



def more_owner_retirement(binary):
    with ScriptedServer([b""]) as world_a:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set wrapsize=80
/set secho=off
/set mecho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b A
/connect B
/def -i -1 -F -q -hMORE retire_b = /set more=off%; /dokey flush%; /dc B
/set status_int_more=(!is_connected("B") ? send("STALE_STATUS", "A", "f") : 0)
/set more=off
/set more=on
/eval /repeat -S $[lines()-1] /test echo("FILL")
/repeat -wB -S 1 /test echo("STALE_PENDING_OUTPUT")
/test send("A_CONTROL", "A", "f")
/quit -y
''', visual_terminal=True)
    assert_not_contains(proc.stdout, "STALE_PENDING_OUTPUT")
    if world_a.connections != [b"A_CONTROL"] or \
            world_b.connections != [b""]:
        raise AssertionError(
            f"More output/status resumed after owner retirement: "
            f"A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )


def more_indicator_returns_after_reactivation(binary):
    with ScriptedServer([b"", b""]) as world_a, \
            ScriptedServer([b""]) as world_b:
        proc = run_tf(binary, f'''/set connect=blocking
/set visual=on
/set scroll=off
/set background=on
/set more=on
/set secho=off
/test check_more := 0
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/connect A
/set status_fields=@more
/set status_int_more=(check_more ? send("MORE_VISIBLE", "B", "f") : 0)
/def -i recover = /connect -b A%; /fg B%; /set check_more=1%; /fg A%; /repeat -0.2 1 /quit -y
/def -i -1 -F -q -hMORE retire_a = /repeat -0 1 /recover%; /dc A
/eval /repeat -S $[lines()+5] /test echo("FILL")
/repeat -2 1 /quit -y
''', interactive_terminal=True)
    if world_a.connections != [b"", b""] or \
            world_b.connections != [b"MORE_VISIBLE"]:
        raise AssertionError(
            f"reactivated pager did not refresh More status: "
            f"A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )


def more_indicator_follows_foreground_switch(binary):
    with ScriptedServer([b""]) as world_a, \
            ScriptedServer([b""]) as world_b:
        proc = run_tf(binary, f'''/set connect=blocking
/set virtscreen=off
/set visual=on
/set scroll=off
/set background=on
/set more=on
/set secho=off
/test watch_more := 0
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/connect A
/set status_fields=@more
/set status_int_more=(watch_more ? send("B_MORE_VISIBLE", "B", "f") : 0)
/def -i exercise_b = /test watch_more := 1%; /repeat -0.2 1 /quit -y%; /repeat -S 100 /test echo("B_FILL")
/def -i -1 -F -q -hMORE retire_a = /fg B%; /repeat -wB -0 1 /exercise_b%; /dc A
/eval /repeat -wA -S $[lines()+5] /test echo("A_FILL")
''', interactive_terminal=True)
    if world_a.connections != [b""] or \
            len(world_b.connections) != 1 or \
            b"B_MORE_VISIBLE" not in world_b.connections[0]:
        raise AssertionError(
            f"retired foreground suppressed replacement More status: "
            f"A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )






def world_file_target_retirement(binary):
    with ScriptedServer([b""]) as world_a:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/set sockmload=off
/test mfile_fire := 0
/test mfile_reconnecting := 0
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}", "", "", "{{ROOT}}/b.tf")
/connect -b B
/connect -b A
/fg A
/def -i reincarnate_b = /test mfile_reconnecting := 1%; /dc B%; /connect -b B%; /test mfile_reconnecting := 0
/def -i stale_mfile_body = /reincarnate_b%; /test send("STALE_MFILE_BODY", "B", "f")
/test mfile_fire := 1
/set sockmload=on
/def -i owner = /fg B%; /test send("A_CONTROL", "A", "f")%; /quit -y
/repeat -wA -S 1 /owner
''', {"b.tf": '''/test mfile_fire & !mfile_reconnecting ? stale_mfile_body() : 0
/test mfile_fire & !mfile_reconnecting ? send("STALE_MFILE_LINE", "B", "f") : 0
'''})
    assert_not_contains(proc.stdout, "last command is incomplete")
    if world_a.connections != [b"A_CONTROL"] or \
            world_b.connections != [b""]:
        raise AssertionError(
            f"world file continued after target reincarnation: "
            f"A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )


def world_file_owner_retirement(binary):
    with ScriptedServer([b""]) as world_a:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}", "user", "secret", "{{ROOT}}/b.tf")
/connect -b A
/def -F -q -wB -hCONNECT stale_connect = /test send("STALE_CONNECT", "B", "f")
/def -F -q -wB -hLOGIN stale_login = /test send("STALE_LOGIN", "B", "f")
/repeat -wA -S 1 /connect -b B
/test send("B_CONTROL", "B", "f")
/test echo(strcat("MFILE_OWNER=", is_connected("A"), ",", is_connected("B")))
/quit -y
''', {"b.tf": '/dc A\n/test send("STALE_MFILE", "B", "f")\n'})
    assert_line(proc.stdout, "MFILE_OWNER=0,1")
    assert_not_contains(proc.stdout, "last command is incomplete")
    if world_a.connections != [b""] or \
            world_b.connections != [b"B_CONTROL"]:
        raise AssertionError(
            f"establishment continued after mfile retired its caller: "
            f"A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )


def trigger_short_listing_retirement(binary):
    with ScriptedServer([b"", b""]) as world_a:
        proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set wrapsize=80
/set secho=off
/set mecho=off
/set iecho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/connect -b A
/def -F -p1 -wA -mglob -t"MATCH" LIST_SHORT =
/set more=off
/set more=on
/eval /repeat -S $[lines()-1] /test echo("FILL")
/def -i finish = /connect -b A%; /test send("REPLACEMENT", "A", "f")%; /test echo("SHORT_LIST_DONE")%; /quit -y
/def -i -1 -F -q -hMORE retire = /set more=off%; /dokey flush%; /repeat -0 1 /finish%; /dc A
/repeat -wA -S 1 /trigger -n -wA MATCH
''')
    assert_line(proc.stdout, "SHORT_LIST_DONE")
    assert_not_contains(proc.stdout, "LIST_SHORT")
    assert_not_contains(proc.stdout, "would have triggered")
    if world_a.connections != [b"", b"REPLACEMENT"]:
        raise AssertionError(
            f"short trigger listing continued after retirement: "
            f"{world_a.connections!r}\n{proc.stdout}"
        )


def trigger_long_listing_retirement(binary):
    with ScriptedServer([b"", b""]) as world_a:
        proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set wrapsize=80
/set secho=off
/set mecho=off
/set iecho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/connect -b A
/def -F -p2 -wA -mglob -t"MATCH" LIST_LONG_FIRST =
/def -F -p1 -wA -mglob -t"MATCH" LIST_LONG_LATER =
/set more=off
/set more=on
/eval /repeat -S $[lines()-2] /test echo("FILL")
/def -i finish = /connect -b A%; /test send("REPLACEMENT", "A", "f")%; /test echo("LONG_LIST_DONE")%; /quit -y
/def -i -1 -F -q -hMORE retire = /set more=off%; /dokey flush%; /repeat -0 1 /finish%; /dc A
/repeat -wA -S 1 /trigger -l -wA MATCH
''')
    assert_line(proc.stdout, "LONG_LIST_DONE")
    assert_not_contains(proc.stdout, "LIST_LONG_LATER")
    assert_not_contains(proc.stdout, "would have triggered")
    if world_a.connections != [b"", b"REPLACEMENT"]:
        raise AssertionError(
            f"long trigger listing continued after retirement: "
            f"{world_a.connections!r}\n{proc.stdout}"
        )


def trigger_summary_restoration(binary):
    with ScriptedServer([b""]) as world_a:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set wrapsize=80
/set secho=off
/set mecho=off
/set iecho=off
/test default_result := -1
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b A
/connect -b B
/fg A
/def -F -p1 -wB -mglob -t"MATCH" LIST_SUMMARY =
/def -i -1 -F -q -hMORE retire_b = /set more=off%; /dokey flush%; /dc B
/def -i owner = /fg B%; /set more=off%; /set more=on%; /eval /repeat -S $[lines()-3] /test echo("FILL")%; /trigger -n -wB MATCH%; /test default_result := send("A_DEFAULT", "", "f")%; /test echo(strcat("SUMMARY_DEFAULT=", default_result, ",", is_connected("A"), ",", is_connected("B")))%; /quit -y
/repeat -wA -S 1 /owner
''')
    assert_line(proc.stdout, "SUMMARY_DEFAULT=1,1,0")
    assert_not_contains(proc.stdout, "send: Not connected.")
    if world_a.connections != [b"A_DEFAULT"] or world_b.connections != [b""]:
        raise AssertionError(
            f"summary callback failed to restore A: "
            f"A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )


def trigger_listing_owner_retirement(binary):
    with ScriptedServer([b""]) as world_a:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set wrapsize=80
/set secho=off
/set mecho=off
/set iecho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b A
/connect -b B
/fg A
/def -F -p1 -wB -mglob -t"MATCH" OWNER_LIST_ITEM =
/def -i finish = /test send("B_CONTROL", "B", "f")%; /quit -y
/def -i -1 -F -q -hMORE retire_a = /set more=off%; /dokey flush%; /repeat -0 1 /finish%; /dc A
/def -i owner = /fg B%; /set more=off%; /set more=on%; /eval /repeat -S $[lines()-1] /test echo("FILL")%; /trigger -n -wB MATCH%; /test send("STALE_OWNER_AFTER", "B", "f")
/repeat -wA -S 1 /owner
''')
    assert_not_contains(proc.stdout, "OWNER_LIST_ITEM")
    assert_not_contains(proc.stdout, "would have triggered")
    if world_a.connections != [b""] or \
            world_b.connections != [b"B_CONTROL"]:
        raise AssertionError(
            f"listing continued after caller retirement: "
            f"A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )



def trigger_listing_condition_retirement(binary):
    with ScriptedServer([b""]) as world_a:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set secho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/connect -b A
/fg A
/def -i finish = /test send("B_CONTROL", "B", "f")%; /quit -y
/def -i retire_condition = /repeat -0 1 /finish%; /dc A%; /return 0
/def -i stale_condition = /test send("STALE_CONDITION", "B", "f")%; /return 0
/def -F -p2 -wB -E"retire_condition()" -mglob -t"MATCH" CONDITION_FIRST =
/def -F -p1 -wB -E"stale_condition()" -mglob -t"MATCH" CONDITION_SECOND =
/def -i owner = /fg B%; /trigger -n -wB MATCH
/repeat -wA -S 1 /owner
''')
    assert_not_contains(proc.stdout, "would have triggered")
    if world_a.connections != [b""] or \
            world_b.connections != [b"B_CONTROL"]:
        raise AssertionError(
            f"cancelled listing evaluated a later condition: "
            f"A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )

def trigger_listing_control(binary):
    with ScriptedServer([b""]) as world_a:
        proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/connect -b A
/def -F -p1 -wA -mglob -t"NORMAL" LIST_CONTROL =
/test short_result := eval("/trigger -n -wA NORMAL")
/test long_result := eval("/trigger -l -wA NORMAL")
/test echo(strcat("LIST_CONTROL_RESULT=", short_result, ",", long_result))
/quit -y
''')
    output = normalized_output(proc.stdout)
    assert_line(proc.stdout, "LIST_CONTROL_RESULT=1,1")
    if output.count("LIST_CONTROL") != 3 or \
            output.count("would have triggered 1 macro") != 2:
        raise AssertionError(
            f"ordinary listing format or counts changed:\n{proc.stdout}"
        )
    if world_a.connections != [b""]:
        raise AssertionError(
            f"ordinary listing changed transport: {world_a.connections!r}"
        )


def quote_qecho_retirement(binary):
    with ScriptedServer([b""]) as world_a:
        proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set wrapsize=80
/set secho=off
/set mecho=off
/set iecho=off
/set qecho=on
/test more_count := 0
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/connect -b A
/def -i -1 -F -q -hMORE retire = /test ++more_count%; /set more=off%; /dokey flush%; /dc A
/set more=off
/set more=on
/eval /repeat -S $[lines()-1] /test echo("FILL")
/test quote_result := eval("/quote -S -wA -decho '{{ROOT}}/quote.txt")
/test echo(strcat("QUOTE_ECHO_RESULT=", quote_result, ",", more_count, ",", is_connected("A")))
/quit -y
''', {"quote.txt": "QUOTE_FIRST\nQUOTE_SECOND\n"})
    assert_line(proc.stdout, "QUOTE_ECHO_RESULT=1,1,0")
    assert_not_contains(proc.stdout, "QUOTE_SECOND")
    if world_a.connections != [b""]:
        raise AssertionError(
            f"qecho cancellation changed transport: {world_a.connections!r}"
        )


def quote_disposition_retirement(binary):
    variants = {
        "send": ("STALE_SEND_1\nSTALE_SEND_2\n", "STALE_SEND_2", ",0"),
        "exec": (
            "/test exec_first := 1\n/test exec_second := 1\n",
            "/test exec_second := 1",
            ",0",
        ),
    }
    for disposition, (contents, stale_marker, result_suffix) in variants.items():
        with ScriptedServer([b""]) as world_a:
            proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set wrapsize=80
/set secho=off
/set mecho=off
/set iecho=off
/set qecho=on
/test more_count := 0
/test exec_first := 0
/test exec_second := 0
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/connect -b A
/def -i -1 -F -q -hMORE retire = /test ++more_count%; /set more=off%; /dokey flush%; /dc A
/set more=off
/set more=on
/eval /repeat -S $[lines()-1] /test echo("FILL")
/test quote_result := eval("/quote -S -wA -d{disposition} '{{ROOT}}/quote.txt")
/test echo(strcat("QUOTE_{disposition.upper()}=", quote_result, ",", more_count, ",", exec_second))
/quit -y
''', {"quote.txt": contents})
        assert_line(
            proc.stdout,
            f"QUOTE_{disposition.upper()}=1,1{result_suffix}",
        )
        assert_not_contains(proc.stdout, stale_marker)
        if world_a.connections != [b""]:
            raise AssertionError(
                f"cancelled {disposition} quote reached transport: "
                f"{world_a.connections!r}\n{proc.stdout}"
            )


def quote_process_cancellation(binary):
    with ScriptedServer([b""]) as world_a:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/set qecho=off
/test kill_count := 0
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/connect -b A
/def -F -q -hKILL killed = /test ++kill_count
/quote -S -wA -dexec '{{ROOT}}/quote.txt
/test send("B_CONTROL", "B", "f")
/test echo(strcat("QUOTE_PROCESS=", kill_count, ",", is_connected("A"), ",", is_connected("B")))
/quit -y
''', {
                "quote.txt":
                    "/dc A\n"
                    "/test send(\"STALE_RESCHEDULED\", \"B\", \"f\")\n",
            })
    assert_line(proc.stdout, "QUOTE_PROCESS=1,0,1")
    if world_a.connections != [b""] or \
            world_b.connections != [b"B_CONTROL"]:
        raise AssertionError(
            f"cancelled quote process was rescheduled: "
            f"A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )


def quote_self_kill_retirement(binary):
    with ScriptedServer([b""]) as world_a:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/test kill_count := 0
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/connect -b A
/def -F -q -hKILL killed = /test ++kill_count
/def -i self_kill = /kill %{{qpid}}%; /dc A
/def -i finish = /test send("B_CONTROL", "B", "f")%; /test echo(strcat("QUOTE_SELF_KILL=", kill_count, ",", is_connected("A"), ",", is_connected("B")))%; /quit -y
/test qpid := eval("/quote -0.1 -wA -dexec '{{ROOT}}/quote.txt")
/repeat -0.5 1 /finish
''', {"quote.txt": "/self_kill\n"})
    assert_line(proc.stdout, "QUOTE_SELF_KILL=1,0,1")
    if world_a.connections != [b""] or \
            world_b.connections != [b"B_CONTROL"]:
        raise AssertionError(
            f"self-killed quote was cleaned twice or resumed: "
            f"A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )


def synchronous_repeat_cancellation(binary):
    with ScriptedServer([b""]) as world_a:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/test kill_count := 0
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/connect -b A
/def -F -q -hKILL killed = /test ++kill_count
/def -i retire = /dc A%; /test send("STALE_REPEAT", "B", "f")
/repeat -wA -S 2 /retire
/test send("B_CONTROL", "B", "f")
/test echo(strcat("REPEAT_CANCEL=", kill_count, ",", is_connected("A"), ",", is_connected("B")))
/quit -y
''')
    assert_line(proc.stdout, "REPEAT_CANCEL=1,0,1")
    if world_a.connections != [b""] or \
            world_b.connections != [b"B_CONTROL"]:
        raise AssertionError(
            f"cancelled synchronous repeat was killed twice or resumed: "
            f"A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )


def socketless_quote_retirement(binary):
    with ScriptedServer([b""]) as world_a:
        proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set wrapsize=80
/set secho=off
/set mecho=off
/set iecho=off
/set qecho=on
/test more_count := 0
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/connect -b A
/def -i -1 -F -q -hMORE retire = /test ++more_count%; /set more=off%; /dokey flush%; /dc A
/set more=off
/set more=on
/eval /repeat -S $[lines()-1] /test echo("FILL")
/test quote_result := eval("/quote -S -decho '{{ROOT}}/quote.txt")
/test echo(strcat("SOCKETLESS_QUOTE=", quote_result, ",", more_count, ",", is_connected("A")))
/quit -y
''', {"quote.txt": "SOCKETLESS_FIRST\nSOCKETLESS_SECOND\n"})
    assert_line(proc.stdout, "SOCKETLESS_QUOTE=1,1,0")
    if normalized_output(proc.stdout).count("SOCKETLESS_SECOND") != 2:
        raise AssertionError(
            f"socketless quote did not continue normally:\n{proc.stdout}"
        )
    if world_a.connections != [b""]:
        raise AssertionError(
            f"socketless quote changed transport: {world_a.connections!r}"
        )


def normal_quote_control(binary):
    with ScriptedServer([b"NORMAL_SEND\r\n"]) as world_a:
        proc = run_tf(binary, f'''/set connect=blocking
/set secho=off
/set qecho=on
/test normal_exec := 0
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/connect -b A
/quote -S -wA -decho '{{ROOT}}/echo.txt
/quote -S -wA -dsend '{{ROOT}}/send.txt
/quote -S -wA -dexec '{{ROOT}}/exec.txt
/test echo(strcat("NORMAL_QUOTE=", normal_exec, ",", is_connected("A")))
/quit -y
''', {
                "echo.txt": "NORMAL_ECHO\n",
                "send.txt": "NORMAL_SEND\n",
                "exec.txt": "/test normal_exec := 1\n",
            })
    assert_line(proc.stdout, "NORMAL_QUOTE=1,1")
    if normalized_output(proc.stdout).count("NORMAL_ECHO") != 2:
        raise AssertionError(f"normal qecho/echo behavior changed:\n{proc.stdout}")
    if world_a.connections != [b"NORMAL_SEND\r\n"]:
        raise AssertionError(
            f"normal quote send changed: {world_a.connections!r}"
        )


def world_output_owner_cancellation(binary):
    with ScriptedServer([b""]) as world_a:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set secho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/connect -b A
/fg B
/fg A
/def -i finish = /test send("B_CONTROL", "B", "f")%; /quit -y
/def -i -1 -F -q -wB -hPREACTIVITY retire_owner = /repeat -0 1 /finish%; /dc A
/def -F -q -wB -hACTIVITY stale_activity = /test send("STALE_ACTIVITY", "B", "f")
/def -F -q -wB -hBGTEXT stale_bgtext = /test send("STALE_BGTEXT", "B", "f")
/def -i owner = /test echo("OUTPUT", "", 0, "wB")%; /test send("STALE_AFTER", "B", "f")
/repeat -wA -S 1 /owner
''')
    if world_a.connections != [b""] or \
            world_b.connections != [b"B_CONTROL"]:
        raise AssertionError(
            f"world output continued after owner cancellation: "
            f"A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )


def disconnect_owner_cancellation(binary):
    with ScriptedServer([b""]) as world_a:
        with ScriptedServer([b""]) as world_b:
            proc = run_tf(binary, f'''/set connect=blocking
/set visual=off
/set secho=off
/test addworld("A", "", "127.0.0.1", "{world_a.port}")
/test addworld("B", "", "127.0.0.1", "{world_b.port}")
/connect -b B
/connect -b A
/fg B
/fg A
/def -i finish = /test survived := send("B_SURVIVED", "B", "f")%; /test echo(strcat("DC_OWNER=", survived, ",", is_connected("A"), ",", is_connected("B")))%; /quit -y
/def -i -1 -F -q -wB -hPREACTIVITY retire_owner = /repeat -0 1 /finish%; /dc A
/repeat -wA -S 1 /dc B
''')
    assert_line(proc.stdout, "DC_OWNER=1,0,1")
    assert_not_contains(proc.stdout, "send: Not connected.")
    if world_a.connections != [b""] or \
            world_b.connections != [b"B_SURVIVED"]:
        raise AssertionError(
            f"disconnect continued after owner cancellation: "
            f"A={world_a.connections!r}, B={world_b.connections!r}\n"
            f"{proc.stdout}"
        )

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "binary", nargs="?", default="src/tf", type=Path,
        help="TinyFugue binary to exercise (default: src/tf)",
    )
    parser.add_argument(
        "--without-widechar", action="store_true",
        help="skip synthetic-input and ICU charset cases",
    )
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"binary not found: {binary}")

    features = probe_features(binary)
    try:
        address_families = [
            info[0] for info in socket.getaddrinfo(
                "localhost.localdomain", 1, type=socket.SOCK_STREAM
            )
        ]
    except socket.gaierror:
        address_families = []
    multi_address_fallback = (
        bool(address_families)
        and address_families[0] == socket.AF_INET6
        and socket.AF_INET in address_families[1:]
    )
    cases = [
        ("mfile selects B during A initialization",
         initialization_mfile_select),
        ("mfile connects B during A initialization",
         initialization_mfile_connect),
        ("manual reconnect from dead foreground",
         foreground_dead_manual_reconnect),
        ("foreground callback reincarnation",
         foreground_hook_reincarnation),
        ("H_CONNECT same-world reincarnation",
         connect_hook_reincarnation),
        ("H_LOGIN same-world reincarnation",
         login_hook_reincarnation),
        ("quiet H_SEND reincarnation", send_hook_reincarnation),
        ("consumed H_SEND disconnect", consumed_send_disconnect),
        ("consumed H_SEND reconnect", consumed_send_reconnect),
        ("unconsumed H_SEND retirement", unconsumed_send_retirement),
        ("consumed H_SEND connected", consumed_send_connected),
        ("ordinary H_SEND control", ordinary_send_control),
        ("cross-world consumed H_SEND", cross_world_consumed_send),
        ("H_SEND owner retirement", owner_retirement_during_send_hook),
        ("H_SEND foreground and suppression", send_hook_foreground),
        ("recursive H_SEND", recursive_send_hook),
        ("queued-line reincarnation", queued_reincarnation),
        ("retired queue draining", retired_queue_draining),
        ("prompted process replacement", prompted_process_replacement),
        ("H_BAMF same-world reincarnation", bamf_reincarnation),
        ("simulated portal handoff", bamf_portal_handoff),
        ("H_MORE output preserves pending line",
         more_hook_output_preserves_pending_line),
        ("nested send buffers", nested_sends),
        ("SOCKECHO retirement", sockecho_retirement),
        ("explicit fake_recv target", explicit_fake_recv_target),
        ("ordinary output hook reincarnation", output_reentrancy_ordinary),
        ("output foreground change remains valid",
         output_reentrancy_foreground_change),
        ("alert output hook reincarnation", output_reentrancy_alert),
        ("world alert output hook reincarnation",
         output_reentrancy_world_alert),
        ("async pending completion", async_pending_completion),
        ("async pending reconnect", async_pending_reconnect),
        ("async H_CONNECT reconnect", async_connect_hook_reconnect),
        ("async pending foreground change",
         async_pending_foreground_change),
        ("fg_sock(NULL) rejects hook connect", foreground_null_hook_connect),
        ("macro echo reincarnation", macro_echo_reincarnation),
        ("macro substitution echo reincarnation",
         macro_substitution_echo_reincarnation),
        ("undefined macro echo reincarnation",
         undefined_macro_echo_reincarnation),
        ("pipeline echo reincarnation", pipeline_echo_reincarnation),
        ("foreground switch reincarnation", foreground_switch_reincarnation),
        ("disconnect output reincarnation", disconnect_output_reincarnation),
        ("disconnect output foreground change",
         disconnect_output_foreground_change),
        ("preactivity reincarnation", preactivity_reincarnation),
        ("activity reincarnation", activity_reincarnation),
        ("suspended owner isolation", suspended_owner_isolation),
        ("socketless owner isolation", socketless_owner_isolation),
        ("cross-world owner isolation", cross_world_owner_isolation),
        ("cross-world echo owner isolation",
         cross_world_echo_owner_isolation),
        ("cross-world pause owner isolation",
         cross_world_pause_owner_isolation),
        ("indirect owner cancellation", indirect_owner_cancellation),
        ("keyboard echo cancellation", keyboard_echo_cancellation),
        ("bound-key owner cancellation", bound_key_owner_cancellation),
        ("dead foreground bound-key reconnect",
         dead_foreground_bound_key_reconnect),
        ("same-world suspended cancellation",
         same_world_suspended_cancellation),
        ("foreground-only nested execution",
         foreground_only_nested_execution),
        ("sequential reincarnation isolation",
         sequential_reincarnation_isolation),
        ("instruction dump reincarnation", instruction_dump_reincarnation),
        ("output owner retirement", output_owner_retirement),
        ("socketless output retirement", socketless_output_retirement),
        ("ordinary EOF suspended owner", ordinary_eof_suspended_owner),
        ("unrelated EOF suspended owner", unrelated_eof_suspended_owner),
        ("retirement resource cleanup", retirement_resource_cleanup),
        ("repeated retirement notification",
         repeated_retirement_notification),
        ("foreground owner cancellation", foreground_owner_cancellation),
        ("null foreground owner cancellation",
         foreground_null_owner_cancellation),
        ("foreground unrelated retirement",
         foreground_unrelated_retirement),
        ("foreground connect owner cancellation",
         foreground_connect_owner_cancellation),
        ("background recycle owner cancellation",
         background_recycle_owner_cancellation),
        ("nested disconnect hook reconnect", disconnect_hook_reconnect),
        ("queued hook parent cancellation", queued_hook_parent_cancellation),
        ("foreground restore activity and reader",
         foreground_restore_activity_and_reader),
        ("foreground status state coherence",
         foreground_status_state_coherence),
        ("foreground active-state rollback",
         foreground_status_active_rollback),
        ("dead foreground screen rollback",
         foreground_dead_screen_rollback),
        ("foreground status target retirement",
         foreground_status_target_retirement),
        ("ownerless More retirement", ownerless_more_retirement),
        ("More owner retirement", more_owner_retirement),
        ("More indicator after reactivation",
         more_indicator_returns_after_reactivation),
        ("More indicator after retired foreground switch",
         more_indicator_follows_foreground_switch),
        ("world file target retirement", world_file_target_retirement),
        ("world file owner retirement", world_file_owner_retirement),
        ("short trigger listing retirement",
         trigger_short_listing_retirement),
        ("long trigger listing retirement",
         trigger_long_listing_retirement),
        ("trigger summary restoration", trigger_summary_restoration),
        ("trigger listing owner retirement",
         trigger_listing_owner_retirement),
        ("trigger listing condition retirement",
         trigger_listing_condition_retirement),
        ("ordinary trigger listing", trigger_listing_control),
        ("quote qecho retirement", quote_qecho_retirement),
        ("quote disposition retirement", quote_disposition_retirement),
        ("quote process cancellation", quote_process_cancellation),
        ("quote self-kill retirement", quote_self_kill_retirement),
        ("synchronous repeat cancellation", synchronous_repeat_cancellation),
        ("socketless quote retirement", socketless_quote_retirement),
        ("ordinary quote control", normal_quote_control),
        ("world output owner cancellation",
         world_output_owner_cancellation),
        ("disconnect owner cancellation", disconnect_owner_cancellation),
    ]
    if multi_address_fallback:
        cases.extend([
            ("repeated multi-address failure", repeated_address_failure),
            ("async multi-address fallback", async_multi_address_fallback),
        ])
    else:
        print("SKIP: multi-address fallback cases "
              "(localhost.localdomain does not resolve as IPv6 then IPv4)")
    if args.without_widechar:
        print("SKIP: synthetic reincarnation cleanup (widechar disabled)")
        print("SKIP: Telnet charset replacement (widechar disabled)")
        print("SKIP: nested charset replacement (widechar disabled)")
        print("SKIP: overlong charset rejection (widechar disabled)")
        print("SKIP: MCCP charset replacement (widechar disabled)")
        print("SKIP: invalid UTF-8 send expansion (widechar disabled)")
        print("SKIP: SOCKECHO charset roundtrip (widechar disabled)")
    else:
        cases.extend([
            ("synthetic reincarnation cleanup", synthetic_reincarnation),
            ("Telnet charset replacement", charset_replacement),
            ("nested charset replacement", nested_charset_replacement),
            ("overlong charset rejection", overlong_charset),
            ("invalid UTF-8 send expansion", invalid_utf8_send),
            ("SOCKECHO charset roundtrip", sockecho_charset),
        ])
    if features["option102"] and not args.without_widechar:
        cases.append(("nested Telnet subnegotiation",
                      nested_telnet_subnegotiation))
    elif args.without_widechar:
        print("SKIP: nested Telnet subnegotiation "
              "(fixture requires byte-preserving char())")
    else:
        print("SKIP: nested Telnet subnegotiation (option102 disabled)")
    if features["mccp"]:
        if not args.without_widechar:
            cases.append(("MCCP stream end with trailing plaintext",
                          mccp_charset_replacement))
        cases.append((
            "recursive MCCP reincarnation",
            mccp_reincarnation_network if args.without_widechar
            else mccp_reincarnation,
        ))
    else:
        print("SKIP: MCCP charset replacement (MCCP disabled)")
        print("SKIP: MCCP reincarnation (MCCP disabled)")
    if features["ssl"]:
        cases.extend([
            ("TLS failure same-world reconnect", tls_failure_reconnect),
            ("TLS failure callback send", tls_failure_callback_send),
            ("TLS write failure", tls_write_failure),
        ])
        if multi_address_fallback:
            cases.append(
                ("TLS multi-address fallback", tls_multi_address_fallback)
            )
    elif ssl is None:
        print("SKIP: TLS lifetime cases (Python ssl unavailable)")
    else:
        print("SKIP: TLS lifetime cases (TinyFugue SSL disabled)")

    for name, case in cases:
        case(binary)
        print(f"PASS: {name}")


if __name__ == "__main__":
    main()
