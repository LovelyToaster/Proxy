#!/usr/bin/env python3
"""Bounded in-memory TCP throughput fixture, no external network or packages."""
import concurrent.futures
import json
import socket
import sys
import threading
import time

SIZE = 128 * 1024 * 1024
BLOCK = b"x" * (256 * 1024)


def serve(conn):
    with conn:
        conn.settimeout(20)
        mode = conn.recv(1)
        if mode == b"D":
            for _ in range(SIZE // len(BLOCK)):
                conn.sendall(BLOCK)
        elif mode == b"U":
            count = 0
            while count < SIZE:
                data = conn.recv(min(len(BLOCK), SIZE - count))
                if not data:
                    raise RuntimeError("short upload")
                count += len(data)
            conn.sendall(b"K")


def transfer(host, port, mode):
    with socket.create_connection((host, port), timeout=20) as conn:
        conn.sendall(mode.encode())
        if mode == "U":
            for _ in range(SIZE // len(BLOCK)):
                conn.sendall(BLOCK)
            if conn.recv(1) != b"K":
                raise RuntimeError("missing upload acknowledgement")
        else:
            count = 0
            while count < SIZE:
                data = conn.recv(len(BLOCK))
                if not data:
                    raise RuntimeError("short download")
                count += len(data)


if sys.argv[1] == "server":
    family = socket.AF_INET6 if ":" in sys.argv[2] else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((sys.argv[2], int(sys.argv[3])))
        listener.listen(32)
        print("ready throughput", flush=True)
        while True:
            conn, _ = listener.accept()
            threading.Thread(target=serve, args=(conn,), daemon=True).start()
else:
    host, port, label = sys.argv[2], int(sys.argv[3]), sys.argv[4]
    for mode in ("D", "U"):
        for streams in (1, 4):
            for repeat in (1, 2):
                start = time.perf_counter()
                with concurrent.futures.ThreadPoolExecutor(streams) as pool:
                    list(pool.map(lambda _: transfer(host, port, mode), range(streams)))
                elapsed = time.perf_counter() - start
                print(json.dumps(dict(label=label, direction=mode, streams=streams,
                                      repeat=repeat, bytes=SIZE * streams,
                                      seconds=round(elapsed, 4),
                                      mbps=round(SIZE * streams * 8 / elapsed / 1e6, 2))), flush=True)
