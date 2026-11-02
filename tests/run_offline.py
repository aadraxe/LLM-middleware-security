"""Run pytest without local secrets, external connections, or model downloads.

Usage: venv/Scripts/python.exe -B tests/run_offline.py [pytest arguments]
Loopback sockets support Windows asyncio's internal socketpair. Real httpx
HTTP transports are blocked, while TestClient's in-process transport works.
"""
import os
from pathlib import Path
import socket
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
for name in ("GROQ_API_KEY", "GATEWAY_API_KEYS", "PIPELINE_MODE", "CLASSIFIER_BACKEND",
             "LOCAL_CLASSIFIER_PATH", "JUDGE_CACHE_JSONL", "JUDGE_CACHE_DIR", "CASCADE_CONFIG"):
    os.environ.pop(name, None)
os.environ.update(PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", HF_HUB_OFFLINE="1",
                  TRANSFORMERS_OFFLINE="1", HF_HUB_DISABLE_TELEMETRY="1",
                  OMP_NUM_THREADS="1", MKL_NUM_THREADS="1")

_connect = socket.socket.connect
_connect_ex = socket.socket.connect_ex


def _local(address):
    return isinstance(address, tuple) and address[0] in ("127.0.0.1", "::1")


def connect(sock, address):
    if not _local(address):
        raise RuntimeError("External connections disabled for offline tests")
    return _connect(sock, address)


def connect_ex(sock, address):
    if not _local(address):
        raise RuntimeError("External connections disabled for offline tests")
    return _connect_ex(sock, address)


socket.socket.connect = connect
socket.socket.connect_ex = connect_ex

import httpx
import pytest


def no_http(*args, **kwargs):
    raise RuntimeError("Real HTTP transport disabled for offline tests")


async def no_async_http(*args, **kwargs):
    raise RuntimeError("Real HTTP transport disabled for offline tests")


httpx.HTTPTransport.handle_request = no_http
httpx.AsyncHTTPTransport.handle_async_request = no_async_http

if __name__ == "__main__":
    raise SystemExit(pytest.main(sys.argv[1:] or ["tests/", "-q", "-p", "no:cacheprovider"]))
