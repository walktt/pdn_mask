"""
Точка входа для запуска сервиса: python run.py.

uvicorn.run() на Windows (начиная с версии 0.36) жёстко использует ProactorEventLoop,
даже если выставить asyncio.set_event_loop_policy() заранее — а psycopg в async-режиме
требует SelectorEventLoop. Поэтому здесь сервер запускается напрямую через
uvicorn.Server.serve() на вручную созданном SelectorEventLoop, минуя uvicorn.run().
"""

import asyncio
import sys

import uvicorn


def main() -> None:
    config = uvicorn.Config("api:app", host="0.0.0.0", port=8000)
    server = uvicorn.Server(config)

    loop = asyncio.SelectorEventLoop() if sys.platform == "win32" else asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(server.serve())


if __name__ == "__main__":
    main()
