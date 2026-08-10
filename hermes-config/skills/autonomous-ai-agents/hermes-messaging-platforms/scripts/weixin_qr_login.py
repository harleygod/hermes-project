# -*- coding: utf-8 -*-
"""Weixin iLink QR login: fetch QR -> show PNG on screen -> poll status -> print creds.
Run with the hermes venv python (has aiohttp+PIL+qrcode):
  python weixin_qr_login.py
Needs: uv pip install --python "C:\\Users\\user\\AppData\\Local\\hermes\\hermes-agent\\venv\\Scripts\\python.exe" qrcode
"""
import asyncio
import os
import sys
import time

HERMES_AGENT_DIR = r"C:\Users\user\AppData\Local\hermes\hermes-agent"
sys.path.insert(0, HERMES_AGENT_DIR)

from gateway.platforms.weixin import (  # noqa: E402
    _api_get, ILINK_BASE_URL, EP_GET_BOT_QR, EP_GET_QR_STATUS)

QR_PNG = r"C:\Users\user\AppData\Local\Temp\weixin_qr.png"


async def main():
    import aiohttp
    import qrcode
    async with aiohttp.ClientSession(trust_env=True) as session:
        for attempt in range(3):
            qr = await _api_get(session, base_url=ILINK_BASE_URL,
                                endpoint=f"{EP_GET_BOT_QR}?bot_type=3",
                                timeout_ms=15000)
            qval = str(qr.get("qrcode") or "")
            qurl = str(qr.get("qrcode_img_content") or "") or qval
            print(f"===QR_URL=== {qurl}", flush=True)
            img = qrcode.QRCode(border=2)
            img.add_data(qurl)
            img.make(fit=True)
            img.make_image(fill_color="black", back_color="white").save(QR_PNG)
            os.startfile(QR_PNG)  # pop the PNG on screen for the user to scan
            print(f"===QR_SHOWN=== {QR_PNG} attempt={attempt + 1}", flush=True)
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                try:
                    st = await _api_get(session, base_url=ILINK_BASE_URL,
                                        endpoint=f"{EP_GET_QR_STATUS}?qrcode={qval}",
                                        timeout_ms=10000)
                except Exception:
                    await asyncio.sleep(1)
                    continue
                status = str(st.get("status") or "wait")
                if status != "wait":
                    print(f"===STATUS=== {status}", flush=True)
                    print(f"===FULL=== {st}", flush=True)  # creds land here
                    return
                await asyncio.sleep(2)
            print("===EXPIRED=== refreshing", flush=True)
    print("===ALL_EXPIRED===", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
