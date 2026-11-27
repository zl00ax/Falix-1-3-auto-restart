import html
import os
from typing import Optional

import requests


def send_telegram_report(
    bot_token: str,
    chat_id: str,
    caption: str,
    image_path: Optional[str] = None,
) -> bool:
    if not bot_token or not chat_id:
        print("[Telegram] 未配置 TG_BOT_TOKEN 或 TG_CHAT_ID，跳过推送")
        return False

    direct_proxies = {"http": None, "https": None}
    safe_caption = caption[:1000] + ("..." if len(caption) > 1000 else "")

    if image_path and os.path.exists(image_path):
        url = f"https://api.telegram.org/bot{bot_token}/sendPhoto"
        try:
            with open(image_path, "rb") as photo:
                resp = requests.post(
                    url,
                    data={
                        "chat_id": chat_id,
                        "caption": safe_caption,
                        "parse_mode": "HTML",
                    },
                    files={"photo": photo},
                    proxies=direct_proxies,
                    timeout=30,
                )
            if resp.ok:
                print("[Telegram] 图文推送成功")
                return True
            print(f"[Telegram] 图片推送失败 ({resp.status_code}): {resp.text}")
        except Exception as e:
            print(f"[Telegram] 图片推送异常: {e}")

    return send_telegram_text(bot_token, chat_id, caption)


def send_telegram_text(bot_token: str, chat_id: str, text: str) -> bool:
    if not bot_token or not chat_id:
        return False

    direct_proxies = {"http": None, "https": None}
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        resp = requests.post(
            url,
            data={
                "chat_id": chat_id,
                "text": text[:4000],
                "parse_mode": "HTML",
            },
            proxies=direct_proxies,
            timeout=20,
        )
        if resp.ok:
            print("[Telegram] 文本推送成功")
            return True
        print(f"[Telegram] 文本推送失败 ({resp.status_code}): {resp.text}")
        return False
    except Exception as e:
        print(f"[Telegram] 文本推送异常: {e}")
        return False


def escape_html(text: str) -> str:
    return html.escape(str(text or ""))
