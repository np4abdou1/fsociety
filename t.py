import requests
import time

TOKEN = "7933260420:AAG37jmdanboUUqeWkS7cpQr6zz7jtPeF5g"
API_URL = f"https://api.telegram.org/bot{TOKEN}/"

offset = 0

print("Listening for messages...")

while True:
    try:
        resp = requests.get(API_URL + "getUpdates", params={"timeout": 10, "offset": offset})
        data = resp.json()

        if not data["ok"]:
            print("Telegram error:", data)
            time.sleep(1)
            continue

        for update in data["result"]:
            offset = update["update_id"] + 1

            message = update.get("message") or update.get("channel_post")

            if message:
                chat = message["chat"]
                chat_id = chat["id"]
                chat_type = chat["type"]
                text = message.get("text", "")

                print("\n=== NEW UPDATE ===")
                print("Chat Type:", chat_type)
                print("Chat Title:", chat.get("title"))
                print("Chat ID:", chat_id)
                print("Message:", text)

    except Exception as e:
        print("Error:", e)
        time.sleep(1)
