import os
from flask import Flask, request, make_response, jsonify
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

app = Flask(__name__)

# Slack Token desde variables de entorno
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")
slack_client = WebClient(token=SLACK_BOT_TOKEN)

@app.route("/", methods=["GET"])
def home():
    return "Slack bot is running!"

@app.route("/slack/events", methods=["POST"])
def slack_events():
    data = request.get_json()
    print("🔔 Evento recibido:", data)

    # Validación inicial del challenge (cuando se registra el endpoint)
    if "challenge" in data:
        return jsonify({"challenge": data["challenge"]})

    # Procesa eventos reales
    if data.get("type") == "event_callback":
        event = data.get("event", {})
        if event.get("type") == "app_mention":
            text = event.get("text", "")
            user = event.get("user")
            channel = event.get("channel")
            print(f"📢 Mención detectada de {user} en canal {channel}: {text}")

            try:
                slack_client.chat_postMessage(
                    channel=channel,
                    text="¡Hola! ¿Cómo puedo ayudarte?"
                )
            except SlackApiError as e:
                print(f"❌ Error al enviar mensaje: {e.response['error']}")

    return make_response("OK", 200)

if __name__ == "__main__":
    app.run(port=10000)
