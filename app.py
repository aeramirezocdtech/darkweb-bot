import os
from flask import Flask
from slackeventsapi import SlackEventAdapter
from slack import WebClient
from dotenv import load_dotenv
from pathlib import Path

# Cargar variables de entorno
env_path = Path('.') / '.env'
load_dotenv(dotenv_path=env_path)

app = Flask(__name__)

# Adaptador de eventos de Slack
slack_event_adapter = SlackEventAdapter(
    os.environ['SIGNING_SECRET'], "/slack/events", app
)

# Cliente de Slack
client = WebClient(token=os.environ['SLACK_TOKEN'])

# Evento: cuando alguien envía un mensaje
@slack_event_adapter.on("message")
def handle_message(event_data):
    message = event_data["event"]

    if message.get("subtype") is None:
        user = message["user"]
        text = message["text"]
        channel = message["channel"]

        if "scan" in text.lower():
            client.chat_postMessage(
                channel=channel,
                text=f"<@{user}> recibido. Estoy preparando el reporte de DarkWeb..."
            )

@app.route("/", methods=["GET"])
def index():
    return "Bot activo.", 200

if __name__ == "__main__":
    app.run(debug=True)
