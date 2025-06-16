import os
import re
from flask import Flask, request
from slack_sdk import WebClient
from slackeventsapi import SlackEventAdapter

# App Flask
app = Flask(__name__)

# Slack Event Adapter para manejar eventos desde Slack
slack_events_adapter = SlackEventAdapter(
    os.environ["SLACK_SIGNING_SECRET"], "/slack/events", app
)

# Cliente de Slack
client = WebClient(token=os.environ["SLACK_BOT_TOKEN"])

# Evento: mensaje recibido
@slack_events_adapter.on("message")
def handle_message(event_data):
    message = event_data["event"]
    text = message.get("text", "")
    channel = message.get("channel")
    user = message.get("user")

    if user is None or "bot_id" in message:
        return  # Ignora mensajes de bots o sin usuario

    # Verifica si contiene 'scan' y extrae correo
    if "scan" in text.lower():
        match = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", text)
        if match:
            email = match.group(0)
            client.chat_postMessage(
                channel=channel,
                text=f"<@{user}> recibido. Estoy preparando el reporte de DarkWeb para: `{email}`"
            )
        else:
            client.chat_postMessage(
                channel=channel,
                text=f"<@{user}> no encontré un correo válido en tu mensaje. Usa el formato `scan correo@dominio.com`."
            )

    elif "hola" in text.lower():
        client.chat_postMessage(
            channel=channel,
            text=f"👋 ¡Hola <@{user}>! Escribe `scan correo@dominio.com` para iniciar un escaneo."
        )

# Ruta raíz opcional para verificar despliegue
@app.route("/", methods=["GET"])
def home():
    return "Bot activo", 200
