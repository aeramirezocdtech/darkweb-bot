import os
import re
import requests
from flask import Flask, request, make_response, jsonify
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from dotenv import load_dotenv

load_dotenv()  # Cargar variables desde .env (útil en local)

app = Flask(__name__)

# Tokens desde variables de entorno
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")
VT_API_KEY = os.environ.get("VT_API_KEY")

slack_client = WebClient(token=SLACK_BOT_TOKEN)

@app.route("/", methods=["GET"])
def home():
    return "Slack bot is running!"

@app.route("/slack/events", methods=["POST"])
def slack_events():
    data = request.get_json()
    print("🔔 Evento recibido:", data)

    # Validación inicial (challenge de Slack)
    if "challenge" in data:
        return jsonify({"challenge": data["challenge"]})

    if data.get("type") == "event_callback":
        event = data.get("event", {})
        if event.get("type") == "app_mention":
            text = event.get("text", "")
            user = event.get("user")
            channel = event.get("channel")
            print(f"📢 Mención detectada de {user} en canal {channel}: {text}")

            dominio = extraer_dominio(text)
            if dominio:
                resultado = consultar_virustotal(dominio)
                mensaje = formatear_respuesta(resultado)
            else:
                mensaje = "Por favor, indícame qué dominio deseas escanear. Ejemplo: `scan dominio.com`"

            try:
                slack_client.chat_postMessage(
                    channel=channel,
                    text=mensaje
                )
            except SlackApiError as e:
                print(f"❌ Error al enviar mensaje: {e.response['error']}")

    return make_response("OK", 200)

def extraer_dominio(texto):
    """Extrae el dominio desde el texto tipo: 'scan dominio.com'"""
    match = re.search(r'\bscan\s+([^\s]+)', texto, re.IGNORECASE)
    return match.group(1) if match else None

def consultar_virustotal(dominio):
    """Consulta la API de VirusTotal con el dominio recibido"""
    url = f"https://www.virustotal.com/api/v3/domains/{dominio}"
    headers = {
    "x-apikey": os.getenv("VT_API_KEY").strip()
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"Error {response.status_code} - {response.text}"}

def formatear_respuesta(data):
    """Formatea los resultados en un mensaje para Slack"""
    if "error" in data:
        return data["error"]

    atributos = data.get("data", {}).get("attributes", {})
    stats = atributos.get("last_analysis_stats", {})
    reputacion = atributos.get("reputation", "N/A")
    whois = atributos.get("whois_date", None)

    mensaje = (
        f"*🔍 Resultados de VirusTotal:*\n"
        f"🌐 Dominio: `{data.get('data', {}).get('id', 'desconocido')}`\n"
        f"🧠 Reputación: `{reputacion}`\n"
        f"✅ Harmless: {stats.get('harmless', 0)}\n"
        f"⚠️ Suspicious: {stats.get('suspicious', 0)}\n"
        f"❌ Malicious: {stats.get('malicious', 0)}\n"
        f"🧪 Undetected: {stats.get('undetected', 0)}\n"
    )

    return mensaje

if __name__ == "__main__":
    app.run(port=10000)
