import os
import re
import requests
from flask import Flask, request, make_response, jsonify
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env (useful locally)

app = Flask(__name__)

# Tokens from environment variables
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")
VT_API_KEY = os.environ.get("VT_API_KEY")

slack_client = WebClient(token=SLACK_BOT_TOKEN)

@app.route("/", methods=["GET"])
def home():
    return "Slack bot is running!"

@app.route("/slack/events", methods=["POST"])
def slack_events():
    data = request.get_json()
    print("🔔 Event received:", data)

    # Initial validation (Slack challenge)
    if "challenge" in data:
        return jsonify({"challenge": data["challenge"]})

    if data.get("type") == "event_callback":
        event = data.get("event", {})
        if event.get("type") == "app_mention":
            text = event.get("text", "")
            user = event.get("user")
            channel = event.get("channel")
            print(f"📢 Mention detected from {user} in channel {channel}: {text}")

            dominio = extraer_dominio(text)
            if dominio:
                resultado = consultar_virustotal(dominio)
                mensaje = formatear_respuesta(resultado)
            else:
                mensaje = "Please tell me which domain you want to scan. Example: `scan domain.com`"

            try:
                slack_client.chat_postMessage(
                    channel=channel,
                    text=mensaje
                )
            except SlackApiError as e:
                print(f"❌ Error sending message: {e.response['error']}")

    return make_response("OK", 200)

def extraer_dominio(texto):
    """Extract the domain from a Slack message like '@bot scan domain.com'"""
    # Remove mentions like <@UXXXX>
    texto = re.sub(r"<@[\w]+>", "", texto)

    # Remove Slack-formatted links: <http://...|...> → domain.com
    texto = re.sub(r"<http[s]?://[^|]+\|([^>]+)>", r"\1", texto)

    # Remove http(s):// if received in plain text
    texto = texto.replace("http://", "").replace("https://", "")

    # Extract the word after 'scan'
    match = re.search(r'\bscan\s+([^\s]+)', texto, re.IGNORECASE)
    return match.group(1).strip() if match else None

def consultar_virustotal(dominio):
    """Query the VirusTotal API with the provided domain"""
    url = f"https://www.virustotal.com/api/v3/domains/{dominio}"
    headers = {
        "x-apikey": VT_API_KEY
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"Error {response.status_code} - {response.text}"}

def formatear_respuesta(data):
    """Format the VirusTotal results into a message for Slack"""
    if "error" in data:
        return data["error"]

    atributos = data.get("data", {}).get("attributes", {})
    stats = atributos.get("last_analysis_stats", {})
    reputacion = atributos.get("reputation", "N/A")
    whois = atributos.get("whois_date", None)

    mensaje = (
        f"*🔍 VirusTotal Scan Results:*\n"
        f"1 Domain: `{data.get('data', {}).get('id', 'unknown')}`\n"
        f"2 Reputation: `{reputacion}`\n"
        f"3 Harmless: {stats.get('harmless', 0)}\n"
        f"4 Suspicious: {stats.get('suspicious', 0)}\n"
        f"5 Malicious: {stats.get('malicious', 0)}\n"
        f"6 Undetected: {stats.get('undetected', 0)}"
    )

    return mensaje

if __name__ == "__main__":
    app.run(port=10000)
