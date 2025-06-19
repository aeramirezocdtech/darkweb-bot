import os
import re
import requests
from flask import Flask, request, make_response, jsonify, send_file
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from dotenv import load_dotenv
from darkweb_report import generate_dwid_reports  # Import the DWID report function

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

            if "darkweb" in text.lower():
                modo = extract_mode(text)
                if modo in ["monthly", "weekly", "weekly friday"]:
                    try:
                        file_paths = generate_dwid_reports(modo)
                        for path in file_paths:
                            slack_client.files_upload(
                                channels=channel,
                                file=path,
                                title=os.path.basename(path),
                                initial_comment=f"🕵️ Report: {os.path.basename(path)}"
                            )
                    except Exception as e:
                        slack_client.chat_postMessage(
                            channel=channel,
                            text=f"❌ Error generating report: {str(e)}"
                        )
                else:
                    slack_client.chat_postMessage(
                        channel=channel,
                        text="❗ Please specify a valid mode: `darkweb monthly`, `darkweb weekly`, or `darkweb weekly friday`"
                    )
            else:
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

def extract_mode(text):
    """Extracts the report mode (monthly, weekly, etc.) from a Slack message."""
    match = re.search(r"darkweb\s+(monthly|weekly|weekly friday)", text, re.IGNORECASE)
    return match.group(1).lower() if match else None

def extraer_dominio(texto):
    """Extract the domain from a Slack message like '@bot scan domain.com'"""
    texto = re.sub(r"<@[\w]+>", "", texto)
    texto = re.sub(r"<http[s]?://[^|]+\|([^>]+)>", r"\1", texto)
    texto = texto.replace("http://", "").replace("https://", "")
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
