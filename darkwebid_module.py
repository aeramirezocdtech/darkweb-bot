import requests
import pandas as pd
from requests.auth import HTTPBasicAuth
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timedelta
import os
import calendar

# Credentials from environment variables
USERNAME = os.environ.get("DWID_USERNAME")
PASSWORD = os.environ.get("DWID_PASSWORD")
base_url = os.environ.get("DWID_BASE_URL", "https://secure.darkwebid.com/services/compromise.json")

# Output folder (temporary)
EXPORT_FOLDER = "/tmp/darkweb_reports"
os.makedirs(EXPORT_FOLDER, exist_ok=True)

def generate_darkweb_reports(mode="monthly"):
    """Generates XLSX reports by organization from DarkWebID API."""

    if mode not in ["monthly", "weekly", "weekly friday"]:
        raise ValueError("Invalid mode. Choose: monthly, weekly or weekly friday")

    today = datetime.now()

    if mode == "monthly":
        first_day_this_month = today.replace(day=1)
        last_day_prev_month = first_day_this_month - timedelta(days=1)
        start_date = last_day_prev_month.replace(day=1)
        end_date = last_day_prev_month.replace(day=calendar.monthrange(last_day_prev_month.year, last_day_prev_month.month)[1])
        period_name = start_date.strftime("%B").lower() + str(start_date.year)

    elif mode == "weekly":
        start_week = today - timedelta(days=today.weekday())
        end_date = start_week - timedelta(days=1)
        start_date = end_date - timedelta(days=6)
        period_name = f"week_{start_date.strftime('%Y%m%d')}_{end_date.strftime('%Y%m%d')}"

    elif mode == "weekly friday":
        last_friday = today - timedelta(days=(today.weekday() + 3) % 7 + 1)
        end_date = last_friday
        start_date = end_date - timedelta(days=6)
        period_name = f"fridayweek_{start_date.strftime('%Y%m%d')}_{end_date.strftime('%Y%m%d')}"

    # Fetch latest page count
    resp = requests.get(BASE_URL, auth=HTTPBasicAuth(USERNAME, PASSWORD))
    resp.raise_for_status()
    data = resp.json()
    last_url = data.get("last", "")
    last_page = int(parse_qs(urlparse(last_url).query)['page'][0])

    all_records = []
    for page in range(1, last_page + 1):
        paged_url = f"{BASE_URL}?page={page}"
        resp = requests.get(paged_url, auth=HTTPBasicAuth(USERNAME, PASSWORD))
        resp.raise_for_status()
        page_data = resp.json()

        for item in page_data.get("list", []):
            flat = item.copy()
            pii = flat.pop("pii_hit", {})
            if isinstance(pii, dict):
                for key, value in pii.items():
                    flat[f"pii_hit.{key}"] = value
            elif isinstance(pii, list) and pii:
                for i, sub_pii in enumerate(pii):
                    for key, value in sub_pii.items():
                        flat[f"pii_hit{i+1}.{key}"] = value
            all_records.append(flat)

    df = pd.DataFrame(all_records)
    df['detected'] = pd.to_datetime(df['detected'], unit='s', errors='coerce')
    df = df[(df['detected'] >= start_date) & (df['detected'] <= end_date)]
    df['attribution_list'] = df['attribution'].apply(lambda x: x if isinstance(x, list) else [])
    df['attribution_str'] = df['attribution_list'].apply(lambda x: "; ".join(map(str, x)))
    df.drop(columns=['attribution'], inplace=True, errors='ignore')

    # Organize columns
    column_order = [
        'uuid', 'organization', 'password', 'record_type', 'source', 'origin',
        'record_status', 'compromise', 'password_criteria', 'search_value', 'search_record',
        'detected', 'password_status_name', 'description', 'source_locations',
        'activity_title', 'known_attackers', 'hash_type', 'target_industries',
        'reliability_score', 'occurred', 'api', 'record_number',
        'pii_hit.namefirst', 'pii_hit.namelast', 'pii_hit.addr1',
        'pii_hit.addrcity', 'pii_hit.addrzip', 'attribution_str', 'synopsis_id'
    ]
    for col in column_order:
        if col not in df.columns:
            df[col] = None
    df = df[column_order]

    # Group by organization
    org_groups = df.groupby('organization')
    files = []

    for org_id, group in org_groups:
        emails = group['search_value'].dropna().astype(str)
        domains = emails.str.extract(r'@([\w\.-]+)')[0].dropna().str.lower().unique()
        base_name = domains[0].split('.')[0] if len(domains) > 0 else f"org_{org_id[:6]}"
        if 'arbella' in base_name or 'bearingstar' in base_name:
            base_name = 'arbella'

        filename = f"{base_name}_{period_name}.xlsx"
        filepath = os.path.join(EXPORT_FOLDER, filename)
        group.to_excel(filepath, index=False)
        files.append(filepath)

    return files
