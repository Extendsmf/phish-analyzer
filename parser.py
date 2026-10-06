import email
from email import policy
import re
import hashlib
import os
import base64
import requests
from dotenv import load_dotenv
import pathlib

load_dotenv()
virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")



def check_virustotal_hash(hash_sum, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{hash_sum}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            return response.json().get('data', {})
    except requests.RequestException:
        pass

    return {}


def check_virustotal_url(addr, api_key):
    url_encoded = base64.urlsafe_b64encode(addr.encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_encoded}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            return response.json().get('data', {})
    except requests.RequestException:
        pass

    return {}


def analyze_email(filepath):

    rec_spf_score = 0
    extention_score = 0
    vendor_vt_score = 0

    report_lines = ["--- ОТЧЕТ АНАЛИЗА ПИСЬМА ---"]

    with open(filepath, 'rb') as file:
        msg = email.message_from_binary_file(file, policy=policy.default)

    body_part = msg.get_body(preferencelist=('plain', 'html'))
    body = body_part.get_content() if body_part else ""

    report_lines.append(f"Subject: {msg['Subject']}")
    report_lines.append(f"From: {msg['From']}")
    report_lines.append(f"Received-SPF: {msg['Received-SPF']}")

    spf_header = str(msg.get('Received-SPF', '')).lower()
    if "fail" in spf_header:
        rec_spf_score = 40

    dangerous_ext = [".exe" , ".scr", ".bat", ".vbs", ".iso"]
    # Анализ вложений
    for attachment in msg.iter_attachments():
        name = attachment.get_filename()
        data = attachment.get_content()

        filename_ext = pathlib.Path(name).suffix

        if filename_ext in dangerous_ext:
            extention_score = 40

        file_hash = hashlib.sha256(data).hexdigest()

        report_lines.append(f"\nНазвание прикрепленного файла: {name}")
        report_lines.append(f"Содержание прикрепленного файла (SHA-256): {file_hash}")

        hash_data_vt = check_virustotal_hash(file_hash, virustotal_api_key)
        hash_attributes = hash_data_vt.get('attributes', {})
        hash_stats = hash_attributes.get('last_analysis_stats', {})
        hash_malicious = hash_stats.get("malicious", 0)

        if hash_malicious > 0:
            vendor_vt_score = 50

        report_lines.append(f"сколько вендоров считают файл вредоносным: {hash_malicious}")

    # Анализ ссылок
    links = re.findall(r'https?://[^\s<>"]+', body)
    if links:
        report_lines.append("\nНайденные ссылки:")
        for link in links:
            report_lines.append(link)
            url_data_vt = check_virustotal_url(link, virustotal_api_key)

            attributes = url_data_vt.get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            malicious = stats.get("malicious", 0)
            
            if malicious > 0:
                vendor_vt_score = 50

            report_lines.append(f"сколько вендоров считают ссылку вредоносной: {malicious}")

    total_score = vendor_vt_score + rec_spf_score + extention_score

    if total_score < 50: 
        report_lines.append("🟢ВЕРДИКТ: ЯВНЫХ УГРОЗ НЕ ОБНАРУЖЕНО")
    else:
        report_lines.append("🔴 ВЕРДИКТ: ВЫСОКАЯ ВЕРОЯТНОСТЬ ФИШИНГА!")


    report = "\n".join(report_lines)
    return report