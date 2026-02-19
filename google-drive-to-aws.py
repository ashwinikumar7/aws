import base64
import csv
import hashlib
import hmac
import io
import json
import os
import re
import time
from datetime import datetime
from typing import Dict, Iterator, List, Tuple
from urllib.parse import quote

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError
from boto3.s3.transfer import TransferConfig

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload

# Environment variables or default settings
S3_BUCKET = os.environ.get("S3_BUCKET", "bs-sar-portal")
ROOT_FOLDER_NAME = os.environ.get("GDRIVE_ROOT", "SAR Notes")
HMAC_SECRET_ARN = os.environ.get("HMAC_SECRET_ARN")
HMAC_FALLBACK_SECRET = os.environ.get("HMAC_FALLBACK_SECRET", "CHANGE_THIS_SECRET")
GDRIVE_SA_JSON_SECRET_ARN = os.environ.get("GDRIVE_SA_JSON_SECRET_ARN")
S3_SSE = os.environ.get("S3_SSE", "").strip()
S3_SSE_KMS_KEY_ID = os.environ.get("S3_SSE_KMS_KEY_ID", "").strip()
S3_URL_SPACE_PLUS = os.environ.get("S3_URL_SPACE_PLUS", "").lower() in ("1", "true", "yes")
CYCLE_CSV_PATH = os.environ.get("CYCLE_CSV_PATH", "cycle_rows.csv")

# Multipart upload
MB = 1024 * 1024
TRANSFER_CONFIG = TransferConfig(
    multipart_threshold=8 * MB,
    multipart_chunksize=8 * MB,
    max_concurrency=4,
    use_threads=True,
)

S3 = boto3.client("s3", config=BotoConfig(retries={"max_attempts": 5, "mode": "standard"}))
SECRETS = boto3.client("secretsmanager")

# Naming convention
# SAR_YYYY_Mon_EmployeeID_Name.pdf
NAME_RE = re.compile(r"^SAR_(\d{4})_([A-Za-z]{3})_([A-Za-z0-9]+)_(.+)\.pdf$", re.IGNORECASE)
VALID_MON = {"JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC"}

# -------- Cycle → ID mapping helpers --------
def _norm_cycle_str(raw: str) -> str:
    """
    Normalize a cycle string to canonical 'SAR-Mon-YYYY'.
    - Accepts 'SAP-' or 'SAR-' prefixes (treat 'SAP' as 'SAR').
    - Case-insensitive for everything.
    - Month normalized to Title case (Apr, May, etc.).
    """
    s = (raw or "").strip()
    if not s:
        return ""
    # unify prefix
    if s[:4].upper() == "SAP-":
        s = "SAR-" + s[4:]
    # split into parts; expect 'SAR-Mon-YYYY'
    parts = s.split("-")
    if len(parts) != 3:
        return s  # leave as-is if unexpected
    pref, mon, yyyy = parts[0], parts[1], parts[2]
    return f"SAR-{mon.title()}-{yyyy}"

def load_cycle_map(path: str = CYCLE_CSV_PATH) -> Dict[str, str]:
    """
    Load cycle_rows.csv with at least columns: 'cycle', 'id'.
    Returns dict: 'SAR-Mon-YYYY' -> id
    """
    m: Dict[str, str] = {}
    try:
        # Try as relative to /var/task (Lambda package root)
        pkg_path = os.path.join(os.getcwd(), path)
        candidates = [path, pkg_path]
        for p in candidates:
            if os.path.exists(p):
                with open(p, "r", newline="", encoding="utf-8") as fp:
                    reader = csv.DictReader(fp)
                    for row in reader:
                        cyc = _norm_cycle_str(row.get("cycle", ""))
                        cid = (row.get("id") or "").strip()
                        if cyc and cid:
                            m[cyc] = cid
                break
    except Exception:
        # On any issue, return what we have (possibly empty), keeping the job running
        pass
    return m

# Fetch from AWS Secrets Manager
def load_secret(arn: str, fallback: str = "") -> str:
    if not arn:
        return fallback
    resp = SECRETS.get_secret_value(SecretId=arn)
    if "SecretString" in resp:
        return resp["SecretString"]
    return resp["SecretBinary"].decode("utf-8")

def get_hmac_key() -> bytes:
    """
    Load HMAC key from Secrets Manager.
    Supports JSON {"hmac_key": "<base64>", "algorithm": "HMAC-SHA256"} or raw/base64/hex strings.
    """
    raw = load_secret(HMAC_SECRET_ARN, HMAC_FALLBACK_SECRET).strip()

    # If JSON, pull out the field
    try:
        obj = json.loads(raw)
        raw = obj.get("hmac_key") or raw
    except json.JSONDecodeError:
        pass

    # Prefer base64; else try hex; else treat as UTF-8 bytes
    for decoder in (
        lambda s: base64.b64decode(s, validate=True),
        lambda s: bytes.fromhex(s),
        lambda s: s.encode("utf-8"),
    ):
        try:
            return decoder(raw)
        except Exception:
            continue
    raise RuntimeError("Unable to decode HMAC key from secret")

# Google Drive settings
def get_service_account_creds():
    sa_json = load_secret(GDRIVE_SA_JSON_SECRET_ARN, "")
    if not sa_json:
        raise RuntimeError("Missing Google service account JSON in Secrets Manager.")
    info = json.loads(sa_json)
    scopes = ["https://www.googleapis.com/auth/drive.readonly"]
    creds = service_account.Credentials.from_service_account_info(info, scopes=scopes)
    # NOTE: For your case you shared the folder from your personal Google Drive
    # directly to the *service account email*. That is sufficient; no delegation needed.
    return creds

def build_drive_client():
    creds = get_service_account_creds()
    return build("drive", "v3", credentials=creds, cache_discovery=False)

def find_folder_id(drive, name: str) -> str:
    """
    Finds folder by name across My Drive + Shared Drives + items shared to the service account.
    Ensure you've shared the target folder to the service account email.
    """
    q = f"mimeType='application/vnd.google-apps.folder' and name='{name}' and trashed=false"
    resp = drive.files().list(
        q=q,
        fields="files(id, name)",
        includeItemsFromAllDrives=True,
        supportsAllDrives=True,
        corpora="allDrives",
    ).execute()
    files = resp.get("files", [])
    if not files:
        raise RuntimeError(f'Folder "{name}" not found (My Drive or Shared Drives). Have you shared it with the service account?')
    # If multiple folders with same name, pick the first. You can disambiguate by ID via env if needed.
    return files[0]["id"]

# def list_all_files_under(drive, folder_id: str) -> Iterator[Dict]:
#     """
#     BFS traversal listing *all* files (not folders) beneath folder_id.
#     Ignores the Drive folder structure for output—only filename is used to build S3 key.
#     """
#     queue = [folder_id]
#     while queue:
#         pid = queue.pop(0)
#         # list subfolders
#         qf = f"mimeType='application/vnd.google-apps.folder' and '{pid}' in parents and trashed=false"
#         rf = drive.files().list(
#             q=qf,
#             fields="files(id, name)",
#             includeItemsFromAllDrives=True,
#             supportsAllDrives=True,
#         ).execute()
#         for f in rf.get("files", []):
#             queue.append(f["id"])

#         # list files under this folder
#         q = f"mimeType!='application/vnd.google-apps.folder' and '{pid}' in parents and trashed=false"
#         page_token = None
#         while True:
#             resp = drive.files().list(
#                 q=q,
#                 fields="nextPageToken, files(id, name, webViewLink)",
#                 pageToken=page_token,
#                 includeItemsFromAllDrives=True,
#                 supportsAllDrives=True,
#             ).execute()
#             for f in resp.get("files", []):
#                 yield f
#             page_token = resp.get("nextPageToken")
#             if not page_token:
#                 break

def list_files_in_folder(drive, folder_id: str) -> Iterator[Dict]:
    """
    List only the *direct* file children of the given folder_id (no recursion).
    """
    q = f"mimeType!='application/vnd.google-apps.folder' and '{folder_id}' in parents and trashed=false"
    page_token = None
    while True:
        resp = drive.files().list(
            q=q,
            fields="nextPageToken, files(id, name, webViewLink)",
            pageToken=page_token,
            includeItemsFromAllDrives=True,
            supportsAllDrives=True,
        ).execute()
        for f in resp.get("files", []):
            yield f
        page_token = resp.get("nextPageToken")
        if not page_token:
            break

def download_drive_file(drive, file_id: str, out_path: str):
    req = drive.files().get_media(fileId=file_id)
    fh = io.FileIO(out_path, "wb")
    downloader = MediaIoBaseDownload(fh, req, chunksize=8 * MB)
    done = False
    while not done:
        _, done = downloader.next_chunk()  # could log status.progress() if desired

# ---------- Parsing / hashing ----------
def parse_filename(name: str) -> Tuple[str, str, str, str]:
    m = NAME_RE.match(name)
    if not m:
        raise ValueError("Filename does not match SAR pattern")
    yyyy, mon, emp, empname = m.groups()
    mon_up = mon.upper()
    if mon_up not in VALID_MON:
        raise ValueError("Invalid month abbreviation")
    mon_norm = mon_up.title()  # "APR" -> "Apr"
    return yyyy, mon_norm, emp, empname

def hash32(hmac_key: bytes, file_id: str, employee_id: str, name: str) -> str:
    msg = f"{file_id}|{employee_id}|{name}".encode("utf-8")
    return hmac.new(hmac_key, msg, hashlib.sha256).hexdigest()[:32]

# ---------- S3 ----------
def s3_key_for(yyyy: str, mon: str, employee_id: str, name: str, hash32_str: str) -> str:
    # SAR/YYYY/Mon/EmployeeID/Name<hash32>.pdf Now, converted to hash32
    return f"SAR/{yyyy}/{mon}/{employee_id}/{name}{hash32_str}.pdf"

# This one has bug
# def s3_https_url(bucket: str, key: str) -> str:
#     return f"https://{bucket}.s3.amazonaws.com/{key}"

def s3_https_url(bucket: str, key: str, region: str | None = None) -> str:
    """
    Regional, URL-encoded virtual-hosted–style S3 URL.
    Encodes path safely; optional '+' for spaces if S3_URL_SPACE_PLUS=true.
    """
    if not region:
        # Try client region, then env, fallback to us-east-1
        region = S3.meta.region_name or os.environ.get("AWS_REGION") or "us-east-1"
    encoded_key = quote(key, safe="/")  # % encoding for path
    if S3_URL_SPACE_PLUS:
        encoded_key = encoded_key.replace("%20", "+")
    return f"https://{bucket}.s3.{region}.amazonaws.com/{encoded_key}"

def _s3_extra_args():
    """Optional SSE settings."""
    if S3_SSE == "AES256":
        return {"ServerSideEncryption": "AES256"}
    if S3_SSE == "aws:kms":
        extra = {"ServerSideEncryption": "aws:kms"}
        if S3_SSE_KMS_KEY_ID:
            extra["SSEKMSKeyId"] = S3_SSE_KMS_KEY_ID
        return extra
    return None

def upload_to_s3(local_path: str, key: str) -> None:
    extra = _s3_extra_args()
    kwargs = dict(Config=TRANSFER_CONFIG)
    if extra:
        kwargs["ExtraArgs"] = extra
    S3.upload_file(local_path, S3_BUCKET, key, **kwargs)

def s3_exists(bucket: str, key: str) -> bool:
    try:
        S3.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        status = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        if code in ("404", "NotFound", "NoSuchKey") or status == 404:
            return False
        # If it's AccessDenied or something else, surface it
        raise

# ---------- Main ----------
def handler_main(event, context):
    start = time.time()

    # Secrets and clients
    hkey = get_hmac_key()
    drive = build_drive_client()
    cycle_map = load_cycle_map()

    # Find the root folder (must be shared with the service account email)
    root_id = find_folder_id(drive, ROOT_FOLDER_NAME)

    # csv_rows: List[Tuple[str, str, str]] = []
    # file_name, google_drive_link, s3_object_url, id, employeeid
    csv_rows: List[Tuple[str, str, str, str, str]] = []
    processed = skipped = 0

    # CSV file name
    stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    csv_local = f"/tmp/sar_mapping_{stamp}.csv"
    csv_s3_key = f"SAR/csv/sar_mapping_{stamp}.csv"

    # for f in list_all_files_under(drive, root_id):
    for f in list_files_in_folder(drive, root_id):
        name = f["name"]
        file_id = f["id"]
        web_link = f.get("webViewLink") or f"https://drive.google.com/file/d/{file_id}/view"

        try:
            yyyy, mon, emp, empname = parse_filename(name)
        except Exception:
            skipped += 1
            continue

        # Build the SAR cycle key (canonical form) and find id from cycle map
        cycle_key = f"SAR-{mon}-{yyyy}"
        cycle_id = cycle_map.get(cycle_key, "")

        # Build destination key
        h32 = hash32(hkey, file_id, emp, empname)
        s3_key = s3_key_for(yyyy, mon, emp, empname, h32)

        # Idempotency: if object exists, skip downloading/uploading
        if s3_exists(S3_BUCKET, s3_key):
            s3_url = s3_https_url(S3_BUCKET, s3_key)
            # csv_rows.append((name, web_link, s3_url))
            # csv_rows.append((name, web_link, s3_url, cycle_id))
            csv_rows.append((name, web_link, s3_url, cycle_id, emp))
            processed += 1
            continue

        # Download to /tmp then upload
        local_pdf = f"/tmp/{file_id}.pdf"
        download_drive_file(drive, file_id, local_pdf)
        upload_to_s3(local_pdf, s3_key)

        # CSV row: file name, google link, HTTPS S3 URL
        s3_url = s3_https_url(S3_BUCKET, s3_key)
        # csv_rows.append((name, web_link, s3_url))
        # csv_rows.append((name, web_link, s3_url, cycle_id))
        csv_rows.append((name, web_link, s3_url, cycle_id, emp))
        processed += 1

        # Clean up
        try:
            os.remove(local_pdf)
        except OSError:
            pass

    # Write CSV
    with open(csv_local, "w", newline="", encoding="utf-8") as fp:
        writer = csv.writer(fp)
        # writer.writerow(["file_name", "google_drive_link", "s3_object_url"])
        # writer.writerow(["file_name", "google_drive_link", "s3_object_url", "id"])
        writer.writerow(["file_name", "google_drive_link", "s3_object_url", "id", "employeeid"])
        writer.writerows(csv_rows)

    # Upload CSV
    upload_to_s3(csv_local, csv_s3_key)
    try:
        os.remove(csv_local)
    except OSError:
        pass

    elapsed = round(time.time() - start, 2)
    return {
        "processed": processed,
        "skipped": skipped,
        "csv_s3_key": csv_s3_key,
        "csv_https_url": s3_https_url(S3_BUCKET, csv_s3_key),
        "elapsed_sec": elapsed,
    }

def lambda_handler(event, context):
    return handler_main(event, context)
