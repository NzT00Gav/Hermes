import argparse
import sys
import time
import re
import json
import base64
import mimetypes
import random
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List
import requests

VERSION = "0.1.0"

BANNER = rf"""
     █████   █████
    ░░███   ░░███
     ░███    ░███   ██████  ████████  █████████████    ██████   █████
     ░███████████  ███░░███░░███░░███░░███░░███░░███  ███░░███ ███░░
     ░███░░░░░███ ░███████  ░███ ░░░  ░███ ░███ ░███ ░███████ ░░█████
     ░███    ░███ ░███░░░   ░███      ░███ ░███ ░███ ░███░░░   ░░░░███
     █████   █████░░██████  █████     █████░███ █████░░██████  ██████
    ░░░░░   ░░░░░  ░░░░░░  ░░░░░     ░░░░░ ░░░ ░░░░░  ░░░░░░  ░░░░░░

                       Email sender via Graph API v{VERSION}

Inspired in part by the GraphRunner project
https://github.com/dafthack/GraphRunner
"""

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

MIME_OVERRIDES = {
    ".doc":  "application/msword",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xls":  "application/vnd.ms-excel",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".ppt":  "application/vnd.ms-powerpoint",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".zip":  "application/zip",
    ".rar":  "application/x-rar-compressed",
}
DEFAULT_MIME = "application/octet-stream"
DEFAULT_SLEEP_SECONDS = 300
TOKEN_CACHE_FILE = ".hermes_tokens.json"
CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
GRAPH_RESOURCE = "https://graph.microsoft.com"
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/token?api-version=1.0"
DEVICECODE_URL = "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0"
TOKEN_EXPIRY_MARGIN = 60

@dataclass
class DeviceCodeAuthResult:
    tokens: Dict[str, Any]
    jwt_payload: Dict[str, Any]
    tenant_id: Optional[str]
    expires_at_local: Optional[datetime]

def _b64url_decode(data: str) -> bytes:
    data = data.replace("-", "+").replace("_", "/")
    data += "=" * (-len(data) % 4)
    return base64.b64decode(data)

def _get_request_headers() -> Dict[str, str]:
    return {"User-Agent": "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Edge/79.0.1451.30 Safari/537.36"}

def _decode_jwt(access_token: str) -> tuple[Dict[str, Any], Optional[str], Optional[datetime]]:
    parts = access_token.split(".")
    jwt_payload: Dict[str, Any] = {}
    tenant_id = None
    expires_at_local = None

    if len(parts) >= 2 and parts[1]:
        payload_bytes = _b64url_decode(parts[1])
        jwt_payload = json.loads(payload_bytes.decode("utf-8", errors="replace"))
        tenant_id = jwt_payload.get("tid")

        exp = jwt_payload.get("exp")
        if isinstance(exp, (int, float)):
            expires_at_local = datetime.fromtimestamp(exp, tz=timezone.utc).astimezone()

    return jwt_payload, tenant_id, expires_at_local

def _is_token_valid(tokens: Dict[str, Any]) -> bool:
    access_token = tokens.get("access_token", "")
    if not access_token:
        return False

    _, _, expires_at = _decode_jwt(access_token)
    if not expires_at:
        return False

    now = datetime.now(timezone.utc).astimezone()
    return (expires_at - now).total_seconds() > TOKEN_EXPIRY_MARGIN

def _save_tokens_to_cache(tokens: Dict[str, Any]) -> None:
    cache_path = Path(TOKEN_CACHE_FILE)
    try:
        cache_path.write_text(json.dumps(tokens, indent=2), encoding="utf-8")
        print(f"[+] Tokens saved to {TOKEN_CACHE_FILE}")
    except OSError as e:
        print(f"[!] Warning: Could not save tokens to cache: {e}")

def _load_tokens_from_cache() -> Optional[Dict[str, Any]]:
    cache_path = Path(TOKEN_CACHE_FILE)
    if not cache_path.is_file():
        return None

    try:
        content = cache_path.read_text(encoding="utf-8")
        return json.loads(content)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[!] Warning: Could not read tokens from cache: {e}")
        return None

def _refresh_access_token(refresh_token: str) -> Optional[Dict[str, Any]]:
    print("[*] Attempting to refresh access token using refresh token...")

    try:
        r = requests.post(
            TOKEN_URL,
            headers=_get_request_headers(),
            data={
                "client_id": CLIENT_ID,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "resource": GRAPH_RESOURCE,
            },
            timeout=30,
        )

        if r.ok:
            tokens = r.json()
            print("[+] Access token refreshed successfully!")
            return tokens
        else:
            print(f"[!] Failed to refresh token: {r.status_code}")
            return None

    except Exception as e:
        print(f"[!] Error refreshing token: {e}")
        return None

def _device_code_auth() -> Dict[str, Any]:
    print("[*] Starting Device Code authentication...")

    r = requests.post(
        DEVICECODE_URL,
        headers=_get_request_headers(),
        data={"client_id": CLIENT_ID, "resource": GRAPH_RESOURCE},
        timeout=30,
    )

    r.raise_for_status()
    auth = r.json()

    print(auth.get("message") or auth.get("Message") or json.dumps(auth, indent=2))

    device_code = auth["device_code"]
    interval = int(auth.get("interval", 5))

    while True:
        tr = requests.post(
            TOKEN_URL,
            headers=_get_request_headers(),
            data={
                "client_id": CLIENT_ID,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "code": device_code,
                "resource": GRAPH_RESOURCE,
            },
            timeout=30,
        )

        if tr.ok:
            return tr.json()

        try:
            err = tr.json()
        except Exception:
            tr.raise_for_status()
            raise

        error = err.get("error")
        print(error)

        if error == "authorization_pending":
            time.sleep(interval)
            continue
        if error == "slow_down":
            interval += 5
            time.sleep(interval)
            continue

        raise RuntimeError(f"Token request failed: {err}")

def get_graph_tokens(verbose: bool = False, force_new: bool = False) -> DeviceCodeAuthResult:
    tokens: Optional[Dict[str, Any]] = None

    if not force_new:
        cached_tokens = _load_tokens_from_cache()

        if cached_tokens:
            if _is_token_valid(cached_tokens):
                print("[+] Using cached access token (still valid)")
                tokens = cached_tokens
            else:
                refresh_token = cached_tokens.get("refresh_token")
                if refresh_token:
                    tokens = _refresh_access_token(refresh_token)
                    if tokens:
                        _save_tokens_to_cache(tokens)

    if not tokens:
        tokens = _device_code_auth()
        _save_tokens_to_cache(tokens)

    access_token = tokens.get("access_token", "")
    jwt_payload, tenant_id, expires_at_local = _decode_jwt(access_token)

    if verbose:
        print("\n[+] Decoded JWT payload:\n")
        print(json.dumps(jwt_payload, indent=2, ensure_ascii=False))
        print("")

    if expires_at_local:
        print(f"[!] Access token expires at (local): {expires_at_local.isoformat()}")

    return DeviceCodeAuthResult(
        tokens=tokens,
        jwt_payload=jwt_payload,
        tenant_id=tenant_id,
        expires_at_local=expires_at_local,
    )

def clear_token_cache() -> bool:
    cache_path = Path(TOKEN_CACHE_FILE)
    if cache_path.is_file():
        try:
            cache_path.unlink()
            print(f"[+] Token cache removed ({TOKEN_CACHE_FILE})")
            return True
        except OSError as e:
            print(f"[!] Error removing cache: {e}")
            return False
    else:
        print(f"[*] Token cache does not exist ({TOKEN_CACHE_FILE})")
        return True

def email_type(s: str) -> str:
    if not EMAIL_RE.match(s):
        raise argparse.ArgumentTypeError(f"[!] Invalid e-mail address: {s}")
    return s

def existing_file(p: str) -> Path:
    path = Path(p)
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"[!] File not found: {p}")
    return path

def parse_bool(s: str) -> bool:
    t = s.strip().lower()

    if t in {"1", "true", "t", "yes", "y", "on"}:
        return True

    if t in {"0", "false", "f", "no", "n", "off"}:
        return False

    raise argparse.ArgumentTypeError(f"Invalid boolean input: {s} (use true/false)")

def list_from_file(p: str) -> List[str]:
    path = existing_file(p)
    valid, invalid = [], 0

    with path.open(encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if EMAIL_RE.match(s):
                valid.append(s)
            else:
                invalid += 1

    if not valid:
        raise argparse.ArgumentTypeError(f"[!] {p} Does not contain valid email addresses.")

    if invalid > 0:
        print(f"[!] Warning: {invalid} Invalid address(es) ignored in {p}")

    return valid

def subjects_from_file(p: str) -> List[str]:
    path = existing_file(p)
    subjects = []

    with path.open(encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            subjects.append(s)

    if not subjects:
        raise argparse.ArgumentTypeError(f"[!] {p} Does not contain valid subjects.")

    return subjects

def sniff_mime(path: Path) -> str:
    ext = path.suffix.lower()
    if ext in MIME_OVERRIDES:
        return MIME_OVERRIDES[ext]
    guess, _ = mimetypes.guess_type(str(path))
    return guess or DEFAULT_MIME

def build_attachments(attachments: List[Path], inline_flags: List[bool]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    cid_counter = 1

    for i, apath in enumerate(attachments):
        is_inline = inline_flags[i] if i < len(inline_flags) else False
        ctype = sniff_mime(apath)

        try:
            raw = apath.read_bytes()
        except OSError as e:
            raise RuntimeError(f"Error while reading attachment '{apath}': {e}") from e

        b64 = base64.b64encode(raw).decode("ascii")
        entry: Dict[str, Any] = {
            "@odata.type": "#microsoft.graph.fileAttachment",
            "name": apath.name,
            "contentType": ctype,
            "isInline": is_inline,
            "contentBytes": b64,
        }

        if is_inline:
            cid = f"attachment_cid{cid_counter}"
            entry["contentId"] = cid
            cid_counter += 1

        out.append(entry)

    return out

def parse_float_range(value: str) -> float:
    try:
        val = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid float value: {value}")

    if val < 0.0 or val > 1.0:
        raise argparse.ArgumentTypeError(f"Jitter must be between 0.0 and 1.0 (got {val})")

    return val

def format_sleep_time(seconds: int) -> str:
    if seconds >= 60:
        minutes = seconds // 60
        remaining_seconds = seconds % 60
        if remaining_seconds > 0:
            return f"{minutes}m {remaining_seconds}s"
        return f"{minutes} minute(s)"
    return f"{seconds} second(s)"

def send_mail(access_token: str, subject: str, email_body: str, recipients: List[str],
              attachment_objects: List[Dict[str, Any]], sleep_time: int = DEFAULT_SLEEP_SECONDS,
              jitter: float = 0.0, save_to_sent: bool = True, subject_list: Optional[List[str]] = None,
              content_type: str = "html", cc_recipients: Optional[List[str]] = None):

    url = "https://graph.microsoft.com/v1.0/me/sendMail"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    success_count = 0
    error_count = 0
    total_recipients = len(recipients)

    print(f"\n[*] Sending to {total_recipients} recipient(s)")
    print(f"[*] Interval between sends: {format_sleep_time(sleep_time)}")
    print(f"[*] Body format: {content_type.upper()}")

    if subject_list:
        print(f"[*] Using list of {len(subject_list)} subject(s) (random selection)")

    if cc_recipients:
        print(f"[*] CC: {len(cc_recipients)} recipient(s) in copy")

    print()

    for i, recipient in enumerate(recipients):
        current_subject = random.choice(subject_list) if subject_list else subject

        print(f"\n[{i+1}/{total_recipients}] Sending to: {recipient}")
        print(f"    Subject: {current_subject}")

        message_obj: Dict[str, Any] = {
            "subject": current_subject,
            "body": {
                "contentType": content_type,
                "content": email_body
            },
            "toRecipients": [{
                "emailAddress": {
                    "address": recipient
                }
            }],
            "attachments": attachment_objects
        }

        if cc_recipients:
            message_obj["ccRecipients"] = [
                {"emailAddress": {"address": cc}} for cc in cc_recipients
            ]

        json_body = {
            "message": message_obj,
            "saveToSentItems": save_to_sent
        }

        try:
            r = requests.post(url, headers=headers, json=json_body, timeout=60)
            r.raise_for_status()
            print(f"    [+] Email sent successfully!")
            success_count += 1
        except requests.exceptions.HTTPError as e:
            print(f"    [-] HTTP Error: {e}")
            if e.response is not None:
                try:
                    error_details = e.response.json()
                    print(f"        Details: {error_details}")
                except:
                    print(f"        Response: {e.response.text}")
            error_count += 1
        except Exception as e:
            print(f"    [-] Error: {e}")
            error_count += 1

        if i < total_recipients - 1:
            actual_sleep = sleep_time
            if jitter > 0.0:
                variation = random.uniform(-jitter, jitter) * sleep_time
                actual_sleep = max(1, sleep_time + variation)
                print(f"[*] Waiting {format_sleep_time(int(actual_sleep))} (jitter applied)")
            else:
                print(f"[*] Waiting {format_sleep_time(sleep_time)}")

            time.sleep(actual_sleep)

    print(f"\n{'='*40}")
    print(f"  Total recipients: {total_recipients}")
    print(f"  Successful sends: {success_count}")
    print(f"  Failed sends: {error_count}")
    print(f"{'='*40}")

def main(args):
    auth_result = get_graph_tokens(verbose=args.verbose, force_new=args.new_auth)
    access_token = auth_result.tokens["access_token"]

    if args.message_file:
        try:
            email_body = Path(args.message_file).read_text(encoding="utf-8")
        except OSError as e:
            raise SystemExit(f"[!] Error reading message file: {e}")
    else:
        email_body = args.message

    if args.target:
        recipients = [args.target]
    else:
        recipients = list_from_file(args.target_list)

    subject_list = None
    if args.subject_list:
        subject_list = subjects_from_file(args.subject_list)

    cc_recipients = []
    if args.cc:
        cc_recipients.append(args.cc)
    if args.cc_list:
        cc_recipients.extend(list_from_file(args.cc_list))

    attachment_objects = []
    if args.attachments:
        if len(args.attachments) != len(args.is_inline):
            print("[!] -a/--attachments and -i/--is-inline must have the same number of arguments")
            sys.exit(2)

        try:
            attachment_objects = build_attachments(
                attachments=args.attachments,
                inline_flags=args.is_inline
            )
        except RuntimeError as e:
            raise SystemExit(str(e))

    print("\n" + BANNER)

    if subject_list:
        print(f"\n[*] Available subjects: {len(subject_list)}")
        for i, subj in enumerate(subject_list, 1):
            print(f"    [{i}] {subj}")
    else:
        print(f"\n[*] Subject: {args.subject}")

    print(f"[*] Recipients: {len(recipients)}")
    if cc_recipients:
        print(f"[*] CC: {len(cc_recipients)} address(es)")
        for i, cc in enumerate(cc_recipients, 1):
            print(f"    [{i}] {cc}")
    if attachment_objects:
        print(f"[*] Attachments: {len(attachment_objects)}")
        for i, att in enumerate(attachment_objects, 1):
            line = f"    [{i}] {att['name']} | {att['contentType']} | inline={att['isInline']}"
            if att.get("contentId"):
                line += f" | CID={att['contentId']}"
            print(line)

    content_type = "text" if args.text else "html"
    send_mail(
        access_token=access_token,
        subject=args.subject if args.subject else "",
        email_body=email_body,
        recipients=recipients,
        attachment_objects=attachment_objects,
        sleep_time=args.sleep,
        jitter=args.jitter if args.jitter else 0.0,
        subject_list=subject_list,
        content_type=content_type,
        cc_recipients=cc_recipients if cc_recipients else None
    )

class BuildParser(argparse.ArgumentParser):
    def format_help(self):
        return BANNER + "\n" + super().format_help()

if __name__ == "__main__":
    parser = BuildParser(
        description="Email sender via Microsoft Graph API",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    g_recp = parser.add_mutually_exclusive_group(required=True)
    g_recp.add_argument("-t", "--target", type=email_type,
                       help="Recipient's email address.")
    g_recp.add_argument("-l", "--target-list", type=str,
                       help="File with list of recipients' email addresses (one per line).")

    g_subj = parser.add_mutually_exclusive_group(required=True)
    g_subj.add_argument("-s", "--subject", type=str,
                       help="Email subject.")
    g_subj.add_argument("-S", "--subject-list", type=str,
                       help="File with list of subjects (one per line). A random subject will be chosen for each email.")

    g_body = parser.add_mutually_exclusive_group(required=True)
    g_body.add_argument("-m", "--message", type=str,
                       help="Body of the email to be sent.")
    g_body.add_argument("-M", "--message-file", type=str,
                       help="File containing the email body to be sent.")

    parser.add_argument("-c", "--cc", type=email_type,
                       help="Email address to CC (carbon copy).")
    parser.add_argument("-C", "--cc-list", type=str,
                       help="File with list of CC email addresses (one per line). All addresses will be CC'd on every email.")

    parser.add_argument("-a", "--attachments", type=existing_file, nargs="+",
                       help="Attachment files", default=[])
    parser.add_argument("-i", "--is-inline", type=parse_bool, nargs="+",
                       help="Defines whether attachments are inline or not (true/false). It must always be specified when there are attachments.", default=[])

    parser.add_argument("-T", "--sleep", type=int, default=DEFAULT_SLEEP_SECONDS,
                       help=f"Sleep between requests in seconds (default: {DEFAULT_SLEEP_SECONDS} = 5 minutes)")

    parser.add_argument("--text", action="store_true",
                       help="Send email body as plain text instead of HTML (default: HTML)")

    parser.add_argument("-j", "--jitter", type=parse_float_range,
                        help="Jitter factor (0.0 to 1.0). Adds random variation to sleep time. Example: 0.3 = +30%% variation.")

    parser.add_argument("-v", "--verbose", action="store_true", help="If specified, will print the decoded JWT after authentication.")

    parser.add_argument("--new-auth", action="store_true",
                       help="Force new authentication, ignoring cached tokens.")
    parser.add_argument("--clear-cache", action="store_true",
                       help="Clear token cache and exit.")

    if "--clear-cache" in sys.argv:
        clear_token_cache()
        sys.exit(0)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(2)

    args = parser.parse_args()

    if args.attachments and args.is_inline:
        if len(args.attachments) != len(args.is_inline):
            parser.error("Number of --attachments and --is-inline arguments must match")

    main(args)