# Hermes

```
     █████   █████
    ░░███   ░░███
     ░███    ░███   ██████  ████████  █████████████    ██████   █████
     ░███████████  ███░░███░░███░░███░░███░░███░░███  ███░░███ ███░░
     ░███░░░░░███ ░███████  ░███ ░░░  ░███ ░███ ░███ ░███████ ░░█████
     ░███    ░███ ░███░░░   ░███      ░███ ░███ ░███ ░███░░░   ░░░░███
     █████   █████░░██████  █████     █████░███ █████░░██████  ██████
    ░░░░░   ░░░░░  ░░░░░░  ░░░░░     ░░░░░ ░░░ ░░░░░  ░░░░░░  ░░░░░░
```

**Version:** 0.1.0

---
### Description

Hermes is a command-line tool for sending emails using the Microsoft Graph API. It uses OAuth2 Device Code Flow authentication, allowing you to send emails through Microsoft 365 accounts.

### Requirements

- Python 3.8+
- `requests` library

```bash
pip install requests
```

### Features

- Device Code Flow authentication (OAuth2)
- Token caching (avoids re-authentication on each run)
- Automatic token refresh via refresh token
- Single recipient or recipient list support
- Single CC or CC list support
- Fixed subjects or subject list (random selection)
- Email body in HTML or plain text
- Attachment support (inline or regular)
- Configurable delay between sends (default: 5 minutes)
- Jitter for random variation in delay

### Usage

```bash
python hermes.py [options]
```

### Arguments

#### Recipients (required, mutually exclusive)

| Argument | Description |
|----------|-------------|
| `-t, --target EMAIL` | Recipient's email address |
| `-l, --target-list FILE` | File with list of recipients (one per line) |

#### Subject (required, mutually exclusive)

| Argument | Description |
|----------|-------------|
| `-s, --subject TEXT` | Email subject |
| `-S, --subject-list FILE` | File with list of subjects (one per line). A random subject will be chosen for each email |

#### Email Body (required, mutually exclusive)

| Argument | Description |
|----------|-------------|
| `-m, --message TEXT` | Email body |
| `-M, --message-file FILE` | File containing the email body |

#### CC (Carbon Copy)

| Argument | Description |
|----------|-------------|
| `-c, --cc EMAIL` | Email address to CC |
| `-C, --cc-list FILE` | File with list of CC addresses (one per line) |

#### Attachments

| Argument | Description |
|----------|-------------|
| `-a, --attachments FILE [FILE ...]` | Files to attach |
| `-i, --is-inline BOOL [BOOL ...]` | Defines whether attachments are inline (true/false). Must match the number of attachments |

#### Send Settings

| Argument | Description |
|----------|-------------|
| `-T, --sleep SECONDS` | Delay between sends in seconds (default: 300 = 5 minutes) |
| `-j, --jitter FACTOR` | Jitter factor (0.0 to 1.0). Adds random variation to the delay |
| `--text` | Send body as plain text instead of HTML |

#### Authentication

| Argument | Description |
|----------|-------------|
| `--new-auth` | Force new authentication, ignoring cached tokens |
| `--clear-cache` | Clear token cache and exit |
| `-v, --verbose` | Display decoded JWT payload after authentication |

### Examples

#### Basic send
```bash
python hermes.py -t recipient@email.com -s "Email Subject" -m "Email body"
```

#### Send with HTML file
```bash
python hermes.py -t recipient@email.com -s "Newsletter" -M template.html
```

#### Send to recipient list
```bash
python hermes.py -l recipients.txt -s "Announcement" -m "Announcement text"
```

#### With random subjects
```bash
python hermes.py -l recipients.txt -S subjects.txt -M body.html
```

#### With CC
```bash
python hermes.py -t recipient@email.com -s "Report" -m "Report attached" -c copy@email.com
```

#### With CC list
```bash
python hermes.py -t recipient@email.com -s "Report" -m "Report attached" -C cc_list.txt
```

#### With attachment
```bash
python hermes.py -t recipient@email.com -s "Document" -m "See attachment" -a document.pdf -i false
```

#### Send as plain text
```bash
python hermes.py -t recipient@email.com -s "Notice" -m "Plain text" --text
```

#### Custom delay with jitter
```bash
python hermes.py -l recipients.txt -s "Subject" -m "Body" -T 60 -j 0.3
```

#### Force new authentication
```bash
python hermes.py -t recipient@email.com -s "Test" -m "Test" --new-auth
```

#### Clear token cache
```bash
python hermes.py --clear-cache
```

### List File Format

```
email1@example.com
email2@example.com
# Lines starting with # are ignored
email3@example.com
```

### Token Caching

Hermes saves authentication tokens to `.hermes_tokens.json` in the current directory. This avoids the need to re-authenticate on each run.

- If the access token is still valid, it is reused
- If expired, the refresh token is used to obtain a new access token
- Only if both fail, a new authentication is requested

---

## License

This project is for educational and authorized testing purposes only.

## Credits

Inspired in part by the [GraphRunner](https://github.com/dafthack/GraphRunner) project.
