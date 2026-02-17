# Email Extractor

Enterprise Email Credential Extraction System for migrating email accounts between different email clients and services.

## Features

- **Multi-Client Support**: Extract credentials from Microsoft Outlook, Mozilla Thunderbird, and Apple Mail
- **Multiple Authentication Types**: Supports IMAP, POP3, SMTP, Exchange, OAuth (Microsoft), and OAuth (Google)
- **Secure Credential Handling**: Credentials are handled securely in-memory and can be stored via keyring
- **Connection Testing**: Validates extracted credentials by testing connections
- **Encrypted Storage**: Supports secure storage of extracted credentials

## Supported Email Clients

- Microsoft Outlook (Windows/macOS)
- Mozilla Thunderbird (Windows/macOS/Linux)
- Apple Mail (macOS only)

## Requirements

- Python 3.8+
- pip install keyring pywin32 msal google-auth-oauthlib cryptography

## Usage

```
bash
# Extract Outlook credentials
python email_extractor.py --client outlook --account user@example.com --output-store keyring

# Extractpython email_extractor Thunderbird credentials
.py --client thunderbird --output-store keyring

# Extract Apple Mail credentials
python email_extractor.py --client applemail --output-store keyring
```

## Options

- `--client`: Email client (outlook, thunderbird, applemail)
- `--account`: Specific account ID (optional)
- `--output-store`: Storage backend (keyring, json)
- `--os`: Override OS detection (windows, darwin, linux)

## Security Notes

- Run under user context for access to secure stores
- Credentials are handled securely in-memory
- Master passwords may be required for Thunderbird profiles

## License

MIT License
