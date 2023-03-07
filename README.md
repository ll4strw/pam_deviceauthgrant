## Installation

```
autoreconf --install
./configure [--with-pam-mod-dir=/lib64/security]
make
make install

Take note of the installation directory, e.g.

/lib64/security/pam_deviceauthgrant.so

```

## Configuration

```
cat /etc/pam.d/deviceauthgrant

auth    required        pam_nologin.so
auth    sufficient      /lib64/security/pam_deviceauthgrant.so [debug] [qrcode] [agentconf=/full/path/to/pam_deviceauthgrant/conf/file.json]
auth    required        pam_deny.so
account sufficient      /lib64/security/pam_deviceauthgrant.so
```

If agentconf is not specified, deviceauthgrant.so will try parsing
/etc/deviceauthgrant.json


Do **NOT** use the `debug` option in production! 

```
cat /full/path/to/pam_deviceauthgrant/conf/file.json

{
    "dev_auth_url": "<device auth endpoint>",
    "token_url": "<token endpoint>",
    "client_secret": "<client secret>",
    "ca_certs": "<full path to 'bundle' of Certificate Authority (CA) public keys (CA certs)>",
    "client_scopes": "<requested scopes>",
    "client_id": "<client identifier>"
}

For instance, with Keycloak IAM

{
    "dev_auth_url": "https://YOUR_KC_INSTANCE/auth/realms/YOUR_REALM_NAME/protocol/openid-connect/auth/device",
    "token_url": "https://YOUR_KC_INSTANCE/auth/realms/YOUR_REALM_NAME/protocol/openid-connect/token",
    "client_secret": "YOUR-CLIENT-SECRET",
    "ca_certs": "/etc/pki/tls/certs/ca-bundle.crt",
    "client_scopes": "ANY-VALID-SCOPES",
    "client_id": "YOUR-CLIENT-ID"
}

```

## Test

```
pamtester deviceauthgrant USERNAME authenticate
pamtester deviceauthgrant USERNAME acct_mgmt
```

