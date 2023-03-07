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

### Use case 1

Login on a GNU/Linux workstation via the GNOME Display Manager (GDM) and `pam_deviceauthgrant`.

1. Install `pam_deviceauthgrant`

2. Modify the pam login flow used by GDM. On my test Fedora 37 workstation this is located at `/etc/pam.d/gdm-password`

   ```
   # my system has two pre-existing local accounts which I exclude from
   # the pam_deviceauthgrant routines
   auth [success=2 default=ignore] pam_succeed_if.so uid in 0:1000
   auth    sufficient      /lib64/security/pam_deviceauthgrant.so qrcode
   auth    required        pam_deny.so
   account [success=1 default=ignore] pam_succeed_if.so uid in 0:1000
   account sufficient      /lib64/security/pam_deviceauthgrant.so
   ```
3. Modify the GDM shell theme as described for instance here https://wiki.archlinux.org/title/GDM
   Most importantly, make sure that you modify  `gnome-shell.css` to include something like
   
   ```
   .login-dialog-prompt-layout {
   /* .. all other things here .. */
   width: 100%!important;
   }

    /* this is needed to display the QR code correctly */
   .login-dialog-message {
    display: block;
    unicode-bidi: embed;
    font-family: monospace;
    white-space: pre-wrap;
   }
   ```
4. systemctl restart gdm

5. Make sure your workstation is connected to the internet

6. Login

### Use case 2

Login on an iRODS system `pam_deviceauthgrant`. The advantage here is to delegate the login process, including where
applicable multifactor authentication (MFA), to your institution  identity provider (IdP).

1. Clone `pam_deviceauthgrant`

2. Modify `deviceauthgrant.c` to add your iRODS user creation logics in `pam_sm_acct_mgmt`. Recompile

3. Modify the pam login flow used by iRODS. This is located at `/etc/pam.d/irods`, for instance

   ```
   auth    required        pam_nologin.so
   auth    sufficient      /lib64/security/pam_deviceauthgrant.so
   auth    required        pam_deny.so
   account sufficient      /lib64/security/pam_deviceauthgrant.so
   ```

4. Login
