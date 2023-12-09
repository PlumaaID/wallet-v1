## Plumaa Keys

This directory contains the keys for the accounts used in Plumaa tests. Each subfolder requires to be filled with a `private.pem` and `public.pem` file, which can be obtained from [the oficial SAT website](http://omawww.sat.gob.mx/tramitesyservicios/Paginas/certificado_sello_digital.htm) since they provide tests certificates and keys for developers.

The characteristics of these certificates are well outlined in [this external documentation.](https://go.reachcore.com/docs/Articulos/CSDPruebas).

### How to generate each `private.pem` and `public.pem` file

The tests certificates provided by the SAT are in `.cer` format. These include the identification information associated to each public key included in the certificate and should've been signed by the SAT certification authority.

Similarly, the private keys of each `.cer` file are given in `.key` format. These files are encrypted by a password, which is provided by the SAT in a `.txt` file.

You'll need both `.cer` and `.key` to convert them to `.pem` using OpenSSL.

For the `.cer` to a `public.pem`:

> [!WARNING]
> Never use actual private keys here since they'll be stored without encryption. Although the keys are ignored by git, there's a high risk of leaking if such key is kept unencrypted.

```bash
openssl x509 -inform der -in path/to/certificate.cer -pubkey -noout -outform der > public.pem
```

For the `.key` to a `private.pem`:

```bash
## NOTE: You'll be prompted for the password here.
openssl rsa -inform der -outform pem -in path/to/private.key -out private.pem
```

Repeat these steps for each signer subfolder in this directory.
