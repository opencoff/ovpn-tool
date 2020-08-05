## TL;DR
This is an opinionated single-file OpenVPN TLS certificate manager and OpenVPN
configuration generator. It has _no_ dependencies on any other external tool
such as openssl. It is a replacement for and an enhancement to easy-rsa
(typically bundled with OpenVPN).

## IMPORTANT
* v0.9.x is a breaking change from the previous version:
   - `pki/` code is moved to its own repository
   - boltdb code refactored (e.g., use AEAD for storing DB key)
* If you are using v0.8.x, please export the database and import it.
  See the section on importing below.

## Features
* Uses a single [boltdb](https://github.com/etcd/bbolt) instance to store the
  certificates and keys.
* All data strored in the database is encrypted with keys derived from a user
  supplied CA passphrase.
* Support for arbitrary chain of intermediate CAs
* The certificates and keys are opinionated:
   * Secp521r1 used for CA certificates
   * Secp256k1 EC certificate private keys
   * "SSL-Server" attribute set on server certificates (nsCertType)
   * "SSL-Client" attribute set on client certificates (nsCertType)
   * ECDSA with SHA512 is used as the signature algorithm
* The generated OpenVPN configuration for client or server uses inline
  certificates, keys *and* runs with an opinionated set of defaults:
   * `TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256` for
      TLS control channel
   * `AES-256-GCM` for data encryption
   * TLS 1.2 is the minimum version negotiation
   * Client verifies the X509 Common-Name of the server
   * Uses "tun" mode
   * Server pushes its tunnel address as the default gateway for all
     client traffic
   * Server pushes its tunnel address as the DNS address so that all
     DNS lookups on the client can be handled inside the tunnel. The
     server will need additional software such as unbound to provide
     DNS server functionality.
   * The Client and Server configurations uses the `tls-crypt` option
     to ensure that the server is protected with an additional layer
     of encryption to thwart DoS attacks.
* Ability to export DB contents as a JSON file; ability to import
  JSON from a previous export.

## Building ovpn-tool
You will need a fairly recent golang toolchain (>1.10):

    $ git clone https://github.com/opencoff/ovpn-tool
    $ cd ovpn-tool
    $ ./build -s

The build script puts the binary in a platform specific directory:

* macOS: `bin/darwin-amd64`
* Linux: `bin/linux-amd64`
* OpenBSD: `bin/openbsd-amd64`

And so on. The build script can generate a fully standalone
statically-linked binary on platforms that support it. To build
statically linked binaries, use `build -s`.

You can also do cross-platform builds for any supported OS, Arch
combination supported by the golang toolchain. e.g., on macOS,
to build a statically linked binary for linux-amd64 architecture:

    $ ./build -s --arch linux-amd64

## Invoking ovpn-tool
The common pattern for invoking ovpn-tool is:

    ovpn-tool DB CMD [options] [arguments]

Where:
* *DB* is the name of the certificate store (database). This is a
  [boltdb](https://github.com/etcd/bbolt) instance.

* *CMD* is a command - one of `init`, `server`, `client`, `export`,
  `list`, `delete`, `crl`, `passwd`.

The tool writes the certificates, keys into an encrypted boltdb instance.

The tool comes with builtin help:

    $ ./bin/openbsd-amd64/ovpn-tool --help

Every subcommand comes with its own help; but, requires you to at least
supply a database name as the first argument. e.g.,

    $ ./bin/openbsd-amd64/ovpn-tool foo.db server --help

## Common Workflows
In what follows, we will assume that you have built ovpn-tool and
installed somewhere in your `$PATH`.

### Initialize a new CA
Before any certificates are generated, one must first create a CA and
initialize the certificate DB:

    $ ovpn-tool -v foo.db init my-CA

You can see the generated CA certificate via two ways:

1. Using `-v` for the ovpn-tool's global options
2. Using the `list` command with the `--ca` option.

In general, using the `-v` global option when generating the CA, server
or client certificates will print the certificate to stdout at the end.

The CA can be initialized with additional data such as Organization Name,
Organization Unit Name etc. See `init --help` for additional details.

The default lifetime of the CA is 5 years; you can change this via
the `-V` (`--validity`) option to "init".

### Initialize a new CA by Importing from a JSON file
If you are using any version of ovpn-tool **prior** to v0.9.x, you
must first export the DB into a JSON file *using the v0.8.x version
of the tool*. Assuming the DB dump is in *db.json*, then you can
initialize a new CA instance like so:

    $ ovpn-tool -v foo.db init --from-json db.json

You will be prompted for the DB passphrase; this passphrase is for
the **new** database (and NOT the old database).

### Creating an intermediate CA
Often, it's useful to have an intermediate CA for issuing server or
client certificates. These intermediate CAs can be arbitrarily
chained.

    $ ovpn-tool -v foo.db inter client-ca

Once created, this intermediate CA can be used to issue new leaf
certificates:

    $ ovpn-tool -v foo.db user -s client-ca user@example.com

### Create an OpenVPN server certificate & key pair
An OpenVPN server needs a few things:
* A server common name - so client can either address it by DNS Name.
* An IP Address - so that the server config can use it to listen on
  an IP:Port.
* The IP Address has the additional benefit (or drawback) of not
  requiring the client to do a DNS lookup.

Creating a new server certificate/key pair:

    $ ovpn-tool -v foo.db server -i IP.ADDR.ES server.domain.name

Of course, you should use the appropriate values for `IP.ADDR.ES`
and `server.domain.name` for your setup.

The IP Address and Server FQDN show up in the certificate as
Certificate.IPAddress and Certificate.Sibject.CommonName.
Additionally, the server FQDN also shows up in Certificate.DNSNames.

You can also set a custom OpenVPN port for this server via the `-p`
flag. You can request the server certificate to have a different
validity via the `V` (`--validity`) option; this option takes the
value in units of years.

You can of course create as many server certificates as needed. But,
when you export a *client* configuration, you must select the correct
server name this client will connect to. See example below.

### Create an OpenVPN client (user) certificate & key pair
An OpenVPN client certificate is quite simple - it just needs a
common name. For convenience, you may use the email address as the
common Name.

    $ ovpn-tool -v foo.db client user@domain.name

You can ask the client private key to be encrypted with a user
supplied passphrase by using the `-p` or `--password` option to the
`client` command.  You can request the client certificate to have
a different validity via the `V` (`--validity`) option; this option
takes the value in units of years.

### Delete an OpenVPN user from the Cert Database
Once in a while you will want to delete users and prevent them from
connecting to the OpenVPN server. E.g.,

    $ ovpn-tool -v foo.db delete user@domain.name user2@domain

This only deletes the users from the certificate DB. You still need
to generate a new CRL (Certificate Revocation List) and push it to
your server. See the next workflow.

### Generate a CRL from Revoked Certificates
Once a user is deleted from the system, you will need to generate a
new CRL and push it to the server. The command to generate a new
CRL:

    $ ovpn-tool -v foo.db crl -o crl.pem

This write the PEM encoded CRL to `crl.pem`. You must copy this file
to the OpenVPN server and reload (or restart) it.

You can also just view a full list of revoked users:

    $ ovpn-tool foo.db crl --list

### See list of certificates managed by this CA
To see a list of certificates in the database:

    $ ovpn-tool foo.db list

## Revoking CAs or Leaf Certificates
ovpn-tool enables you to revoke intermediate CAs or leaf
certificates. To revoke a user/server cerfificate:

    $ ovpn-tool foo.db del NAME

where `NAME` is the common-name of the certificate you want to
revoke. **Note** you should generate a new CRL once you revoke any
certificate:

    $ ovpn-tool foo.db crl -v 7 -o crl.pem

This generates a CRL with a 7 day validity (you should regenerate
the CRLs regularly).

### Exporting a Server Configuration
While the tool manages certificates, what we are really after are
OpenVPN server & client configurations for the server & client
respectively. To export a server configuration:

    $ ovpn-tool foo.db export server.domain.name

This prints the server configuration to stdout. To save this to a
file:

    $ ovpn-tool foo.db export server.domain.name -o server.conf

Note the configuration uses certain private IP address blocks and
such. Please edit the configuration file to suit your environment.

*At a minimum* you have to edit the user/group information
particular to your OS for dropping privilege of the OpenVPN daemon.
e.g., on Alpine Linux, the preferred user and group for the daemon
is "openvpn". On OpenBSD it is "\_openvpn"; on macOS it is "nobody".

The server configuration uses a template baked into ovpn-tool. You
have the option of providing your own template. The easiest way is
to export the template and edit it. You can then feed the modified
template back to the export command:

    $ ovpn-tool foo.db export --print-server-template > s.template
    $ vi s.template
    $ ovpn-tool foo.db export -t s.template -o s.conf server.domain.name

### Exporting a Client Configuration
Client configuration is typically associated with one OpenVPN
server. However, this is optional and you can take an unassociated
configuration and make manual changes as needed. A typical
invocation is:

    $ ovpn-tool foo.db export -s server.domain.name -o client.conf user@domain.name

You can export the default client configuration template like so:

    $ ovpn-tool foo.db export --print-client-template > c.template

### Replacing the user passphrase on a DB
If you desire to change the DB passphrase, you can do so with the
`passwd` command:

    $ ovpn-tool foo.db passwd

This merely changes the way the encrypted DB key is stored on disk.

## Template variables available for customization
The following template parameters are available for use in your
custom configuration templates:

* `.CommonName` - Certificate common name
* `.Date` - Today's date and time (UTC)
* `.Tool` - ovpn-tool build information (version, etc.)
* `.Cert` - PEM encoded certificate
* `.Key`  - PEM encoded private key
* `.Ca`   - PEM encoded CA certificate
* `.TlsCrypt` - Base64 encoded OpenVPN "tls-crypt" key
* `.ServerCommonName` - Common name of the server
* `.Host` - Server DNS name from the server certificate
* `.IP`   - Server IP address from the server certificate
* `.Port` - OpenVPN server port number provided when server
  certificate was created


# Development Notes
If you wish to hack on this, notes here might be useful.

The code is organized as a library & command line frontend for that library.

* We use go module support; you will need go 1.10+ or later

* The common PKI creation & storage is in the `pki/` library. This
  library can be used by external callers. e.g., see
  https://github.com/opencoff/certik


* The build script `build` is a shell script to build the program.
  It does two very important things:
    * Puts the binary in an OS+Arch specific directory
    * Injects a git version-tag into the final binary ("linker resolved symbol")

* The OpenVPN server & client configuration templates are in `src/export.go`.
  It uses golang's `text/template` syntax.

* Database encryption:
    * User passphrase is first expanded to 64 bytes by hashing it via SHA-512.
    * The DB is associated with a random 32-byte encryption key and a random 32-byte
      salt. This key is protected with a Key-encryption-key (KEK) derived from
      the expanded passphrase.
    * The salt and expanded passphrase are fed into Argon2i to derive the KEK.
    * The DB encryption key is stored on disk as an AEAD encrypted blob (AES-256-GCM).
      The salt and KEK is stored in the DB.
    * In pseudo code, the above looks like so:
      ```python

          expanded  = SHA512(passphrase)
          salt      = randombytes(32)
          dbkey     = randombytes(32)
          kek       = KDF(expanded, salt)
          enc_dbkey = AES-256-GCM(kek, salt)
      ```

    * Database entries are individually encrypted in AEAD (AES-256-GCM) mode.
      The AEAD nonce size is 16 bytes (instead of the golang default of 12 bytes).
    * Each AEAD encrypt instance uses a separate salt and key extracted via HKDF.
    * The HKDF salt is used as additional data in the AEAD construction.
    * Database bucket keys are entangled with the expanded passphrase and the DB
      salt via HMAC-SHA256. We don't use any kind of AEAD here because we need a
      quick and easy way to map user CN's to actual keys.  See how `d.key()` is
      used in *db.go*.

## Guide to Source Code
* The bulk of the code for PKI management is in
  [go-pki](https://github.com/opencoff/go-pki).

* The ovpn-tool command line code is in the `src/` directory.
  Each command is in its own file.

* `internal/utils`: Misc utilities for asking interactive password

