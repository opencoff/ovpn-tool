// db.go - db storage for certs, server info etc.
//
// (c) 2018 Sudhi Herle; License GPLv2
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package ovpn

// Internal details:
//
// * All data written to the db is encrypted with a key derived from a
//   user supplied passphrase
// * Updating serial#: anytime a user cert or a server cert is written,
//   we update the serial number at the same time. We also update serial
//   number when CA is created for the first time.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/gob"
	"encoding/pem"
	"fmt"
	bolt "github.com/etcd-io/bbolt"
	"math/big"
	"os"
	"path"
	"time"

	"golang.org/x/crypto/argon2"
)

type database struct {
	db  *bolt.DB
	pwd []byte // expanded 64 byte passphrase

	// set to true if CA has been initialized
	ca bool
}

type cadata struct {
	Cert
	serial *big.Int
}

// gob encoded Cert pair
type certgob struct {
	Cert []byte
	Key  []byte
}

// gob encoded server info
type srvgob struct {
	Cert []byte
	Key  []byte

	Port uint16

	TLS []byte
}

func newDB(fn string, pw string, creat bool) (*database, error) {
	fi, _ := os.Stat(fn)
	if fi != nil {
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("%s: not a regular file", fn)
		}
	} else if !creat {
		return nil, fmt.Errorf("Can't open DB %s", fn)
	}

	dbdir := path.Dir(fn)
	err := os.MkdirAll(dbdir, 0700)
	if err != nil {
		return nil, fmt.Errorf("can't create dir %s for DB %s: %s", dbdir, fn, err)
	}

	db, err := bolt.Open(fn, 0600, nil)
	if err != nil {
		return nil, err
	}

	// initialize key buckets
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("server"))
		if err != nil {
			return fmt.Errorf("%s: can't create server bucket: %s", fn, err)
		}

		_, err = tx.CreateBucketIfNotExists([]byte("user"))
		if err != nil {
			return fmt.Errorf("%s: can't create user bucket: %s", fn, err)
		}

		_, err = tx.CreateBucketIfNotExists([]byte("config"))
		if err != nil {
			return fmt.Errorf("%s: can't create ca bucket: %s", fn, err)
		}

		_, err = tx.CreateBucketIfNotExists([]byte("revoked"))
		if err != nil {
			return fmt.Errorf("%s: can't create revoked bucket: %s", fn, err)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	h := sha512.New()
	h.Write([]byte(pw))
	h.Write([]byte("dbpassword"))
	d := &database{
		db:  db,
		pwd: h.Sum(nil),
	}

	return d, nil
}

func (d *database) close() error {
	return d.db.Close()
}

func (d *database) getCA(pw string) (*cadata, error) {
	var c *cadata

	err := d.db.View(func(tx *bolt.Tx) error {
		bc := tx.Bucket([]byte("config"))
		if bc == nil {
			return fmt.Errorf("can't find config bucket")
		}

		rgb := bc.Get(d.key("ca"))
		rsn := bc.Get(d.key("serial"))
		if rgb == nil || rsn == nil {
			return nil
		}

		gb, err := d.decrypt(rgb)
		if err != nil {
			return fmt.Errorf("can't decrypt ca: %s", err)
		}

		sn, err := d.decrypt(rsn)
		if err != nil {
			return fmt.Errorf("can't decrypt serial#: %s", err)
		}

		ck, err := decodeCert("ca", gb)
		if err != nil {
			return err
		}

		err = ck.decryptKey(ck.Rawkey, pw)
		if err != nil {
			return err
		}

		c = &cadata{
			Cert:   *ck,
			serial: big.NewInt(0).SetBytes(sn),
		}

		d.ca = true
		return nil
	})

	return c, err
}

func decodeCert(cn string, ub []byte) (*Cert, error) {
	var cg certgob

	b := bytes.NewBuffer(ub)
	g := gob.NewDecoder(b)
	err := g.Decode(&cg)
	if err != nil {
		return nil, fmt.Errorf("%s: can't decode gob: %s", cn, err)
	}
	cert, err := x509.ParseCertificate(cg.Cert)
	if err != nil {
		return nil, fmt.Errorf("%s: can't parse cert: %s", cn, err)
	}

	ck := &Cert{
		Crt:    cert,
		Rawkey: cg.Key,
	}
	return ck, nil
}

// Given a Cert, a raw key block and a password, decrypt the privatekey
// and set it to c.Key
func (c *Cert) decryptKey(key []byte, pw string) error {
	blk, _ := pem.Decode(key)

	var der []byte = blk.Bytes
	var err error

	if x509.IsEncryptedPEMBlock(blk) {
		pk, ok := c.Crt.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("bad cert (PublicKey not ECDSA)")
		}

		salt := cksum(pk)
		pass := kdfstr(pw, salt)

		der, err = x509.DecryptPEMBlock(blk, pass)
		if err != nil {
			return fmt.Errorf("can't decrypt private key: %s", err)
		}
	}

	sk, err := x509.ParseECPrivateKey(der)
	if err == nil {
		c.Key = sk
	}

	return err
}

// given a Cert, marshal the private key and return as bytes
func (c *Cert) encryptKey(pw string) ([]byte, error) {
	if c.Key == nil {
		return nil, fmt.Errorf("privatkey is nil")
	}

	derkey, err := x509.MarshalECPrivateKey(c.Key)
	if err != nil {
		return nil, fmt.Errorf("can't marshal private key: %s", err)
	}

	var blk *pem.Block
	if len(pw) > 0 {
		salt := cksum(&c.Key.PublicKey)
		pass := kdfstr(pw, salt)

		blk, err = x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", derkey, pass, x509.PEMCipherAES256)
		if err != nil {
			return nil, err
		}
	} else {
		blk = &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: derkey,
		}
	}

	return pem.EncodeToMemory(blk), nil
}

// marshal a Cert into a gob stream
func (c *Cert) marshal(pw string) ([]byte, error) {
	sn := c.Crt.Subject.CommonName
	if c.Crt.Raw == nil {
		return nil, fmt.Errorf("%s: Raw cert is nil?", sn)
	}

	key, err := c.encryptKey(pw)
	if err != nil {
		return nil, err
	}

	cg := &certgob{
		Cert: c.Crt.Raw,
		Key:  key,
	}

	var b bytes.Buffer
	g := gob.NewEncoder(&b)
	err = g.Encode(cg)
	if err != nil {
		return nil, fmt.Errorf("%s: can't gob-encode cert: %s", sn, err)
	}

	return b.Bytes(), nil
}

// marshal and write the CA to disk
// Also update the serial#
func (d *database) putCA(ca *cadata, pw string) error {
	if d.ca {
		return fmt.Errorf("CA already initialized")
	}

	b, err := ca.Cert.marshal(pw)
	if err != nil {
		return err
	}

	eb, err := d.encrypt(b)
	if err != nil {
		return fmt.Errorf("can't encrypt ca: %s", err)
	}

	es, err := d.encrypt(ca.Crt.SerialNumber.Bytes())
	if err != nil {
		return fmt.Errorf("can't encrypt serial#: %s", err)
	}

	err = d.db.Update(func(tx *bolt.Tx) error {
		bc := tx.Bucket([]byte("config"))
		if bc == nil {
			return fmt.Errorf("can't find config bucket")
		}

		err := bc.Put(d.key("ca"), eb)
		if err != nil {
			return fmt.Errorf("can't write ca data: %s", err)
		}

		err = bc.Put(d.key("serial"), es)
		if err != nil {
			return fmt.Errorf("can't write serial#: %s", err)
		}
		return nil
	})

	return err
}

// Return either Server or Cert
func (d *database) getcn(cn string) (interface{}, error) {
	s, err := d.getsrv(cn)
	if err == nil {
		return s, nil
	}

	c, err := d.getuser(cn)
	return c, err
}

func decodeSrv(ub []byte) (*Server, error) {
	var sg srvgob

	b := bytes.NewBuffer(ub)
	g := gob.NewDecoder(b)
	err := g.Decode(&sg)
	if err != nil {
		return nil, fmt.Errorf("can't gob-unmarshal: %s", err)
	}

	cert, err := x509.ParseCertificate(sg.Cert)
	if err != nil {
		return nil, fmt.Errorf("can't parse cert: %s", err)
	}

	sd := &Server{
		Cert: Cert{
			Crt:    cert,
			Rawkey: sg.Key,
		},

		ServerInfo: ServerInfo{
			Port: sg.Port,
			TLS:  sg.TLS,
		},
	}

	return sd, nil
}

// Return server with this config
func (d *database) getsrv(cn string) (*Server, error) {
	var s *Server

	err := d.db.View(func(tx *bolt.Tx) error {
		var err error

		bu := tx.Bucket([]byte("server"))
		if bu == nil {
			return fmt.Errorf("%s: can't find server bucket", cn)
		}

		rub := bu.Get(d.key(cn))
		if rub == nil {
			return fmt.Errorf("%s: can't find server", cn)
		}

		ub, err := d.decrypt(rub)
		if err != nil {
			return fmt.Errorf("can't decrypt server info: %s", err)
		}

		sd, err := decodeSrv(ub)
		if err != nil {
			return err
		}

		s = sd
		return nil
	})

	return s, err
}

// Return user with this config
func (d *database) getuser(cn string) (*Cert, error) {
	var c *Cert

	err := d.db.View(func(tx *bolt.Tx) error {
		var err error

		bu := tx.Bucket([]byte("user"))
		if bu == nil {
			return fmt.Errorf("%s: can't find user bucket", cn)
		}

		rub := bu.Get(d.key(cn))
		if rub == nil {
			return fmt.Errorf("%s: can't find user", cn)
		}

		ub, err := d.decrypt(rub)
		if err != nil {
			return fmt.Errorf("can't decrypt user info: %s", err)
		}

		c, err = decodeCert(cn, ub)
		if err != nil {
			return err
		}

		return nil
	})

	return c, err
}

// Store server config
func (d *database) putsrv(s *Server, pw string) error {
	crt := &s.Cert
	sn := crt.Crt.Subject.CommonName
	if crt.Crt.Raw == nil {
		return fmt.Errorf("%s: Server Cert is nil?", sn)
	}

	key, err := crt.encryptKey(pw)
	if err != nil {
		return err
	}

	sg := &srvgob{
		Cert: crt.Crt.Raw,
		Key:  key,
		TLS:  s.TLS,
	}

	var b bytes.Buffer
	g := gob.NewEncoder(&b)
	err = g.Encode(sg)
	if err != nil {
		return fmt.Errorf("can't encode server info: %s", err)
	}

	eb, err := d.encrypt(b.Bytes())
	if err != nil {
		return fmt.Errorf("can't encrypt server info: %s", err)
	}

	es, err := d.encrypt(crt.Crt.SerialNumber.Bytes())
	if err != nil {
		return fmt.Errorf("can't encrypt server serial#: %s", err)
	}

	err = d.db.Update(func(tx *bolt.Tx) error {
		bs := tx.Bucket([]byte("server"))
		if bs == nil {
			return fmt.Errorf("%s: can't find server bucket", sn)
		}
		bc := tx.Bucket([]byte("config"))
		if bc == nil {
			return fmt.Errorf("%s: can't find config bucket", sn)
		}

		err := bs.Put(d.key(sn), eb)
		if err != nil {
			return fmt.Errorf("%s: can't write server info: %s", sn, err)
		}

		err = bc.Put(d.key("serial"), es)
		if err != nil {
			return fmt.Errorf("%s: can't write serial#: %s", sn, err)
		}
		return nil
	})

	return err
}

// store user cert with the provided password
func (d *database) putuser(c *Cert, pw string) error {
	crt := c.Crt
	sn := crt.Subject.CommonName
	if crt.Raw == nil {
		return fmt.Errorf("%s: User Cert is nil?", sn)
	}

	b, err := c.marshal(pw)
	if err != nil {
		return fmt.Errorf("%s: can't marshal cert+key: %s", sn, err)
	}

	eb, err := d.encrypt(b)
	if err != nil {
		return fmt.Errorf("can't encrypt client info: %s", err)
	}

	es, err := d.encrypt(crt.SerialNumber.Bytes())
	if err != nil {
		return fmt.Errorf("can't encrypt client serial#: %s", err)
	}

	err = d.db.Update(func(tx *bolt.Tx) error {
		bu := tx.Bucket([]byte("user"))
		if bu == nil {
			return fmt.Errorf("%s: can't find user bucket", sn)
		}

		bc := tx.Bucket([]byte("config"))
		if bc == nil {
			return fmt.Errorf("%s: can't find config bucket", sn)
		}

		err := bu.Put(d.key(sn), eb)
		if err != nil {
			return fmt.Errorf("%s: can't write user info: %s", sn, err)
		}

		err = bc.Put(d.key("serial"), es)
		if err != nil {
			return fmt.Errorf("%s: can't write serial#: %s", sn, err)
		}
		return nil
	})

	return err
}

// delete user
func (d *database) deluser(cn string) error {
	err := d.db.Update(func(tx *bolt.Tx) error {
		bu := tx.Bucket([]byte("user"))
		if bu == nil {
			return fmt.Errorf("%s: can't find user bucket", cn)
		}

		rv := tx.Bucket([]byte("revoked"))
		if bu == nil {
			return fmt.Errorf("%s: can't find revoked bucket", cn)
		}

		k := d.key(cn)
		rub := bu.Get(d.key(cn))
		if rub == nil {
			return fmt.Errorf("%s: can't find user", cn)
		}

		now, err := time.Now().UTC().MarshalBinary()
		if err != nil {
			return fmt.Errorf("%s: can't get time: %s", cn, err)
		}

		et, err := d.encrypt(now)
		if err != nil {
			return fmt.Errorf("%s: can't encrypt time: %s", cn, err)
		}

		// Add the cert on the revoked list. We'll use this to list revoked certs
		// and generate an up-to-date CRL.
		err = rv.Put(et, rub)
		if err != nil {
			return fmt.Errorf("%s: can't add to revoked bucket: %s", cn, err)
		}

		return bu.Delete(k)
	})
	return err
}

// iterators for revoked certs
func (d *database) mapRevoked(fp func(t time.Time, c *x509.Certificate)) error {
	err := d.db.View(func(tx *bolt.Tx) error {
		bs := tx.Bucket([]byte("revoked"))
		if bs == nil {
			return fmt.Errorf("can't find revoked bucket")
		}

		err := bs.ForEach(func(k, ev []byte) error {
			tb, err := d.decrypt(k)
			if err != nil {
				return fmt.Errorf("can't decrypt time: %s", err)
			}

			var t time.Time

			err = t.UnmarshalBinary(tb)
			if err != nil {
				return fmt.Errorf("can't decode time: %s", err)
			}

			v, err := d.decrypt(ev)
			if err != nil {
				return fmt.Errorf("can't decrypt revoked cert: %s", err)
			}

			ck, err := decodeCert("$revoked-cert", v)
			if err != nil {
				return err
			}

			fp(t, ck.Crt)
			return nil
		})
		return err
	})
	return err
}

// iterators for server block
func (d *database) mapSrv(fp func(s *Server)) error {
	err := d.db.View(func(tx *bolt.Tx) error {
		bs := tx.Bucket([]byte("server"))
		if bs == nil {
			return fmt.Errorf("can't find server bucket")
		}

		err := bs.ForEach(func(k, ev []byte) error {
			v, err := d.decrypt(ev)
			if err != nil {
				return fmt.Errorf("can't decrypt server info: %s", err)
			}

			sd, err := decodeSrv(v)
			if err != nil {
				return err
			}

			fp(sd)
			return nil
		})

		return err
	})

	return err
}

// iterators for user block
func (d *database) mapUser(fp func(c *Cert)) error {
	err := d.db.View(func(tx *bolt.Tx) error {
		bu := tx.Bucket([]byte("user"))
		if bu == nil {
			return fmt.Errorf("can't find user bucket")
		}

		err := bu.ForEach(func(k, ev []byte) error {
			v, err := d.decrypt(ev)
			if err != nil {
				return fmt.Errorf("can't decrypt client info: %s", err)
			}

			ck, err := decodeCert("$user-cert", v)
			if err != nil {
				return err
			}

			fp(ck)
			return nil
		})

		return err
	})

	return err
}

// hash publickey; we use it as a salt for encryption and also SubjectKeyId
func cksum(pk *ecdsa.PublicKey) []byte {
	h := sha256.New()
	pm := elliptic.Marshal(pk.Curve, pk.X, pk.Y)

	h.Write(pm)
	return h.Sum(nil)
}

// Argon2 KDF
func kdf(pwd []byte, salt []byte) []byte {
	const _Time uint32 = 1
	const _Mem uint32 = 1 * 1024 * 1024
	const _Threads uint8 = 8

	// Generate a 32-byte AES-256 key
	return argon2.IDKey(pwd, salt, _Time, _Mem, _Threads, 32)
}

func kdfstr(pw string, salt []byte) []byte {
	h := sha512.New()
	h.Write([]byte(pw))
	pwd := h.Sum(nil)
	return kdf(pwd, salt)
}
