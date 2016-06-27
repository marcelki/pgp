package pgp

import (
	"bytes"
	"fmt"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/clearsign"
	"golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/packet"
	"io/ioutil"
)

// ArmoredKeyToEntity returns a entity from the given byte slice
//
// TODO: decrypt private key if its encrypted
func ArmoredKeyToEntity(key []byte) (*openpgp.Entity, error) {
	rd := bytes.NewReader(key)
	block, err := armor.Decode(rd)
	if err != nil {
		return nil, err
	}
	entity, err := openpgp.ReadEntity(packet.NewReader(block.Body))
	if err != nil {
		return nil, fmt.Errorf("Couldn't read the armored key", err)
	}
	return entity, err
}

// ClearSignMessage generates a clear-signed message using the private key from the given entity.
func ClearSignMessage(message []byte, entity *openpgp.Entity) ([]byte, error) {
	out := &bytes.Buffer{}

	if entity.PrivateKey == nil {
		return nil, fmt.Errorf("No private key in entity")
	}
	wc, err := clearsign.Encode(out, entity.PrivateKey, nil)
	if err != nil {
		return nil, err
	}
	_, err = wc.Write(message)
	wc.Close()
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// DecryptMessage decrypts a armored message using the given entity
func DecryptMessage(message []byte, entity *openpgp.Entity) ([]byte, error) {
	rd := bytes.NewReader(message)
	keyring := openpgp.EntityList{entity}

	block, err := armor.Decode(rd)
	if err != nil {
		return nil, err
	}
	md, err := openpgp.ReadMessage(block.Body, keyring, nil, nil)
	if err != nil {
		return nil, err
	}
	if !md.IsEncrypted {
		return message, fmt.Errorf("message is not encrypted")
	}
	out, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DetachSignMessage generates a amored detached sign message using a entity
func DetachSignMessage(message []byte, entity *openpgp.Entity) ([]byte, error) {
	rd := bytes.NewReader(message)
	out := &bytes.Buffer{}

	err := openpgp.ArmoredDetachSignText(out, entity, rd, nil)
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// EncryptMessage encrypts a message to a number of entities and returns the encrypted armored message
func EncryptMessage(message []byte, entities []*openpgp.Entity) ([]byte, error) {
	out := &bytes.Buffer{}
	enc, err := armor.Encode(out, "PGP MESSAGE", nil)
	if err != nil {
		return nil, err
	}
	wc, err := openpgp.Encrypt(enc, entities, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	_, err = wc.Write(message)
	wc.Close()
	if err != nil {
		return nil, err
	}
	if err = enc.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// SerializeEntity serializes both the public and private key from a entity.
// Notice: serializing a encrypted private key is not yet supported!
func SerializeEntity(entity *openpgp.Entity) ([]byte, error) {
	out := &bytes.Buffer{}
	if entity.PrimaryKey == nil && entity.PrimaryKey == nil {
		return nil, fmt.Errorf("pgp: no key found")
	}
	if entity.PrivateKey != nil {
		w, err := armor.Encode(out, openpgp.PrivateKeyType, nil)
		if err != nil {
			return nil, err
		}
		err = entity.SerializePrivate(w, nil)
		w.Close()
		if err != nil {
			// serializing encrypted private key is not yet supported!
			if _, ok := err.(errors.InvalidArgumentError); ok {
				out.Reset()
			} else {
				return nil, err
			}
		}
		out.WriteByte('\n')
	}
	if entity.PrimaryKey != nil {
		w, err := armor.Encode(out, openpgp.PublicKeyType, nil)
		if err != nil {
			return nil, err
		}
		err = entity.Serialize(w)
		w.Close()
		if err != nil {
			return nil, err
		}
		out.WriteByte('\n')
	}
	return out.Bytes(), nil
}
