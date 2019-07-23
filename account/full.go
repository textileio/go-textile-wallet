package account

import (
	"bytes"

	libp2pc "github.com/libp2p/go-libp2p-core/crypto"
	pb "github.com/libp2p/go-libp2p-core/crypto/pb"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/textileio/go-textile-wallet/key"
	"github.com/textileio/go-textile/crypto"
	"golang.org/x/crypto/ed25519"
)

// Full represents a full account which can verify and sign signatures.
//
// NOTE: ensure the seed provided is a valid key encoded textile address.
// Some operations will panic otherwise. It's recommended that you create these
// structs through the Parse() method.
type Full struct {
	seed string
}

// Address returns a string encoded version of the public key
func (kp *Full) Address() string {
	return key.MustEncode(key.VersionByteAccountID, kp.publicKey()[:])
}

// Hint returns the last four bytes of the public key
func (kp *Full) Hint() (r [4]byte) {
	copy(r[:], kp.publicKey()[28:])
	return
}

// Seed returns a string encoded version of the private key
func (kp *Full) Seed() (string, error) {
	return kp.seed, nil
}

// ID returns the associated libp2p peer ID
func (kp *Full) ID() (peer.ID, error) {
	pub, err := kp.LibP2PPubKey()
	if err != nil {
		return "", nil
	}
	return peer.IDFromPublicKey(pub)
}

// LibP2PPrivKey returns the private key as a libp2p Key
func (kp *Full) LibP2PPrivKey() (*libp2pc.Ed25519PrivateKey, error) {
	buf := make([]byte, ed25519.PrivateKeySize)
	copy(buf, kp.rawSeed()[:])
	copy(buf[ed25519.PrivateKeySize-ed25519.PublicKeySize:], kp.publicKey()[:])
	pmes := new(pb.PrivateKey)
	pmes.Data = buf
	sk, err := libp2pc.UnmarshalEd25519PrivateKey(pmes.GetData())
	if err != nil {
		return nil, err
	}
	esk, ok := sk.(*libp2pc.Ed25519PrivateKey)
	if !ok {
		return nil, nil
	}
	return esk, nil
}

// LibP2PPubKey returns the public key as a libp2p Key
func (kp *Full) LibP2PPubKey() (*libp2pc.Ed25519PublicKey, error) {
	pmes := new(pb.PublicKey)
	pmes.Data = kp.publicKey()[:]
	pk, err := libp2pc.UnmarshalEd25519PublicKey(pmes.GetData())
	if err != nil {
		return nil, err
	}
	epk, ok := pk.(*libp2pc.Ed25519PublicKey)
	if !ok {
		return nil, nil
	}
	return epk, nil
}

// Verify that 'sig' is the signed hash of 'input'
func (kp *Full) Verify(input []byte, sig []byte) error {
	if len(sig) != ed25519.PrivateKeySize {
		return ErrInvalidSignature
	}
	var asig [ed25519.PrivateKeySize]byte
	copy(asig[:], sig[:])

	if !ed25519.Verify(kp.publicKey(), input, asig[:]) {
		return ErrInvalidSignature
	}
	return nil
}

// Sign input bytes
func (kp *Full) Sign(input []byte) ([]byte, error) {
	_, priv := kp.keys()
	return ed25519.Sign(priv, input)[:], nil
}

// Encrypt input bytes
func (kp *Full) Encrypt(input []byte) ([]byte, error) {
	pub, err := kp.LibP2PPubKey()
	if err != nil {
		return nil, err
	}
	return crypto.Encrypt(pub, input)
}

// Decrypt input bytes
func (kp *Full) Decrypt(input []byte) ([]byte, error) {
	priv, err := kp.LibP2PPrivKey()
	if err != nil {
		return nil, err
	}
	return crypto.Decrypt(priv, input)
}

func (kp *Full) publicKey() ed25519.PublicKey {
	pub, _ := kp.keys()
	return pub
}

func (kp *Full) keys() (ed25519.PublicKey, ed25519.PrivateKey) {
	reader := bytes.NewReader(kp.rawSeed())
	pub, priv, err := ed25519.GenerateKey(reader)
	if err != nil {
		panic(err)
	}
	return pub, priv
}

func (kp *Full) rawSeed() []byte {
	return key.MustDecode(key.VersionByteSeed, kp.seed)
}
