package account

import (
	libp2pc "github.com/libp2p/go-libp2p-core/crypto"
	pb "github.com/libp2p/go-libp2p-core/crypto/pb"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/textileio/go-textile-wallet/key"
	"github.com/textileio/go-textile/crypto"
	"golang.org/x/crypto/ed25519"
)

// FromAddress represents an account to which only the address is known. This Account
// can verify signatures, but cannot sign them.
//
// NOTE: ensure the address provided is a valid key encoded textile address.
// Some operations will panic otherwise. It's recommended that you create these
// structs through the Parse() method.
type FromAddress struct {
	address string
}

// Address returns a string encoded version of the public key
func (kp *FromAddress) Address() string {
	return kp.address
}

// Hint returns the last four bytes of the public key
func (kp *FromAddress) Hint() (r [4]byte) {
	copy(r[:], kp.publicKey()[28:])
	return
}

// Seed returns an error because an address-based account does not
// have access to the private key
func (kp *FromAddress) Seed() (string, error) {
	return "", ErrNoSeed
}

// ID returns the associated libp2p peer ID
func (kp *FromAddress) ID() (peer.ID, error) {
	pub, err := kp.LibP2PPubKey()
	if err != nil {
		return "", nil
	}
	return peer.IDFromPublicKey(pub)
}

// LibP2PPrivKey returns an error because an address-based account does not
// have access to the private key
func (kp *FromAddress) LibP2PPrivKey() (*libp2pc.Ed25519PrivateKey, error) {
	return nil, ErrCannotSign
}

// LibP2PPubKey returns the public key as a libp2p Key
func (kp *FromAddress) LibP2PPubKey() (*libp2pc.Ed25519PublicKey, error) {
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
func (kp *FromAddress) Verify(input []byte, sig []byte) error {
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

// Sign returns an error because an address-based account does not
// have access to the private key
func (kp *FromAddress) Sign(input []byte) ([]byte, error) {
	return nil, ErrCannotSign
}

// Encrypt input bytes
func (kp *FromAddress) Encrypt(input []byte) ([]byte, error) {
	pub, err := kp.LibP2PPubKey()
	if err != nil {
		return nil, err
	}
	return crypto.Encrypt(pub, input)
}

// Decrypt returns an error because an address-based account does not
// have access to the private key
func (kp *FromAddress) Decrypt(input []byte) ([]byte, error) {
	return nil, ErrCannotDecrypt
}

func (kp *FromAddress) publicKey() ed25519.PublicKey {
	bytes := key.MustDecode(key.VersionByteAccountID, kp.address)
	var result [ed25519.PublicKeySize]byte

	copy(result[:], bytes)

	slice := result[:]
	return slice
}
