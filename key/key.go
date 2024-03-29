package key

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/mr-tron/base58/base58"
	"github.com/textileio/go-textile-wallet/crc16"
)

// ErrInvalidVersionByte is returned when the version byte from a provided
// key-encoded string is not one of the valid values.
var ErrInvalidVersionByte = fmt.Errorf("invalid version byte")

// VersionByte represents one of the possible prefix values for a Key base
// string--the string the when encoded using base58 yields a final Key.
type VersionByte byte

const (
	// VersionByteAccountID is the version byte used for encoded textile address
	VersionByteAccountID VersionByte = 0xdd // Base58-encodes to 'P...'
	// VersionByteSeed is the version byte used for encoded textile seed
	VersionByteSeed = 0xff // Base58-encodes to 'S...'
)

// Decode decodes the provided Key into a raw value, checking the checksum
// and ensuring the expected VersionByte (the version parameter) is the value
// actually encoded into the provided src string.
func Decode(expected VersionByte, src string) ([]byte, error) {
	if err := checkValidVersionByte(expected); err != nil {
		return nil, err
	}

	raw, err := decodeString(src)
	if err != nil {
		return nil, err
	}

	// decode into components
	version := VersionByte(raw[0])
	vp := raw[0 : len(raw)-2]
	payload := raw[1 : len(raw)-2]
	checksum := raw[len(raw)-2:]

	// ensure version byte is expected
	if version != expected {
		return nil, ErrInvalidVersionByte
	}

	// ensure checksum is valid
	if err := crc16.Validate(vp, checksum); err != nil {
		return nil, err
	}

	// if we made it through the gaunlet, return the decoded value
	return payload, nil
}

// MustDecode is like Decode, but panics on error
func MustDecode(expected VersionByte, src string) []byte {
	d, err := Decode(expected, src)
	if err != nil {
		panic(err)
	}
	return d
}

// Encode encodes the provided data to a Key, using the provided version
// byte.
func Encode(version VersionByte, src []byte) (string, error) {
	if err := checkValidVersionByte(version); err != nil {
		return "", err
	}

	var raw bytes.Buffer

	// write version byte
	if err := binary.Write(&raw, binary.LittleEndian, version); err != nil {
		return "", err
	}

	// write payload
	if _, err := raw.Write(src); err != nil {
		return "", err
	}

	// calculate and write checksum
	checksum := crc16.Checksum(raw.Bytes())
	if _, err := raw.Write(checksum); err != nil {
		return "", err
	}

	result := base58.FastBase58Encoding(raw.Bytes())
	return result, nil
}

// MustEncode is like Encode, but panics on error
func MustEncode(version VersionByte, src []byte) string {
	e, err := Encode(version, src)
	if err != nil {
		panic(err)
	}
	return e
}

// Version extracts and returns the version byte from the provided source
// string.
func Version(src string) (VersionByte, error) {
	raw, err := decodeString(src)
	if err != nil {
		return VersionByte(0), err
	}

	return VersionByte(raw[0]), nil
}

// checkValidVersionByte returns an error if the provided value
// is not one of the defined valid version byte constants.
func checkValidVersionByte(version VersionByte) error {
	if version == VersionByteAccountID {
		return nil
	}

	if version == VersionByteSeed {
		return nil
	}

	return ErrInvalidVersionByte
}

// decodeString decodes a base58 string into the raw bytes, and ensures it could
// potentially be key encoded (i.e. it has both a version byte and a
// checksum, neither of which are explicitly checked by this func)
func decodeString(src string) ([]byte, error) {
	raw, err := base58.FastBase58Decoding(src)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("base58 decode failed: %s", err))
	}

	if len(raw) < 3 {
		return nil, fmt.Errorf(fmt.Sprintf("encoded value is %d bytes; minimum valid length is 3", len(raw)))
	}

	return raw, nil
}
