package wallet

import (
	"fmt"

	"github.com/textileio/go-textile-wallet/account"
	"github.com/tyler-smith/go-bip39"
)

// ErrInvalidWordCount indicates that the given word count is invalid
var ErrInvalidWordCount = fmt.Errorf("invalid word count (must be 12, 15, 18, 21, or 24)")

// WordCount represents the number of words in a mnemonic
type WordCount int

const (
	// TwelveWords corresponds to an entropy size of 128
	TwelveWords WordCount = 12
	// FifteenWords corresponds to an entropy size of 160
	FifteenWords WordCount = 15
	// EighteenWords corresponds to an entropy size of 192
	EighteenWords WordCount = 18
	// TwentyOneWords corresponds to an entropy size of 224
	TwentyOneWords WordCount = 21
	// TwentyFourWords corresponds to an entropy size of 256
	TwentyFourWords WordCount = 24
)

// NewWordCount creates a standard word count from the given int
func NewWordCount(count int) (*WordCount, error) {
	var wc WordCount
	switch count {
	case 12:
		wc = TwelveWords
	case 15:
		wc = FifteenWords
	case 18:
		wc = EighteenWords
	case 21:
		wc = TwentyOneWords
	case 24:
		wc = TwentyFourWords
	default:
		return nil, ErrInvalidWordCount
	}
	return &wc, nil
}

// EntropySize returns length of the word counts random entropy bytes
func (w WordCount) EntropySize() int {
	switch w {
	case TwelveWords:
		return 128
	case FifteenWords:
		return 160
	case EighteenWords:
		return 192
	case TwentyOneWords:
		return 224
	case TwentyFourWords:
		return 256
	default:
		return 256
	}
}

// Wallet is a BIP32 Hierarchical Deterministic Wallet based on stellar's
// implementation of https://github.com/satoshilabs/slips/blob/master/slip-0010.md,
// https://github.com/stellar/stellar-protocol/pull/63
type Wallet struct {
	RecoveryPhrase string
}

// FromWordCount creates a wallet with random entropy bytes of the bit size associated with the given word count
func FromWordCount(wordCount int) (*Wallet, error) {
	wcount, err := NewWordCount(wordCount)
	if err != nil {
		return nil, err
	}

	return FromEntropy(wcount.EntropySize())
}

// FromMnemonic creates a wallet with random entropy bytes of the given bit size
func FromEntropy(entropySize int) (*Wallet, error) {
	entropy, err := bip39.NewEntropy(entropySize)
	if err != nil {
		return nil, err
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, err
	}
	return &Wallet{RecoveryPhrase: mnemonic}, nil
}

// FromMnemonic creates a wallet directly from a mnemonic phrase
func FromMnemonic(mnemonic string) *Wallet {
	return &Wallet{RecoveryPhrase: mnemonic}
}

// To understand how this works, refer to the living document:
// https://paper.dropbox.com/doc/Hierarchical-Deterministic-Wallets--Ae0TOjGObNq_zlyYFh7Ea0jNAQ-t7betWDTvXtK6qqD8HXKf
func (w *Wallet) DeriveAccount(index int, passphrase string) (*account.Full, error) {
	seed, err := bip39.NewSeedWithErrorChecking(w.RecoveryPhrase, passphrase)
	if err != nil {
		if err == bip39.ErrInvalidMnemonic {
			return nil, fmt.Errorf("invalid mnemonic phrase")
		}
		return nil, err
	}
	masterKey, err := DeriveForPath(TextileAccountPrefix, seed)
	if err != nil {
		return nil, err
	}
	key, err := masterKey.Derive(FirstHardenedIndex + uint32(index))
	if err != nil {
		return nil, err
	}
	return account.FromRawSeed(key.RawSeed())
}
