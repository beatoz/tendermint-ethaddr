package secp256k1

import (
	"crypto/sha256"
	"encoding/hex"
	secp256k1 "github.com/btcsuite/btcd/btcec"
	"github.com/tendermint/tendermint/crypto"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
	"strings"
)

func decompressPubKey(compressedHex string) ([]byte, error) {
	pubKeyBytes, err := hex.DecodeString(compressedHex)
	if err != nil {
		return nil, err
	}
	pubKey, err := secp256k1.ParsePubKey(pubKeyBytes, secp256k1.S256())
	if err != nil {
		return nil, err
	}
	return pubKey.SerializeUncompressed(), nil
}

// Ethereum style address
func ethAddress(pubKey []byte) crypto.Address {
	if len(pubKey) != PubKeySize {
		panic("length of pubkey is incorrect")
	}

	uncompressedPubKey, _ := decompressPubKey(hex.EncodeToString(pubKey))

	hash := sha3.NewLegacyKeccak256()
	hash.Write(uncompressedPubKey[1:]) // skip 0x04 prefix
	addr := hash.Sum(nil)[12:]         // last 20 bytes
	return crypto.Address(addr)
}

// Bitcoin style address
func btcAddress(pubKey []byte) crypto.Address {
	if len(pubKey) != PubKeySize {
		panic("length of pubkey is incorrect")
	}
	hasherSHA256 := sha256.New()
	_, _ = hasherSHA256.Write(pubKey) // does not error
	sha := hasherSHA256.Sum(nil)

	hasherRIPEMD160 := ripemd160.New()
	_, _ = hasherRIPEMD160.Write(sha) // does not error

	return crypto.Address(hasherRIPEMD160.Sum(nil))
}

func toChecksumAddress(addr string) string {
	addr = strings.ToLower(addr)
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(addr))
	hashSum := hash.Sum(nil)

	result := ""
	for i := 0; i < len(addr); i++ {
		c := addr[i]
		if c >= '0' && c <= '9' {
			result += string(c)
			continue
		}
		// 문자가 알파벳일 경우: 해시값에 따라 대소문자 결정
		if (hashSum[i/2]>>uint(4*(1-i%2)))&0xF >= 8 {
			result += strings.ToUpper(string(c))
		} else {
			result += string(c)
		}
	}
	return result
}
