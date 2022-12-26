package gocrmcl

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
)

// CreateRandomBlsKeys creates an array of random private and their corresponding public keys
func CreateRandomBlsKeys(total int) ([]*PrivateKey, error) {
	blsKeys := make([]*PrivateKey, total)

	for i := 0; i < total; i++ {
		blsKey, err := GenerateBlsKey()
		if err != nil {
			return nil, err
		}

		blsKeys[i] = blsKey
	}

	return blsKeys, nil
}

// MarshalMessageToBigInt marshalls message into two big ints
// first we must convert message bytes to point and than for each coordinate we create big int
func MarshalMessageToBigInt(message []byte) ([2]*big.Int, error) {
	g1, err := hashToG1(message)
	if err != nil {
		return [2]*big.Int{}, err
	}

	buf := g1.SerializeUncompressed()

	return [2]*big.Int{
		new(big.Int).SetBytes(buf[0:32]),
		new(big.Int).SetBytes(buf[32:64]),
	}, nil
}

func hashToG1(message []byte) (*G1, error) {
	fp, err := hashToFp(message, GetDomain(), 2*1)
	if err != nil {
		return nil, err
	}

	g1 := new(G1)

	if err := MapToG1(g1, fp); err != nil {
		return nil, err
	}

	return g1, nil
}

// hashToFp hashes msg to count prime field elements.
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-06#section-5.2
func hashToFp(msg, dst []byte, count int) (*Fp, error) {
	// 128 bits of security
	// L = ceil((ceil(log2(p)) + k) / 8), where k is the security parameter = 128
	Bytes := 1 + (GetFpUnitSize()-1)/8
	L := 16 + Bytes

	lenInBytes := count * L
	pseudoRandomBytes, err := ecc.ExpandMsgXmd(msg, dst, lenInBytes)
	if err != nil {
		return nil, err
	}

	fp := new(Fp)

	fp.SetHashOf(pseudoRandomBytes)

	return fp, nil
}
