package gocrmcl

import (
	"encoding/hex"
	"math/big"
)

var (
	domain, _ = hex.DecodeString("508e30424791cb9a71683381558c3da1979b6fa423b2d6db1396b1d94d7c4a78")

	maxBigInt, _    = new(big.Int).SetString("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16)
	ellipticCurveG2 *G2
)

func init() {
	if err := InitCurve(CurveFp254BNb); err != nil {
		panic(err)
	}

	v1, _ := new(big.Int).SetString("10857046999023057135944570762232829481370756359578518086990519993285655852781", 10)
	v2, _ := new(big.Int).SetString("11559732032986387107991004021392285783925812861821192530917403151452391805634", 10)
	v3, _ := new(big.Int).SetString("8495653923123431417604973247489272438418190587263600148770280649306958101930", 10)
	v4, _ := new(big.Int).SetString("4082367875863433681332203403145435568316851327593401208105741076214120093531", 10)
	pk, _ := UnmarshalPublicKeyFromBigInt([4]*big.Int{v1, v2, v3, v4})
	ellipticCurveG2 = pk.p
}

// Returns bls/bn254 domain
func GetDomain() []byte {
	return domain
}

// colects public keys from the BlsKeys
func collectPublicKeys(keys []*PrivateKey) []*PublicKey {
	pubKeys := make([]*PublicKey, len(keys))

	for i, key := range keys {
		pubKeys[i] = key.PublicKey()
	}

	return pubKeys
}

func PadLeftOrTrim(bb []byte, size int) []byte {
	l := len(bb)
	if l == size {
		return bb
	}

	if l > size {
		return bb[l-size:]
	}

	tmp := make([]byte, size)
	copy(tmp[size-l:], bb)

	return tmp
}
