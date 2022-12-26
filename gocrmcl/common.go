package gocrmcl

import (
	"encoding/hex"
	"math/big"
)

var (
	domain, _ = hex.DecodeString("508e30424791cb9a71683381558c3da1979b6fa423b2d6db1396b1d94d7c4a78")

	maxBigInt, _    = new(big.Int).SetString("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16)
	ellipticCurveG2 *G2

	qCoef = []uint64{
		0x8e83b5d102bc2026, 0xdceb1935497b0172, 0xfbb8264797811adf, 0x19573841af96503b,
		0xafb4737da84c6140, 0x6043dd5a5802d8c4, 0x09e950fc52a02f86, 0x14fef0833aea7b6b,
		0x619dfa9d886be9f6, 0xfe7fd297f59e9b78, 0xff9e1a62231b7dfe, 0x28fd7eebae9e4206,
		0x64095b56c71856ee, 0xdc57f922327d3cbb, 0x55f935be33351076, 0x0da4a0e693fd6482,
		0xd35d438dc58f0d9d, 0x0a78eb28f5c70b3d, 0x666ea36f7879462c, 0x0e0a77c19a07df2f,
		0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
	}
)

func init() {
	if err := InitCurve(CurveFp254BNb); err != nil {
		panic(err)
	}

	// v1, _ := new(big.Int).SetString("10857046999023057135944570762232829481370756359578518086990519993285655852781", 10)
	// v2, _ := new(big.Int).SetString("11559732032986387107991004021392285783925812861821192530917403151452391805634", 10)
	// v3, _ := new(big.Int).SetString("8495653923123431417604973247489272438418190587263600148770280649306958101930", 10)
	// v4, _ := new(big.Int).SetString("4082367875863433681332203403145435568316851327593401208105741076214120093531", 10)
	// pk, _ := UnmarshalPublicKeyFromBigInt([4]*big.Int{v1, v2, v3, v4})
	ellipticCurveG2 = new(G2)
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
