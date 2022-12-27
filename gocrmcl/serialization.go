package gocrmcl

import (
	"fmt"
	"math/big"
)

func G1ToBytes(p *G1) []byte {
	bgs := G1ToBigInt(p)

	a, b := padLeftOrTrim(bgs[0].Bytes(), 32), padLeftOrTrim(bgs[1].Bytes(), 32)

	res := make([]byte, len(a)+len(b))
	copy(res, a)
	copy(res[len(a):], b)

	return res
}

func G2ToBytes(p *G2) []byte {
	bgs := G2ToBigInt(p)

	a, b := padLeftOrTrim(bgs[0].Bytes(), 32), padLeftOrTrim(bgs[1].Bytes(), 32)
	c, d := padLeftOrTrim(bgs[2].Bytes(), 32), padLeftOrTrim(bgs[3].Bytes(), 32)

	res := make([]byte, len(a)+len(b)+len(c)+len(d))
	copy(res, b)
	copy(res[len(b):], a)
	copy(res[len(a)+len(b):], d)
	copy(res[len(a)+len(b)+len(d):], c)

	return res
}

func G1ToBigInt(p *G1) [2]*big.Int {
	G1Normalize(p, p)

	return [2]*big.Int{
		new(big.Int).SetBytes(reverse(p.X.Serialize())),
		new(big.Int).SetBytes(reverse(p.Y.Serialize())),
	}
}

func G2ToBigInt(p *G2) [4]*big.Int {
	G2Normalize(p, p)

	a, b := reverse(p.X.Serialize()), reverse(p.Y.Serialize())

	return [4]*big.Int{
		new(big.Int).SetBytes(a[32:]),
		new(big.Int).SetBytes(a[:32]),
		new(big.Int).SetBytes(b[32:]),
		new(big.Int).SetBytes(b[:32]),
	}
}

func BytesToBigInt2(bytes []byte) ([2]*big.Int, error) {
	if len(bytes) != 64 {
		return [2]*big.Int{}, fmt.Errorf("expect length 64 but got %d", len(bytes))
	}

	return [2]*big.Int{
		new(big.Int).SetBytes(bytes[:32]),
		new(big.Int).SetBytes(bytes[32:]),
	}, nil
}

func BytesToBigInt4(bytes []byte) ([4]*big.Int, error) {
	if len(bytes) != 128 {
		return [4]*big.Int{}, fmt.Errorf("expect length 128 but got %d", len(bytes))
	}

	return [4]*big.Int{
		new(big.Int).SetBytes(bytes[32:64]),
		new(big.Int).SetBytes(bytes[:32]),
		new(big.Int).SetBytes(bytes[96:]),
		new(big.Int).SetBytes(bytes[64:96]),
	}, nil
}

func G1FromBigInt(p [2]*big.Int) (*G1, error) {
	g1 := new(G1)
	str := fmt.Sprintf("1 %s %s", p[0].String(), p[1].String())

	if err := g1.SetString(str, 10); err != nil {
		return nil, err
	}

	return g1, nil
}

func G2FromBigInt(p [4]*big.Int) (*G2, error) {
	g2 := new(G2)
	str := fmt.Sprintf("1 %s %s %s %s", p[0], p[1], p[2], p[3]) // fmt.Sprintf("%x", p[0])

	if err := g2.SetString(str, 10); err != nil {
		return nil, err
	}

	return g2, nil
}

func reverse(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}

	return s
}

func padLeftOrTrim(bb []byte, size int) []byte {
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
