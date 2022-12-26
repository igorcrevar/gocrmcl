package gocrmcl

import (
	"crypto/sha256"
	"errors"
	"math/big"
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
	/*
		hashRes, err := hashToFpXMDSHA256(message, GetDomain(), 2)
		if err != nil {
			return nil, err
		}

		g1, g2 := new(G1), new(G1)
		u0, u1 := hashRes[0], hashRes[1]


		if err := MapToG1(g1, u0); err != nil {
			return nil, err
		}

		if err := MapToG1(g2, u1); err != nil {
			return nil, err
		}

		G1Add(g1, g2, g2)

		return g1, nil
	*/
	g1 := new(G1)
	if err := g1.HashAndMapTo(message); err != nil {
		return nil, err
	}

	return g1, nil
}

func hashToFpXMDSHA256(msg []byte, domain []byte, count int) ([]*Fp, error) {
	randBytes, err := expandMsgSHA256XMD(msg, domain, count*48)
	if err != nil {
		return nil, err
	}
	els := make([]*Fp, count)
	for i := 0; i < count; i++ {
		if err := els[i].Deserialize(randBytes[i*48 : (i+1)*48]); err != nil {
			return nil, err
		}
	}
	return els, nil
}

func expandMsgSHA256XMD(msg []byte, domain []byte, outLen int) ([]byte, error) {
	h := sha256.New()
	if len(domain) > 255 {
		return nil, errors.New("invalid domain length")
	}
	domainLen := uint8(len(domain))
	// DST_prime = DST || I2OSP(len(DST), 1)
	// b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
	_, _ = h.Write(make([]byte, h.BlockSize()))
	_, _ = h.Write(msg)
	_, _ = h.Write([]byte{uint8(outLen >> 8), uint8(outLen)})
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(domain)
	_, _ = h.Write([]byte{domainLen})
	b0 := h.Sum(nil)

	// b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
	h.Reset()
	_, _ = h.Write(b0)
	_, _ = h.Write([]byte{1})
	_, _ = h.Write(domain)
	_, _ = h.Write([]byte{domainLen})
	b1 := h.Sum(nil)

	// b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
	ell := (outLen + h.Size() - 1) / h.Size()
	bi := b1
	out := make([]byte, outLen)
	for i := 1; i < ell; i++ {
		h.Reset()
		// b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
		tmp := make([]byte, h.Size())
		for j := 0; j < h.Size(); j++ {
			tmp[j] = b0[j] ^ bi[j]
		}
		_, _ = h.Write(tmp)
		_, _ = h.Write([]byte{1 + uint8(i)})
		_, _ = h.Write(domain)
		_, _ = h.Write([]byte{domainLen})

		// b_1 || ... || b_(ell - 1)
		copy(out[(i-1)*h.Size():i*h.Size()], bi[:])
		bi = h.Sum(nil)
	}
	// b_ell
	copy(out[(ell-1)*h.Size():], bi[:])
	return out[:outLen], nil
}
