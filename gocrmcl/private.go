package gocrmcl

import (
	"crypto/rand"
	"errors"
)

type PrivateKey struct {
	p *Fr
}

// PublicKey returns the public key from the PrivateKey
func (p *PrivateKey) PublicKey() *PublicKey {
	public := new(G2)

	G2Mul(public, ellipticCurveG2, p.p)
	// g2.MulScalar(public, g2.One(), p.p)

	return &PublicKey{p: public}
}

// Sign generates a signature of the given message
func (p *PrivateKey) Sign(message []byte) (*Signature, error) {
	/*
		g := bn254.NewG1()
		signature, err := g.HashToCurveFT(message, GetDomain())
		if err != nil {
			return nil, err
		}
		g.MulScalar(signature, signature, p.p)
	*/
	messagePoint, err := hashToG1(message)
	if err != nil {
		return nil, err
	}

	g1 := new(G1)

	G1Mul(g1, messagePoint, p.p)

	return &Signature{p: g1}, nil
}

// MarshalJSON marshal the key to bytes.
func (p *PrivateKey) MarshalJSON() ([]byte, error) {
	if p.p == nil {
		return nil, errors.New("cannot marshal empty private key")
	}

	return p.p.Serialize(), nil
}

// UnmarshalPrivateKey reads the private key from the given byte array
func UnmarshalPrivateKey(data []byte) (*PrivateKey, error) {
	p := new(Fr)

	if err := p.Deserialize(data); err != nil {
		return nil, err
	}

	return &PrivateKey{p: p}, nil
}

// GenerateBlsKey creates a random private and its corresponding public keys
func GenerateBlsKey() (*PrivateKey, error) {
	s, err := rand.Int(rand.Reader, maxBigInt)
	if err != nil {
		return nil, err
	}

	p := new(Fr)
	p.SetLittleEndian(s.Bytes())

	return &PrivateKey{p: p}, nil
}