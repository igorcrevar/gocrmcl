package gocrmcl

import (
	"encoding/json"
	"errors"
	"math/big"
)

// PublicKey represents bls public key
type PublicKey struct {
	p *G2
}

// aggregate adds the given public keys
func (p *PublicKey) aggregate(next *PublicKey) *PublicKey {
	newp := new(G2)

	if p.p != nil {
		if next.p != nil {
			G2Add(newp, p.p, next.p)
		} else {
			G2Add(newp, newp, p.p)
		}
	} else if next.p != nil {
		G2Add(newp, newp, next.p)
	}

	return &PublicKey{p: newp}
}

// Marshal marshal the key to bytes.
func (p *PublicKey) Marshal() []byte {
	if p.p == nil {
		return nil
	}

	return p.p.SerializeUncompressed()
}

// MarshalJSON implements the json.Marshaler interface.
func (p *PublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.Marshal())
}

// UnmarshalJSON implements the json.Marshaler interface.
func (p *PublicKey) UnmarshalJSON(b []byte) error {
	var d []byte

	err := json.Unmarshal(b, &d)
	if err != nil {
		return err
	}

	pk, err := UnmarshalPublicKey(d)
	if err != nil {
		return err
	}

	p.p = pk.p

	return nil
}

// UnmarshalPublicKey reads the public key from the given byte array
func UnmarshalPublicKey(raw []byte) (*PublicKey, error) {
	if len(raw) == 0 {
		return nil, errors.New("cannot unmarshal public key from empty slice")
	}

	g2 := new(G2)

	if err := g2.DeserializeUncompressed(raw); err != nil {
		return nil, err
	}

	return &PublicKey{p: g2}, nil
}

// ToBigInt converts public key to 4 big ints
func (p PublicKey) ToBigInt() [4]*big.Int {
	bytes := p.Marshal()

	res := [4]*big.Int{
		new(big.Int).SetBytes(bytes[32:64]),
		new(big.Int).SetBytes(bytes[0:32]),
		new(big.Int).SetBytes(bytes[96:128]),
		new(big.Int).SetBytes(bytes[64:96]),
	}

	return res
}

// UnmarshalPublicKeyFromBigInt unmarshals public key from 4 big ints
// Order of coordinates is [A.Y, A.X, B.Y, B.X]
func UnmarshalPublicKeyFromBigInt(b [4]*big.Int) (*PublicKey, error) {
	const size = 32

	var pubKeyBuf []byte

	pt1 := PadLeftOrTrim(b[1].Bytes(), size)
	pt2 := PadLeftOrTrim(b[0].Bytes(), size)
	pt3 := PadLeftOrTrim(b[3].Bytes(), size)
	pt4 := PadLeftOrTrim(b[2].Bytes(), size)

	pubKeyBuf = append(pubKeyBuf, pt1...)
	pubKeyBuf = append(pubKeyBuf, pt2...)
	pubKeyBuf = append(pubKeyBuf, pt3...)
	pubKeyBuf = append(pubKeyBuf, pt4...)

	return UnmarshalPublicKey(pubKeyBuf)
}

// aggregatePublicKeys calculates P1 + P2 + ...
func aggregatePublicKeys(pubs []*PublicKey) *PublicKey {
	newp := new(G2)

	for _, x := range pubs {
		if x.p != nil {
			G2Add(newp, newp, x.p)
		}
	}

	return &PublicKey{p: newp}
}
