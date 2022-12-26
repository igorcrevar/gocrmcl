package gocrmcl

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_PrivateMarshal(t *testing.T) {
	t.Parallel()

	blsKey, err := GenerateBlsKey() // structure which holds private/public key pair
	require.NoError(t, err)

	// marshal public key
	privateKeyMarshalled, err := blsKey.MarshalJSON()
	require.NoError(t, err)
	// recover private and public key
	blsKeyUnmarshalled, err := UnmarshalPrivateKey(privateKeyMarshalled)
	require.NoError(t, err)

	assert.Equal(t, blsKey, blsKeyUnmarshalled)
}

func Test_Hello(t *testing.T) {
	message := mustDecodeBytes("abcd")

	// in big endian format, this is tricky!
	pub, err := UnmarshalPublicKey(mustDecodeBytes("234a5bd47557d86e76eb95d6e7d41f885f24fe450493bec98babd015728a114e18414e8b403c7e67cdd5b51d41952727d8a28de3734ee4a2114b8c282ce5643f22dd40a86c0efa6719c04ccaa78da913b89efe0c05916eaaa3ff1706367313702a1821de9d934b99c2bbf20bdf25ee9a98d6ef34c539f8880a06637eea2cbfa7"))
	if err != nil {
		panic(err)
	}

	sig, err := UnmarshalSignature(mustDecodeBytes("2583e262990c4ed1d68077cf180d4c3f71ee397d4ac1208f9aa0c114f31ee86e2f16020f0981a38d7d40d96b2dd3e0152a5003ff591e5a1526d0251a7ab56fcb"))
	if err != nil {
		panic(err)
	}

	v := sig.Verify(pub, message)
	require.True(t, v)
}

func mustDecodeBytes(str string) []byte {
	buf, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}

	return buf
}