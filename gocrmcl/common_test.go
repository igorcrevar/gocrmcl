package gocrmcl

import (
	"testing"

	"github.com/stretchr/testify/require"
)

/*
sudo apt install libgmp-dev
make -j4

env LD_LIBRARY_PATH=/home/igor/Documents/gocr-mcl/mcl/lib go test
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/igor/Documents/gocr-mcl/mcl/lib
*/

func TestCommon_Init(t *testing.T) {
	require.NoError(t, InitCurve(CurveFp254BNb))
}
