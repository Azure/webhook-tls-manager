package certificates

import (
	"encoding/pem"
	"io"
)

type PemTrasformer interface {
	encodeFunc(out io.Writer, b *pem.Block) error
}
