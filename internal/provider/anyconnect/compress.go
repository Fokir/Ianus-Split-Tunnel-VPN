package anyconnect

import (
	"bytes"
	"compress/flate"
	"io"
	"sync"
)

// deflateCompressor provides thread-safe DEFLATE compression/decompression for CSTP.
type deflateCompressor struct {
	// Pool of flate.Writer instances to avoid repeated allocation.
	writerPool sync.Pool
}

func newDeflateCompressor() *deflateCompressor {
	return &deflateCompressor{
		writerPool: sync.Pool{
			New: func() any {
				w, _ := flate.NewWriter(nil, flate.DefaultCompression)
				return w
			},
		},
	}
}

// compress compresses data using DEFLATE (RFC 1951).
func (c *deflateCompressor) compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := c.writerPool.Get().(*flate.Writer)
	w.Reset(&buf)
	if _, err := w.Write(data); err != nil {
		c.writerPool.Put(w)
		return nil, err
	}
	if err := w.Close(); err != nil {
		c.writerPool.Put(w)
		return nil, err
	}
	c.writerPool.Put(w)
	return buf.Bytes(), nil
}

// decompress decompresses DEFLATE data.
func (c *deflateCompressor) decompress(data []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(data))
	defer r.Close()
	return io.ReadAll(r)
}
