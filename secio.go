package main

import (
	"io"
)

type SecureReader struct {
	r io.Reader
}

type SecureWriter struct {
	w io.Writer
}

func (sr SecureReader) Read(buf []byte) (n int, err error) {
	n, err = sr.r.Read(buf)
	if err != nil {
		return n, err
	}

	return n, nil
}

func (sw SecureWriter) Write(buf []byte) (n int, err error) {
	n, err = sw.w.Write(buf)
	if err != nil {
		return n, err
	}
	return n, nil
}


// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
        return SecureReader{r:r}
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
        return SecureWriter{w: w}
}