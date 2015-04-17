package main

import (
	"io"
	"golang.org/x/crypto/nacl/box"
	"fmt"
	"crypto/rand"
)

type SecureReader struct {
	r io.Reader
	priv *[32]byte
	pub *[32]byte
	Nonce [24]byte
}

type SecureWriter struct {
	w io.Writer
	priv *[32]byte
	pub *[32]byte
	Nonce [24]byte
}

type SecureReadWriteCloser struct {
	SecureReader
	SecureWriter
}

func (sr SecureReader) Read(buf []byte) (n int, err error) {
	cyphertext := make([]byte, len(buf)+box.Overhead)
	n, err = sr.r.Read(cyphertext)
	if err != nil {
		return n, err
	}
	cyphertext = cyphertext[:n]

	ret,ok := box.Open(buf[0:0],cyphertext, &sr.Nonce,sr.pub,sr.priv)
	fmt.Printf("alright: %v\n",ok)

	return len(ret), nil
}

func (sw SecureWriter) Write(buf []byte) (n int, err error) {
	ret := box.Seal(nil,buf,&sw.Nonce,sw.pub,sw.priv)

	n, err = sw.w.Write(ret)
	if err != nil {
		return n, err
	}
	return n, nil
}


// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
        sr := SecureReader{
        	r:r,
        	pub: pub,
        	priv: priv,
        }
        _, err := rand.Read(sr.Nonce[:])
        if err != nil {
        	fmt.Printf("Failed to initialize Nonce\n")
        }

        return sr
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
        sw := SecureWriter{
        	w: w,
        	pub: pub,
        	priv: priv,
        }
        _, err := rand.Read(sw.Nonce[:])
        if err != nil {
        	fmt.Printf("Failed to initialize Nonce\n")
        }

        return sw
}