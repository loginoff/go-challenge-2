package main

import (
	"io"
	"golang.org/x/crypto/nacl/box"
	"fmt"
	"crypto/rand"
)

const (
	NonceLength = 24
	HeaderLength = box.Overhead + NonceLength
)
type SecureReader struct {
	r io.Reader
	priv *[32]byte
	pub *[32]byte
	receivebuf [2048]byte
	nonce [24]byte
}

type SecureWriter struct {
	w io.Writer
	priv *[32]byte
	pub *[32]byte
	sendbuf [2048]byte
	nonce [24]byte
}

type SecureSocket struct {
	io.Reader
	io.Writer
	io.Closer
}

func (sr *SecureReader) Read(buf []byte) (n int, err error) {
	// fmt.Println("----------Starting read---------")
	// fmt.Printf("Reader pub %v\n",sr.pub)
	// fmt.Printf("Reader priv %v\n",sr.priv)
	n, err = sr.r.Read(sr.receivebuf[:])
	if err != nil {
		return n, err
	}
	// fmt.Printf("read N: %d\n",n)
	copy(sr.nonce[:],sr.receivebuf[:24])
	cyphertext := sr.receivebuf[NonceLength:n]
	// fmt.Printf("len cyphertext %d\n",n)
	// fmt.Printf("cyphertext: %v\n",cyphertext)

	_,ok := box.Open(buf[0:0],cyphertext, &sr.nonce,sr.pub,sr.priv)
	fmt.Printf("alright: %v\n",ok)
	// fmt.Printf("%v\n",ret)
	// fmt.Println("----------Ending read---------")

	return n-box.Overhead, nil
}

func (sw *SecureWriter) Write(buf []byte) (n int, err error) {
	_, err = rand.Read(sw.nonce[:])
	copy(sw.sendbuf[:24],sw.nonce[:])
	box.Seal(sw.sendbuf[:24],buf,&sw.nonce,sw.pub,sw.priv)
	// fmt.Printf("data written %v\n",ret)

	n, err = sw.w.Write(sw.sendbuf[:HeaderLength+len(buf)])
	// fmt.Printf("write N: %d\n",n)
	if err != nil {
		return n, err
	}
	// fmt.Println("----------Ending write---------")
	return n-HeaderLength, nil
}


// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
        sr := SecureReader{
        	r:r,
        	priv: priv,
        	pub: pub,
        }
        // _, err := rand.Read(sr.Nonce[:])
        // if err != nil {
        // 	fmt.Printf("Failed to initialize Nonce\n")
        // }

        return &sr
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
        sw := SecureWriter{
        	w: w,
        	priv: priv,
        	pub: pub,
        }
        // _, err := rand.Read(sw.Nonce[:])
        // if err != nil {
        // 	fmt.Printf("Failed to initialize Nonce\n")
        // }

        return &sw
}