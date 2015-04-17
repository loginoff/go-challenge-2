package main

import (
	"io"
	"golang.org/x/crypto/nacl/box"
	"fmt"
	// "crypto/rand"
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

type SecureSocket struct {
	io.Reader
	io.Writer
	io.Closer
}

func (sr *SecureReader) Read(buf []byte) (n int, err error) {
	// fmt.Println("----------Starting read---------")
	// fmt.Printf("Reader pub %v\n",sr.pub)
	// fmt.Printf("Reader priv %v\n",sr.priv)
	cyphertext := make([]byte, len(buf)+box.Overhead)
	n, err = sr.r.Read(cyphertext)
	if err != nil {
		return n, err
	}
	cyphertext = cyphertext[:n]
	// fmt.Printf("len cyphertext %d\n",n)
	// fmt.Printf("cyphertext: %v\n",cyphertext)

	_,ok := box.Open(buf[0:0],cyphertext, &sr.Nonce,sr.pub,sr.priv)
	fmt.Printf("alright: %v\n",ok)
	// fmt.Printf("%v\n",ret)
	// fmt.Println("----------Ending read---------")

	return n-box.Overhead, nil
}

func (sw *SecureWriter) Write(buf []byte) (n int, err error) {
	// fmt.Println("----------Starting write---------")
	// fmt.Printf("Writer pub %v\n",sw.pub)
	// fmt.Printf("Writer priv %v\n",sw.priv)
	ret := box.Seal(nil,buf,&sw.Nonce,sw.pub,sw.priv)
	// fmt.Printf("data written %v\n",ret)

	n, err = sw.w.Write(ret)
	if err != nil {
		return n, err
	}
	// fmt.Println("----------Ending write---------")
	return n, nil
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

func Wtf() {
	var nonce  [24]byte
	var shared [32]byte
	var message = []byte{'w','t','f'}
	cpriv, cpub, _ := generate_keypair()
	spriv, spub, _ := generate_keypair()
	box.Precompute(&shared,&cpub,&spriv)

	ret := box.Seal(nil,message,&nonce,&spub,&cpriv)

	ret2, ok := box.OpenAfterPrecomputation(nil,ret,&nonce,&shared)
	fmt.Printf("(%v): %v\n",ok, ret2)
}