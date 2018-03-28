package cryptoUtils

import (
    "bytes"
    "crypto/cipher"
    "encoding/hex"
    "crypto/des"
    "strings"
    "errors"
    "crypto/aes"
)

type Padding struct{}

func (p *Padding) ZeroPadding(cipherText []byte, blockSize int) []byte {
    padding := blockSize - len(cipherText)%blockSize
    padText := bytes.Repeat([]byte{0}, padding)
    return append(cipherText, padText...)
}

func (p *Padding) PKCS5Padding(cipherText []byte, blockSize int) []byte {
    padding := blockSize - len(cipherText)%blockSize
    padtext := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(cipherText, padtext...)
}

func (p *Padding) PKCS7Padding(cipherText []byte, blockSize int) []byte {
    return p.PKCS5Padding(cipherText, blockSize)
}

type UnPadding struct{}

func (u *UnPadding) ZeroUnPadding(origData []byte) []byte {
    return bytes.TrimFunc(origData,
        func(r rune) bool {
            return r == rune(0)
        })
}

func (u *UnPadding) PKCS5UnPadding(origData []byte) []byte {
    length := len(origData)
    unpadding := int(origData[length-1])
    if length < unpadding {
        return []byte("unpadding error")
    }
    return origData[:(length - unpadding)]
}

func (u *UnPadding) PKCS7UnPadding(origData []byte) []byte {
    return u.PKCS5UnPadding(origData)
}

type TripleDES struct {
    Key           []byte
    IV            []byte
    PaddingFunc   func([]byte, int) []byte
    UnPaddingFunc func([]byte) []byte
}

func (t *TripleDES) Encrypt(origData string) (string, error) {
    block, err := des.NewTripleDESCipher(t.Key)
    if err != nil {
        return "", err
    }
    orig := t.PaddingFunc([]byte(origData), block.BlockSize())
    blockMode := cipher.NewCBCEncrypter(block, t.IV)
    crypted := make([]byte, len(orig))
    blockMode.CryptBlocks(crypted, orig)
    return strings.ToUpper(hex.EncodeToString(crypted)), nil
}

func (t *TripleDES) Decrypt(encrypted string) (string, error) {
    e, err := hex.DecodeString(strings.ToLower(encrypted))
    if err != nil {
        return "", err
    }
    block, err := des.NewTripleDESCipher(t.Key)
    if err != nil {
        return "", err
    }
    blockMode := cipher.NewCBCDecrypter(block, t.IV)
    origData := make([]byte, len(e))
    blockMode.CryptBlocks(origData, e)
    origData = t.UnPaddingFunc(origData)
    if string(origData) == "unpadding error" {
        return "", errors.New("unpadding error")
    }
    return string(origData), nil
}

type DES struct{}

func (d *DES) Encrypt(src, key string, paddingFunc func([]byte, int) []byte) (string, error) {
    block, err := des.NewCipher([]byte(key))
    if err != nil {
        return "", err
    }
    bs := block.BlockSize()
    src = string(paddingFunc([]byte(src), bs))
    if len(src)%bs != 0 {
        return "", errors.New("Need a multiple of the blocksize")
    }
    out := make([]byte, len(src))
    dst := out
    for len(src) > 0 {
        block.Encrypt(dst, []byte(src)[:bs])
        src = src[bs:]
        dst = dst[bs:]
    }
    return hex.EncodeToString(out), nil
}

func (d *DES) Decrypt(src, key string, unPaddingFunc func([]byte) []byte) (string, error) {
    b, _ := hex.DecodeString(src)
    src = string(b)
    block, err := des.NewCipher([]byte(key))
    if err != nil {
        return "", err
    }
    out := make([]byte, len(src))
    dst := out
    bs := block.BlockSize()
    if len(src)%bs != 0 {
        return "", errors.New("crypto/cipher: input not full blocks")
    }
    for len(src) > 0 {
        block.Decrypt(dst, []byte(src)[:bs])
        src = src[bs:]
        dst = dst[bs:]
    }

    out = unPaddingFunc(out)
    return string(out), nil
}

type AES struct{}

func (a *AES) Encrypt(origData, key, iv []byte, paddingFunc func([]byte, int) []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    blockSize := block.BlockSize()
    origData = paddingFunc(origData, blockSize)

    blockMode := cipher.NewCBCEncrypter(block, iv)
    crypted := make([]byte, len(origData))
    blockMode.CryptBlocks(crypted, origData)
    return crypted, nil
}

func (a *AES) Decrypt(encrypted, key, iv []byte, unPaddingFunc func([]byte) []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    blockMode := cipher.NewCBCDecrypter(block, iv)
    origData := make([]byte, len(encrypted))
    blockMode.CryptBlocks(origData, encrypted)
    origData = unPaddingFunc(origData)
    return origData, nil
}
