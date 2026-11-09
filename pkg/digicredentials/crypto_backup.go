// digi-credentials reads credentials from a TP-Link XGB430v Pro ESDIGI backup.
// It only connects to the numeric IP supplied interactively and keeps all data
// in memory.  It is GPL-3.0-or-later; see LICENSE.
package digicredentials

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5" // required by the router protocol
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	maxResponse = 4 << 20
	maxXML      = 4 << 20
	productID   = uint32(1083710977)
	timeout     = 12 * time.Second
)

var baseKey = []byte{0x74, 0x8d, 0xa5, 0x0b, 0xf9, 0x3e, 0x2d, 0xcf}

type routerError struct{ message string }

func (e *routerError) Error() string { return e.message }
func fail(s string) error            { return &routerError{s} }

func md5sum(b []byte) []byte { s := md5.Sum(b); return s[:] }

func aesCBC(key, iv, input []byte, decrypt bool) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(input)%b.BlockSize() != 0 {
		return nil, errors.New("invalid AES length")
	}
	out := make([]byte, len(input))
	if decrypt {
		cipher.NewCBCDecrypter(b, iv).CryptBlocks(out, input)
	} else {
		cipher.NewCBCEncrypter(b, iv).CryptBlocks(out, input)
	}
	return out, nil
}
func desDecrypt(key, input []byte) ([]byte, error) {
	return desECBDecrypt(key, input)
}
func desECBDecrypt(key, input []byte) ([]byte, error) {
	b, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(input)%des.BlockSize != 0 {
		return nil, errors.New("invalid DES length")
	}
	out := make([]byte, len(input))
	for i := 0; i < len(input); i += des.BlockSize {
		b.Decrypt(out[i:i+des.BlockSize], input[i:i+des.BlockSize])
	}
	return out, nil
}

func deriveKey() []byte {
	h := fmt.Sprintf("%08x", productID)
	k := make([]byte, 8)
	for i := range k {
		k[i] = baseKey[i] ^ h[i]
	}
	return k
}

func decryptBackup(data []byte) ([]byte, error) {
	if len(data) < 24 || len(data) > maxResponse || len(data)%8 != 0 {
		return nil, fail("La descarga no es un backup DES válido (longitud incorrecta).")
	}
	plain, err := desECBDecrypt(deriveKey(), data)
	if err != nil {
		return nil, err
	}
	var payload []byte
	for padding := 0; padding < 8; padding++ {
		if padding > 0 && !bytes.Equal(plain[len(plain)-padding:], make([]byte, padding)) {
			continue
		}
		end := len(plain)
		if padding > 0 {
			end -= padding
		}
		candidate := plain[16:end]
		if bytes.Equal(plain[:16], md5sum(candidate)) {
			payload = candidate
			break
		}
	}
	if payload == nil {
		return nil, fail("MD5 incorrecto: backup dañado o firmware/ProductID no compatible. No se mostrarán credenciales.")
	}
	payload = bytes.TrimRight(payload, "\x00")
	if bytes.HasPrefix(bytes.TrimSpace(payload), []byte("<?xml")) || bytes.HasPrefix(bytes.TrimSpace(payload), []byte("<DslCpeConfig")) {
		return payload, nil
	}
	return decompressLZSS(payload)
}

func decompressLZSS(src []byte) ([]byte, error) {
	if len(src) < 5 {
		return nil, fail("Backup comprimido truncado.")
	}
	sizes := []uint32{binary.BigEndian.Uint32(src), binary.LittleEndian.Uint32(src)}
	var successes [][]byte
	seen := map[uint32]bool{}
	for _, size := range sizes {
		if size == 0 || size > maxXML || seen[size] {
			continue
		}
		seen[size] = true
		pos, flags, left := 5, uint16(0), 0
		out := append([]byte(nil), src[4])
		take := func() (byte, bool) {
			if pos >= len(src) {
				return 0, false
			}
			x := src[pos]
			pos++
			return x, true
		}
		bit := func() (int, bool) {
			if left == 0 {
				a, ok := take()
				if !ok {
					return 0, false
				}
				b, ok := take()
				if !ok {
					return 0, false
				}
				flags = uint16(a) | uint16(b)<<8
				left = 16
			}
			left--
			return int((flags >> left) & 1), true
		}
		variable := func() (int, bool) {
			v := 1
			for i := 0; i < 24; i++ {
				x, ok := bit()
				if !ok {
					return 0, false
				}
				v = v<<1 | x
				stop, ok := bit()
				if !ok {
					return 0, false
				}
				if stop == 0 {
					return v, true
				}
			}
			return 0, false
		}
		valid := true
		reason := "complete"
		for len(out) < int(size) && valid {
			flag, ok := bit()
			if !ok {
				valid = false
				reason = "missing flag"
				break
			}
			if flag == 0 {
				x, ok := take()
				if !ok {
					// Some XGB430v Pro streams count a final implicit sentinel in
					// the header. Accept it only at EOF; the XML signature below
					// remains mandatory.
					if len(out) == int(size)-1 && pos == len(src) {
						break
					}
					valid = false
					reason = "missing literal"
				} else {
					out = append(out, x)
				}
			} else {
				count, ok := variable()
				if !ok {
					valid = false
					reason = "invalid length"
					break
				}
				high, ok := variable()
				if !ok {
					valid = false
					reason = "invalid offset"
					break
				}
				low, ok := take()
				if !ok {
					valid = false
					reason = "missing offset byte"
					break
				}
				count += 2
				distance := ((high - 2) << 8) + int(low) + 1
				if distance > len(out) || count > int(size)-len(out) {
					valid = false
					reason = "invalid back-reference"
					break
				}
				for i := 0; i < count; i++ {
					out = append(out, out[len(out)-distance])
				}
			}
		}
		debugf("LZSS candidate size=%d output=%d input-position=%d/%d valid=%t reason=%s", size, len(out), pos, len(src), valid, reason)
		if valid && len(src)-pos <= 7 && bytes.Count(src[pos:], []byte{0}) == len(src)-pos && (bytes.HasPrefix(bytes.TrimSpace(out), []byte("<?xml")) || bytes.HasPrefix(bytes.TrimSpace(out), []byte("<DslCpeConfig"))) {
			successes = append(successes, out)
		}
	}
	if len(successes) != 1 {
		return nil, fail("LZSS truncado, corrupto o de un formato de firmware no compatible.")
	}
	return bytes.TrimRight(successes[0], "\x00"), nil
}
