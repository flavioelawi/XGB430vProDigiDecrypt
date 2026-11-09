package digicredentials

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

var jsVar = regexp.MustCompile(`(?m)(?:^|[^\w$])([A-Za-z_$][\w$]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|(\d+))\s*(?:;|$)`)

func jsVariable(src, name string) string {
	for _, m := range jsVar.FindAllStringSubmatch(src, -1) {
		if m[1] == name {
			for _, v := range m[2:] {
				if v != "" {
					return v
				}
			}
		}
	}
	return ""
}

var scriptSrc = regexp.MustCompile(`(?is)<script[^>]+\bsrc\s*=\s*["']([^"']+)["']`)

type sessionCipher struct {
	key, iv []byte
	n       *big.Int
	e       int
	seq     int
	hash    string
}

func newSessionCipher(mod, exp, seq, user, password string) (*sessionCipher, error) {
	if !regexp.MustCompile(`^[0-9a-fA-F]{128}$`).MatchString(mod) || !regexp.MustCompile(`^[0-9a-fA-F]{1,8}$`).MatchString(exp) || !regexp.MustCompile(`^\d{1,12}$`).MatchString(seq) {
		return nil, fail("Parámetros RSA/secuencia no compatibles.")
	}
	n := new(big.Int)
	n.SetString(mod, 16)
	ei, err := strconv.Atoi(seq)
	if err != nil {
		return nil, fail("Parámetros RSA/secuencia no compatibles.")
	}
	ev := new(big.Int)
	ev.SetString(exp, 16)
	if n.BitLen() != 512 || !ev.IsInt64() || ev.Int64() < 3 || ev.Bit(0) == 0 {
		return nil, fail("Clave RSA no compatible.")
	}
	digits := func() []byte {
		x := make([]byte, 16)
		for i := range x {
			for {
				x[i] = byte('0' + i%10)
				var b [1]byte
				rand.Read(b[:])
				x[i] = '0' + b[0]%10
				break
			}
		}
		return x
	}
	return &sessionCipher{digits(), digits(), n, int(ev.Int64()), ei, hex.EncodeToString(md5sum([]byte(user + password)))}, nil
}
func (s *sessionCipher) encrypt(text string, login bool) ([]byte, error) {
	raw := []byte(text)
	pad := 16 - len(raw)%16
	raw = append(raw, bytes.Repeat([]byte{byte(pad)}, pad)...)
	enc, e := aesCBC(s.key, s.iv, raw, false)
	if e != nil {
		return nil, e
	}
	data := base64.StdEncoding.EncodeToString(enc)
	msg := fmt.Sprintf("h=%s&s=%d", s.hash, s.seq+len(data))
	if login {
		msg = "key=" + string(s.key) + "&iv=" + string(s.iv) + "&" + msg
	}
	sig := ""
	for i := 0; i < len(msg); i += 64 {
		block := make([]byte, 64)
		copy(block, []byte(msg)[i:])
		v := new(big.Int).SetBytes(block)
		if v.Cmp(s.n) >= 0 {
			return nil, fail("Bloque de firma RSA inválido.")
		}
		z := new(big.Int).Exp(v, big.NewInt(int64(s.e)), s.n).Bytes()
		sig += fmt.Sprintf("%0128x", new(big.Int).SetBytes(z))
	}
	return []byte("sign=" + sig + "\r\ndata=" + data + "\r\n"), nil
}
func (s *sessionCipher) decrypt(data []byte) (string, error) {
	raw, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if e != nil || len(raw) == 0 || len(raw)%16 != 0 {
		return "", fail("Respuesta cifrada no válida; firmware no compatible.")
	}
	plain, e := aesCBC(s.key, s.iv, raw, true)
	if e != nil {
		return "", fail("Respuesta cifrada no válida; firmware no compatible.")
	}
	p := int(plain[len(plain)-1])
	if p < 1 || p > 16 || !bytes.Equal(plain[len(plain)-p:], bytes.Repeat([]byte{byte(p)}, p)) {
		return "", fail("Respuesta cifrada no válida; firmware no compatible.")
	}
	return string(plain[:len(plain)-p]), nil
}
