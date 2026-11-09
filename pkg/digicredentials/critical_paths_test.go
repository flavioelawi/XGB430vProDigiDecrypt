package digicredentials

import (
	"bytes"
	"crypto/des"
	"encoding/base64"
	"testing"
)

func desECBEncrypt(key, input []byte) []byte {
	b, _ := des.NewCipher(key)
	out := make([]byte, len(input))
	for i := 0; i < len(input); i += des.BlockSize {
		b.Encrypt(out[i:i+des.BlockSize], input[i:i+des.BlockSize])
	}
	return out
}

func TestDecryptBackupXMLAndIntegrity(t *testing.T) {
	xml := []byte(`<?xml version="1.0"?><DslCpeConfig/>`)
	plain := append(md5sum(xml), xml...)
	plain = append(plain, bytes.Repeat([]byte{0}, (8-len(plain)%8)%8)...)
	decoded, err := decryptBackup(desECBEncrypt(deriveKey(), plain))
	if err != nil || !bytes.Equal(decoded, xml) {
		t.Fatalf("valid backup: %v, %q", err, decoded)
	}
	corrupt := desECBEncrypt(deriveKey(), append([]byte(nil), plain...))
	corrupt[0] ^= 1
	if _, err := decryptBackup(corrupt); err == nil {
		t.Fatal("corrupt backup was accepted")
	}
}

func TestParseTPLinkBareValuesAndSummary(t *testing.T) {
	root, err := parseConfig([]byte(`<DslCpeConfig><X_TP_UserCfg><adminName val=admin/><adminPwd val="p&#37;ss"/></X_TP_UserCfg><PPP><username val=wan/><password val=secret/></PPP></DslCpeConfig>`))
	if err != nil {
		t.Fatal(err)
	}
	g := credentialGroups(root)
	u, p := summary(g.admin, "admin")
	if u != "admin" || p != "p%ss" {
		t.Fatalf("admin pair = %q, %q", u, p)
	}
	u, p = summary(g.ppp, "ppp")
	if u != "wan" || p != "secret" {
		t.Fatalf("PPP pair = %q, %q", u, p)
	}
}

func TestRouteIsSameOriginOnly(t *testing.T) {
	h, err := newRouterHTTP("192.168.11.254")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := h.route("../js/tpEncrypt.js", "/main/login.htm"); err != nil || got != "/js/tpEncrypt.js" {
		t.Fatalf("relative route = %q, %v", got, err)
	}
	for _, ref := range []string{"https://example.com/x", "//example.com/x", "https://192.168.11.254:444/x", "/x\\y"} {
		if _, err := h.route(ref, "/"); err == nil {
			t.Fatalf("accepted unsafe reference %q", ref)
		}
	}
}

func TestSessionDecryptRejectsBadPadding(t *testing.T) {
	s := &sessionCipher{key: []byte("0123456789012345"), iv: []byte("9876543210987654")}
	plain := append([]byte("ok"), bytes.Repeat([]byte{14}, 14)...)
	ciphertext, err := aesCBC(s.key, s.iv, plain, false)
	if err != nil {
		t.Fatal(err)
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(ciphertext))
	if got, err := s.decrypt(encoded); err != nil || got != "ok" {
		t.Fatalf("decrypt = %q, %v", got, err)
	}
	ciphertext[len(ciphertext)-1] ^= 1
	if _, err := s.decrypt([]byte(base64.StdEncoding.EncodeToString(ciphertext))); err == nil {
		t.Fatal("invalid padding was accepted")
	}
}
