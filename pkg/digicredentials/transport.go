package digicredentials

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

type routerHTTP struct {
	ip      netip.Addr
	scheme  string
	cookies map[string]string
	token   string
	client  *http.Client
}

func newRouterHTTP(address string) (*routerHTTP, error) {
	ip, err := netip.ParseAddr(address)
	if err != nil || ip.IsUnspecified() || ip.IsMulticast() {
		return nil, fail("Introduce solo una IP numérica, sin URL, nombre DNS ni puerto.")
	}
	r := &routerHTTP{ip: ip, scheme: "https", cookies: map[string]string{}}
	r.makeClient()
	return r, nil
}
func (r *routerHTTP) host() string {
	if r.ip.Is6() {
		return "[" + r.ip.String() + "]"
	}
	return r.ip.String()
}
func (r *routerHTTP) origin() string { return r.scheme + "://" + r.host() }
func (r *routerHTTP) makeClient() {
	dial := func(_ interface{}, network, addr string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		return net.DialTimeout(network, net.JoinHostPort(r.ip.String(), port), timeout)
	}
	tr := &http.Transport{Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: false, TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: r.ip.String()}, Dial: func(network, addr string) (net.Conn, error) { return dial(nil, network, addr) }, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout}
	r.client = &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: timeout + 3*time.Second}
}
func (r *routerHTTP) route(ref, base string) (string, error) {
	if strings.Contains(ref, "\\") || strings.ContainsAny(ref, "\r\n\x00") {
		return "", fail("Referencia de red no válida.")
	}
	u, err := url.Parse(htmlUnescape(ref))
	if err != nil {
		return "", fail("Ruta de red no válida.")
	}
	b, _ := url.Parse(r.origin() + base)
	u = b.ResolveReference(u)
	port := u.Port()
	expected := "80"
	if r.scheme == "https" {
		expected = "443"
	}
	if u.Scheme != r.scheme || u.Hostname() != r.ip.String() || u.User != nil || (port != "" && port != expected) {
		return "", fail("Bloqueada una referencia fuera de la IP/origen introducido.")
	}
	if u.Path == "" {
		u.Path = "/"
	}
	if !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
		return "", fail("Ruta de red no válida.")
	}
	if u.RawQuery != "" {
		return u.EscapedPath() + "?" + u.RawQuery, nil
	}
	return u.EscapedPath(), nil
}
func htmlUnescape(s string) string {
	return strings.NewReplacer("&amp;", "&", "&quot;", "\"", "&#39;", "'").Replace(s)
}
func (r *routerHTTP) request(ref, method string, body []byte) (int, []byte, error) {
	p, err := r.route(ref, "/")
	if err != nil {
		debugf("rejected %s reference", method)
		return 0, nil, err
	}
	debugf("%s %s", method, p)
	if method != "GET" && method != "POST" {
		return 0, nil, fail("Método HTTP no permitido.")
	}
	req, err := http.NewRequest(method, r.origin()+p, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Referer", r.origin()+"/")
	req.Header.Set("Origin", r.origin())
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Content-Type", "text/plain; charset=UTF-8")
	if len(r.cookies) > 0 {
		v := []string{}
		for k, x := range r.cookies {
			v = append(v, k+"="+x)
		}
		req.Header.Set("Cookie", strings.Join(v, "; "))
	}
	if r.token != "" {
		req.Header.Set("TokenID", r.token)
	}
	res, err := r.client.Do(req)
	if err != nil {
		debugf("%s %s failed: %T", method, p, err)
		return 0, nil, err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, maxResponse+1))
	if err != nil {
		return 0, nil, err
	}
	if len(data) > maxResponse {
		return 0, nil, fail("Respuesta del router superior al límite de seguridad.")
	}
	debugf("%s %s -> HTTP %d (%d bytes)", method, p, res.StatusCode, len(data))
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return 0, nil, fail("El router redirige la petición; firmware/origen no compatible.")
	}
	if res.Header.Get("Content-Encoding") != "" && res.Header.Get("Content-Encoding") != "identity" {
		return 0, nil, fail("Codificación HTTP no compatible.")
	}
	for _, c := range res.Cookies() {
		r.cookies[c.Name] = c.Value
	}
	return res.StatusCode, data, nil
}
func (r *routerHTTP) text(p, m string) (string, error) {
	s, b, e := r.request(p, m, nil)
	if e != nil {
		return "", e
	}
	if s != 200 {
		return "", fail(fmt.Sprintf("El router devuelve HTTP %d.", s))
	}
	return string(b), nil
}
func (r *routerHTTP) connect() (string, error) {
	x, e := r.text("/", "GET")
	if e == nil {
		debugf("connected using HTTPS")
		return x, nil
	}
	debugf("HTTPS unavailable; falling back to HTTP before credentials are requested")
	r.scheme = "http"
	r.cookies = map[string]string{}
	r.makeClient()
	return r.text("/", "GET")
}
