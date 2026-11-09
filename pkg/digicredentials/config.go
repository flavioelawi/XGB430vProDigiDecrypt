package digicredentials

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"html"
	"regexp"
	"strings"
	"unicode"
)

type ConfigNode struct {
	XMLName  xml.Name
	Attr     []xml.Attr   `xml:",any,attr"`
	Children []ConfigNode `xml:",any"`
	Text     string       `xml:",chardata"`
}

func (n ConfigNode) attr(name string) string {
	for _, a := range n.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

var doctype = regexp.MustCompile(`(?is)<!\s*(?:DOCTYPE|ENTITY)`)
var bareVal = regexp.MustCompile(`(?s)<([A-Za-z_][\w:.-]*)\s+val=(?:"([\s\S]*?)"|([^<>]*?))\s*/>`)
var bareAttr = regexp.MustCompile(`(\s[\w:.-]+)=([^"'\s<>/]+)`)

func parseConfig(data []byte) (*ConfigNode, error) {
	if len(data) > maxXML {
		return nil, fail("Configuración demasiado grande.")
	}
	text := strings.TrimRight(string(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})), "\x00")
	if doctype.MatchString(text) {
		return nil, fail("Configuración con DTD/entidades no admitida.")
	}
	var root ConfigNode
	if xml.Unmarshal([]byte(text), &root) == nil {
		return &root, nil
	}
	text = bareVal.ReplaceAllStringFunc(text, func(s string) string {
		m := bareVal.FindStringSubmatch(s)
		v := m[2]
		if v == "" {
			v = strings.TrimRight(m[3], " \t\r\n")
		}
		v = html.UnescapeString(v)
		return "<" + m[1] + ` val="` + html.EscapeString(v) + `" />`
	})
	text = regexp.MustCompile(`<[^>]+>`).ReplaceAllStringFunc(text, func(tag string) string {
		if strings.Contains(tag, " val=") {
			return tag
		}
		return bareAttr.ReplaceAllString(tag, `$1="$2"`)
	})
	if err := xml.Unmarshal([]byte(text), &root); err != nil {
		return nil, fail("Estructura de configuración no compatible; no se imprimirá XML.")
	}
	return &root, nil
}

type record struct {
	path   string
	fields map[string]string
}
type groups struct{ admin, ppp, sip []record }

func credentialGroups(root *ConfigNode) groups {
	g := groups{}
	var walk func(*ConfigNode, string, []string)
	walk = func(n *ConfigNode, p string, anc []string) {
		tag := n.XMLName.Local
		instance := n.attr("instance")
		if instance == "" {
			instance = n.attr("Instance")
		}
		p += "/" + tag
		if instance != "" {
			p += "[" + instance + "]"
		}
		vals := map[string]string{}
		for i := range n.Children {
			c := &n.Children[i]
			if c.attr("val") != "" || len(c.Children) == 0 && strings.TrimSpace(c.Text) != "" {
				v := c.attr("val")
				if v == "" {
					v = c.Text
				}
				vals[c.XMLName.Local] = v
			}
		}
		lower := map[string]string{}
		for k, v := range vals {
			lower[strings.ToLower(k)] = v
		}
		al := strings.ToLower(strings.Join(append(anc, tag), "/"))
		add := func(dst *[]record, keys map[string]bool) {
			m := map[string]string{}
			for k, v := range vals {
				if keys[strings.ToLower(k)] {
					m[k] = v
				}
			}
			*dst = append(*dst, record{p, m})
		}
		if strings.EqualFold(tag, "X_TP_UserCfg") {
			add(&g.admin, map[string]bool{"adminname": true, "adminusername": true, "adminpwd": true, "username": true, "password": true})
		} else if strings.EqualFold(tag, "User") && strings.Contains(strings.ToLower(strings.Join(anc, "/")), "users") && (lower["password"] != "" || lower["username"] != "") {
			add(&g.admin, map[string]bool{"username": true, "user": true, "name": true, "password": true, "enable": true})
		} else if (strings.Contains(al, "ppp") || strings.Contains(al, "wanpppconnection")) && (lower["username"] != "" || lower["password"] != "") {
			add(&g.ppp, map[string]bool{"username": true, "password": true, "enable": true})
		} else if (strings.Contains(al, "voice") || strings.EqualFold(tag, "sip")) && (lower["authusername"] != "" || lower["authpassword"] != "" || lower["username"] != "") {
			add(&g.sip, map[string]bool{"authusername": true, "authpassword": true, "authuserid": true, "multiauthusername": true, "multiauthpassword": true, "username": true, "password": true, "enable": true, "multienable": true})
		}
		if len(anc) > 128 {
			return
		}
		for i := range n.Children {
			if len(n.Children[i].Children) > 0 {
				walk(&n.Children[i], p, append(anc, tag))
			}
		}
	}
	walk(root, "", nil)
	return g
}
func available(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v != "" && v != "(null)" && v != "null" && v != "none" && v != "n/a"
}
func summary(rs []record, kind string) (string, string) {
	type pair struct{ u, p, e string }
	var cs []pair
	for _, r := range rs {
		f := map[string]string{}
		for k, v := range r.fields {
			f[strings.ToLower(k)] = v
		}
		p := pair{e: f["enable"]}
		if p.e == "" {
			p.e = f["multienable"]
		}
		switch kind {
		case "admin":
			if strings.HasSuffix(r.path, "/X_TP_UserCfg") {
				p.u = f["adminusername"]
				if p.u == "" {
					p.u = f["adminname"]
				}
				p.p = f["adminpwd"]
			} else {
				p.u = f["username"]
				if p.u == "" {
					p.u = f["user"]
				}
				if !strings.EqualFold(p.u, "admin") {
					continue
				}
				p.p = f["password"]
			}
		case "sip":
			for _, z := range [][2]string{{"authusername", "authpassword"}, {"authuserid", "authpassword"}, {"multiauthusername", "multiauthpassword"}, {"username", "password"}} {
				if f[z[0]] != "" || f[z[1]] != "" {
					p.u, p.p = f[z[0]], f[z[1]]
					break
				}
			}
		default:
			p.u, p.p = f["username"], f["password"]
		}
		if available(p.u) || available(p.p) {
			cs = append(cs, p)
		}
	}
	if len(cs) == 0 {
		return "", ""
	}
	best := 0
	rank := func(p pair) int {
		r := 0
		if p.e == "1" {
			r += 2
		}
		if available(p.u) && available(p.p) {
			r++
		}
		return r
	}
	for _, p := range cs {
		if rank(p) > best {
			best = rank(p)
		}
	}
	uniq := map[string]pair{}
	for _, p := range cs {
		if rank(p) == best {
			uniq[p.u+"\x00"+p.p] = p
		}
	}
	if len(uniq) != 1 {
		return "(varios)", "(varios)"
	}
	for _, p := range uniq {
		return p.u, p.p
	}
	return "", ""
}
func display(v string) string {
	if !available(v) {
		return "(no disponible)"
	}
	if regexp.MustCompile(`^[*•]+$`).MatchString(v) {
		return "(oculto)"
	}
	var b strings.Builder
	for _, r := range v {
		if unicode.IsPrint(r) {
			b.WriteRune(r)
		} else {
			fmt.Fprintf(&b, "\\u%04x", r)
		}
	}
	return b.String()
}
