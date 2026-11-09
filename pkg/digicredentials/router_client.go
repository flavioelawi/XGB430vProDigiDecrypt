package digicredentials

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

type routerClient struct {
	http    *routerHTTP
	sources map[string]string
	cipher  *sessionCipher
	page    string
}

func newRouterClient(h *routerHTTP) *routerClient {
	return &routerClient{http: h, sources: map[string]string{}}
}
func (c *routerClient) collectScripts(page, base string) error {
	for _, m := range scriptSrc.FindAllStringSubmatch(page, -1) {
		// The authenticated page embeds JavaScript strings such as
		// `<script src=".\\/js\\/voice.js">`. They are not HTML tags and must
		// not be treated as fetchable resources. Real router script URLs never
		// contain a backslash.
		if strings.Contains(m[1], "\\") {
			continue
		}
		p, e := c.http.route(m[1], base)
		if e != nil {
			return fmt.Errorf("script reference %q: %w", m[1], e)
		}
		if _, ok := c.sources[p]; ok {
			continue
		}
		if len(c.sources) >= 64 {
			return fail("Demasiados recursos web; firmware no compatible.")
		}
		s, b, e := c.http.request(p, "GET", nil)
		if e != nil {
			return e
		}
		if s == 200 {
			c.sources[p] = string(b)
		}
	}
	return nil
}
func (c *routerClient) prepare() error {
	p, e := c.http.connect()
	if e != nil {
		return e
	}
	c.page = p
	debugf("received public login page")
	if e = c.collectScripts(p, "/"); e != nil {
		return e
	}
	merged := p
	for _, s := range c.sources {
		merged += "\n" + s
	}
	find := func(s string) string {
		for k, v := range c.sources {
			if strings.HasSuffix(k, s) {
				return v
			}
		}
		return ""
	}
	enc, rsa, proxy := find("/tpEncrypt.js"), find("/encrypt.js"), find("/gdprProxy.js")
	compact := regexp.MustCompile(`\s+`).ReplaceAllString(p, "")
	ok := strings.Contains(p, "/cgi/getGDPRParm") && strings.Contains(p, "/cgi/login") && strings.Contains(proxy, "/cgi_gdpr?9") && strings.Contains(compact, "tmpcount.Passwd=$.Base64Encoding(auth)") && strings.Contains(enc, "CryptoJS.mode.CBC") && strings.Contains(enc, "CryptoJS.pad.Pkcs7") && regexp.MustCompile(`MD5\s*\(\s*name\s*\+\s*pwd\s*\)`).MatchString(enc) && regexp.MustCompile(`rsaEncrypt\([^;]*512\s*,\s*0\s*\)`).MatchString(enc) && strings.Contains(rsa, "$.rsa.encrypt") && jsVariable(merged, "INCLUDE_LOGIN_GDPR_ENCRYPT") == "1"
	if !ok || strings.Contains(enc, "encryptOAEP") || strings.Contains(enc, "CryptoJS.mode.GCM") {
		return fail("Firmware de login no compatible: no coincide con el protocolo AES-CBC/RSA verificado. No se han enviado credenciales.")
	}
	debugf("validated AES-CBC/RSA login protocol")
	return nil
}
func (c *routerClient) login(user, password string) error {
	if user == "" || password == "" || strings.ContainsAny(user, "\r\n") || len([]byte(user)) > 128 || len([]byte(password)) > 128 {
		return fail("Usuario/contraseña vacíos o usuario no válido.")
	}
	params, e := c.http.text("/cgi/getGDPRParm", "POST")
	if e != nil {
		return e
	}
	nn, ee, seq := jsVariable(params, "nn"), jsVariable(params, "ee"), jsVariable(params, "seq")
	if nn == "" || ee == "" || seq == "" {
		return fail("No se recibieron los parámetros de cifrado esperados.")
	}
	if strings.Contains(c.page, "/cgi/getBusy") {
		busy, e := c.http.text("/cgi/getBusy", "POST")
		if e != nil {
			return e
		}
		if jsVariable(busy, "isLogined") == "1" || jsVariable(busy, "isBusy") == "1" {
			return fail("Hay otra sesión abierta u ocupada. Ciérrala en el navegador y vuelve a ejecutar.")
		}
	}
	c.cipher, e = newSessionCipher(nn, ee, seq, user, password)
	if e != nil {
		return e
	}
	debugf("obtained compatible RSA parameters and created session cipher")
	fields := map[string]string{"UserName": base64.StdEncoding.EncodeToString([]byte(user)), "Passwd": base64.StdEncoding.EncodeToString([]byte(password)), "Action": "1", "stack": "0,0,0,0,0,0", "pstack": "0,0,0,0,0,0"}
	raw, _ := json.Marshal(map[string]any{"data": fields, "operation": "cgi", "oid": "/cgi/login"})
	wire, e := c.cipher.encrypt(string(raw), true)
	if e != nil {
		return e
	}
	status, response, e := c.http.request("/cgi_gdpr?9", "POST", wire)
	if e != nil {
		return e
	}
	if status != 200 {
		return fail(fmt.Sprintf("Login rechazado (HTTP %d); no se reintentará.", status))
	}
	result, e := c.cipher.decrypt(response)
	if e != nil {
		return e
	}
	m := regexp.MustCompile(`\$\.ret\s*=\s*(\d+)\s*;`).FindStringSubmatch(result)
	if len(m) != 2 {
		return fail("Respuesta de login desconocida; no se reintentará.")
	}
	if m[1] == "71233" {
		return fail("Usuario o contraseña incorrectos; no se reintentará.")
	}
	if m[1] != "0" {
		return fail("Login rechazado por el router; no se reintentará.")
	}
	c.page, e = c.http.text("/", "GET")
	if e != nil {
		return e
	}
	token := jsVariable(c.page, "token")
	if token == "" {
		token = jsVariable(c.page, "$.tokenid")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`).MatchString(token) {
		return fail("No se recibió un TokenID válido tras el login.")
	}
	c.http.token = token
	debugf("login accepted; received session token (redacted)")
	return c.collectScripts(c.page, "/")
}

// dmGet is deliberately restricted to the two read-only objects used by the
// backup page. It cannot be repurposed to modify router configuration.
func (c *routerClient) dmGet(oid string, names ...string) (map[string]string, error) {
	allowed := map[string]map[string]bool{
		"DEV2_DEV_INFO": {"modelName": true, "X_TP_DevModelVersion": true, "X_TP_BuildDate": true, "X_TP_BuildTime": true},
		"DEV2_SYS_CFG":  {"signStatus": true},
	}
	if allowed[oid] == nil || c.cipher == nil {
		return nil, fail("Consulta de metadatos no permitida.")
	}
	debugf("reading backup metadata object %s (%s)", oid, strings.Join(names, ", "))
	fields := map[string]string{"stack": "0,0,0,0,0,0", "pstack": "0,0,0,0,0,0"}
	for _, name := range names {
		if !allowed[oid][name] {
			return nil, fail("Consulta de metadatos no permitida.")
		}
		fields[name] = ""
	}
	raw, _ := json.Marshal(map[string]any{"data": fields, "operation": "go", "oid": oid})
	wire, err := c.cipher.encrypt(string(raw), false)
	if err != nil {
		return nil, err
	}
	status, reply, err := c.http.request("/cgi_gdpr?9", "POST", wire)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fail(fmt.Sprintf("No se pudieron leer los metadatos del backup (HTTP %d).", status))
	}
	plain, err := c.cipher.decrypt(reply)
	if err != nil {
		return nil, err
	}
	var result struct {
		ErrorCode any            `json:"errorcode"`
		Data      map[string]any `json:"data"`
	}
	if json.Unmarshal([]byte(plain), &result) != nil || (result.ErrorCode != nil && fmt.Sprint(result.ErrorCode) != "0") {
		return nil, fail("El router rechazó la lectura de los metadatos del backup.")
	}
	out := map[string]string{}
	for _, name := range names {
		v, ok := result.Data[name]
		if !ok {
			return nil, fail("Faltan metadatos necesarios para calcular el nombre del backup.")
		}
		switch x := v.(type) {
		case string:
			out[name] = x
		case float64:
			out[name] = fmt.Sprintf("%.0f", x)
		default:
			return nil, fail("Faltan metadatos necesarios para calcular el nombre del backup.")
		}
	}
	return out, nil
}

func (c *routerClient) dynamicBackupPath(text string, docs map[string]string) (string, error) {
	compact := regexp.MustCompile(`\s+`).ReplaceAllString(text, "")
	evidence := []string{`devInfo.modelName.replace(/\s/g,"")`, `devInfo.X_TP_DevModelVersion.slice(0,devInfo.X_TP_DevModelVersion.indexOf('.'))`, `"/cgi/"+modelName+"V"+modelVersion+devInfo.X_TP_BuildDate+devInfo.X_TP_BuildTime+sign`, `action=action+"_"+INCLUDE_BOOT_AGINETCONFIG_PLATFORM+"_"+INCLUDE_BOOT_AGINETCONFIG_CONFIGKEY`, `action=action+"_backupcfg"`}
	for _, item := range evidence {
		if !strings.Contains(compact, item) {
			debugf("backup-page formula did not match expected expression")
			return "", nil
		}
	}
	merged := ""
	for _, doc := range docs {
		merged += "\n" + doc
	}
	if jsVariable(merged, "INCLUDE_OPTION66") != "1" {
		debugf("backup-page formula has no compatible INCLUDE_OPTION66 flag")
		return "", nil
	}
	signFlag, aginetFlag := jsVariable(merged, "INCLUDE_DIGITAL_SIGNATURE"), jsVariable(merged, "INCLUDE_BOOT_AGINETCONFIG")
	if (signFlag != "0" && signFlag != "1") || (aginetFlag != "0" && aginetFlag != "1") {
		return "", fail("Faltan las opciones de firmware para construir la ruta de backup.")
	}
	if jsVariable(merged, "userType") == "Admin" {
		return "", fail("Este firmware exporta otro formato para Admin. Ejecuta con la cuenta user.")
	}
	info, err := c.dmGet("DEV2_DEV_INFO", "modelName", "X_TP_DevModelVersion", "X_TP_BuildDate", "X_TP_BuildTime")
	if err != nil {
		return "", err
	}
	model := regexp.MustCompile(`\s`).ReplaceAllString(info["modelName"], "")
	version := info["X_TP_DevModelVersion"]
	if !strings.Contains(version, ".") || !regexp.MustCompile(`^[A-Za-z0-9_.()-]{1,80}$`).MatchString(model) {
		return "", fail("Modelo/versión no compatibles con la fórmula de backup.")
	}
	major := strings.SplitN(version, ".", 2)[0]
	for _, value := range []string{major, info["X_TP_BuildDate"], info["X_TP_BuildTime"]} {
		if !regexp.MustCompile(`^\d{1,12}$`).MatchString(value) {
			return "", fail("Versión/fecha de compilación no compatibles.")
		}
	}
	sign := "n"
	if signFlag == "1" {
		cfg, err := c.dmGet("DEV2_SYS_CFG", "signStatus")
		if err != nil {
			return "", err
		}
		if cfg["signStatus"] != "0" {
			sign = "s"
		}
	}
	filename := model + "V" + major + info["X_TP_BuildDate"] + info["X_TP_BuildTime"] + sign
	if aginetFlag == "1" {
		platform, key := jsVariable(merged, "INCLUDE_BOOT_AGINETCONFIG_PLATFORM"), jsVariable(merged, "INCLUDE_BOOT_AGINETCONFIG_CONFIGKEY")
		if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`).MatchString(platform) || !regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`).MatchString(key) {
			return "", fail("Faltan sufijos Aginet en los scripts de este firmware.")
		}
		filename += "_" + platform + "_" + key
	}
	return "/cgi/" + filename + "_backupcfg.bin", nil
}
func (c *routerClient) backupPath() (string, error) {
	docs := map[string]string{"/": c.page}
	for k, v := range c.sources {
		docs[k] = v
	}
	// This is the fixed, observed backup page—not a filename probe.
	if _, ok := docs["/main/backNRestore.htm"]; !ok {
		debugf("reading fixed backup page")
		if status, data, err := c.http.request("/main/backNRestore.htm", "GET", nil); err != nil {
			return "", err
		} else if status == 200 {
			docs["/main/backNRestore.htm"] = string(data)
		}
	}
	var found map[string]bool
	for _, s := range docs {
		for _, m := range regexp.MustCompile(`(?i)["']([^"'< >\r\n]*/cgi/[^"'< >\r\n]*_backupcfg\.bin)["']`).FindAllStringSubmatch(s, -1) {
			if p, e := c.http.route(m[1], "/"); e == nil {
				if found == nil {
					found = map[string]bool{}
				}
				found[p] = true
			}
		}
	}
	if len(found) == 1 {
		for p := range found {
			return p, nil
		}
	}
	if len(found) > 1 {
		return "", fail("El firmware publica varias rutas de backup; no se elegirá una al azar.")
	}
	for _, doc := range docs {
		if strings.Contains(doc, "backupConf") && strings.Contains(doc, "X_TP_BuildDate") {
			if dynamic, err := c.dynamicBackupPath(doc, docs); err != nil {
				return "", err
			} else if dynamic != "" {
				debugf("derived one backup download path")
				return dynamic, nil
			}
		}
	}
	return "", fail("No se reconoce la ruta/fórmula de backup de este firmware. No se probarán nombres inventados.")
}
func (c *routerClient) downloadBackup() ([]byte, error) {
	p, e := c.backupPath()
	if e != nil {
		return nil, e
	}
	s, b, e := c.http.request(p, "GET", nil)
	if e != nil {
		return nil, e
	}
	if s == 401 || s == 403 {
		return nil, fail("La cuenta no tiene permiso para descargar el backup.")
	}
	if s != 200 {
		return nil, fail(fmt.Sprintf("No se pudo descargar el backup (HTTP %d).", s))
	}
	if bytes.HasPrefix(bytes.ToLower(bytes.TrimSpace(b)), []byte("<html")) {
		return nil, fail("El router devolvió una página web en lugar del backup; sesión o permisos insuficientes.")
	}
	return b, nil
}
func (c *routerClient) logout() {
	if c.cipher == nil || c.http.token == "" {
		return
	}
	raw := `{"data":{"stack":"0,0,0,0,0,0","pstack":"0,0,0,0,0,0"},"operation":"cgi","oid":"/cgi/logout"}`
	wire, e := c.cipher.encrypt(raw, false)
	if e == nil {
		c.http.request("/cgi_gdpr?9", "POST", wire)
	}
	c.http.cookies = map[string]string{}
	c.http.token = ""
	c.cipher = nil
}
