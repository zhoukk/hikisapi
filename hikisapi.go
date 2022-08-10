package hikisapi

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type wwwAuthenticate struct {
	Algorithm string // unquoted
	Domain    string // quoted
	Nonce     string // quoted
	Opaque    string // quoted
	Qop       string // quoted
	Realm     string // quoted
	Stale     bool   // unquoted
	Charset   string // quoted
	Userhash  bool   // quoted
}

func newWwwAuthenticate(s string) *wwwAuthenticate {

	wa := wwwAuthenticate{}

	algorithmRegex := regexp.MustCompile(`algorithm="([^ ,]+)"`)
	algorithmMatch := algorithmRegex.FindStringSubmatch(s)
	if algorithmMatch != nil {
		wa.Algorithm = algorithmMatch[1]
	}

	domainRegex := regexp.MustCompile(`domain="(.+?)"`)
	domainMatch := domainRegex.FindStringSubmatch(s)
	if domainMatch != nil {
		wa.Domain = domainMatch[1]
	}

	nonceRegex := regexp.MustCompile(`nonce="(.+?)"`)
	nonceMatch := nonceRegex.FindStringSubmatch(s)
	if nonceMatch != nil {
		wa.Nonce = nonceMatch[1]
	}

	opaqueRegex := regexp.MustCompile(`opaque="(.+?)"`)
	opaqueMatch := opaqueRegex.FindStringSubmatch(s)
	if opaqueMatch != nil {
		wa.Opaque = opaqueMatch[1]
	}

	qopRegex := regexp.MustCompile(`qop="(.+?)"`)
	qopMatch := qopRegex.FindStringSubmatch(s)
	if qopMatch != nil {
		wa.Qop = qopMatch[1]
	}

	realmRegex := regexp.MustCompile(`realm="(.+?)"`)
	realmMatch := realmRegex.FindStringSubmatch(s)
	if realmMatch != nil {
		wa.Realm = realmMatch[1]
	}

	staleRegex := regexp.MustCompile(`stale=([^ ,])"`)
	staleMatch := staleRegex.FindStringSubmatch(s)
	if staleMatch != nil {
		wa.Stale = (strings.ToLower(staleMatch[1]) == "true")
	}

	charsetRegex := regexp.MustCompile(`charset="(.+?)"`)
	charsetMatch := charsetRegex.FindStringSubmatch(s)
	if charsetMatch != nil {
		wa.Charset = charsetMatch[1]
	}

	userhashRegex := regexp.MustCompile(`userhash=([^ ,])"`)
	userhashMatch := userhashRegex.FindStringSubmatch(s)
	if userhashMatch != nil {
		wa.Userhash = (strings.ToLower(userhashMatch[1]) == "true")
	}

	return &wa
}

type authorization struct {
	Algorithm string // unquoted
	Cnonce    string // quoted
	Nc        int    // unquoted
	Nonce     string // quoted
	Opaque    string // quoted
	Qop       string // unquoted
	Realm     string // quoted
	Response  string // quoted
	URI       string // quoted
	Userhash  bool   // quoted
	Username  string // quoted
}

func (wa *wwwAuthenticate) authorize(t *digestAuthTransport, req *http.Request, body string) *authorization {

	a := &authorization{
		Algorithm: wa.Algorithm,
		Cnonce:    "",
		Nc:        0,
		Nonce:     wa.Nonce,
		Opaque:    wa.Opaque,
		Qop:       "",
		Realm:     wa.Realm,
		Response:  "",
		URI:       "",
		Userhash:  wa.Userhash,
		Username:  t.user,
	}

	if a.Userhash {
		a.Username = a.hash(fmt.Sprintf("%s:%s", a.Username, a.Realm))
	}

	a.Nc++

	a.Cnonce = a.hash(fmt.Sprintf("%d:%s:k", time.Now().UnixNano(), t.user))
	a.URI = req.URL.RequestURI()
	a.Response = a.computeResponse(wa, t, req, body)

	return a
}

func (a *authorization) computeResponse(wa *wwwAuthenticate, t *digestAuthTransport, req *http.Request, body string) (s string) {

	kdSecret := a.hash(a.computeA1(t))
	kdData := fmt.Sprintf("%s:%08x:%s:%s:%s", a.Nonce, a.Nc, a.Cnonce, a.Qop, a.hash(a.computeA2(wa, t, req, body)))

	return a.hash(fmt.Sprintf("%s:%s", kdSecret, kdData))
}

func (a *authorization) computeA1(t *digestAuthTransport) string {

	algorithm := strings.ToUpper(a.Algorithm)

	if algorithm == "" || algorithm == "MD5" || algorithm == "SHA-256" {
		return fmt.Sprintf("%s:%s:%s", a.Username, a.Realm, t.pass)
	}

	if algorithm == "SHA-256" || algorithm == "SHA-256-SESS" {
		upHash := a.hash(fmt.Sprintf("%s:%s:%s", a.Username, a.Realm, t.pass))
		return fmt.Sprintf("%s:%s:%s", upHash, a.Nonce, a.Cnonce)
	}

	return ""
}

func (a *authorization) computeA2(wa *wwwAuthenticate, t *digestAuthTransport, req *http.Request, body string) string {

	if strings.Contains(wa.Qop, "auth-int") {
		a.Qop = "auth-int"
		return fmt.Sprintf("%s:%s:%s", req.Method, a.URI, a.hash(body))
	}

	if wa.Qop == "auth" || wa.Qop == "" {
		a.Qop = "auth"
		return fmt.Sprintf("%s:%s", req.Method, a.URI)
	}

	return ""
}

func (a *authorization) hash(str string) string {
	var h hash.Hash
	algorithm := strings.ToUpper(a.Algorithm)

	if algorithm == "" || algorithm == "MD5" || algorithm == "MD5-SESS" {
		h = md5.New()
	} else if algorithm == "SHA-256" || algorithm == "SHA-256-SESS" {
		h = sha256.New()
	} else {
		return ""
	}

	io.WriteString(h, str)
	return hex.EncodeToString(h.Sum(nil))
}

func (a *authorization) string() string {
	var buf bytes.Buffer

	buf.WriteString("Digest ")

	if a.Username != "" {
		buf.WriteString(fmt.Sprintf("username=\"%s\", ", a.Username))
	}

	if a.Realm != "" {
		buf.WriteString(fmt.Sprintf("realm=\"%s\", ", a.Realm))
	}

	if a.Nonce != "" {
		buf.WriteString(fmt.Sprintf("nonce=\"%s\", ", a.Nonce))
	}

	if a.URI != "" {
		buf.WriteString(fmt.Sprintf("uri=\"%s\", ", a.URI))
	}

	if a.Response != "" {
		buf.WriteString(fmt.Sprintf("response=\"%s\", ", a.Response))
	}

	if a.Algorithm != "" {
		buf.WriteString(fmt.Sprintf("algorithm=%s, ", a.Algorithm))
	}

	if a.Cnonce != "" {
		buf.WriteString(fmt.Sprintf("cnonce=\"%s\", ", a.Cnonce))
	}

	if a.Opaque != "" {
		buf.WriteString(fmt.Sprintf("opaque=\"%s\", ", a.Opaque))
	}

	if a.Qop != "" {
		buf.WriteString(fmt.Sprintf("qop=%s, ", a.Qop))
	}

	if a.Nc != 0 {
		buf.WriteString(fmt.Sprintf("nc=%08x, ", a.Nc))
	}

	if a.Userhash {
		buf.WriteString("userhash=true, ")
	}

	return strings.TrimSuffix(buf.String(), ", ")
}

type digestAuthTransport struct {
	user      string
	pass      string
	transport http.RoundTripper
}

func newTransport(user, pass string) *digestAuthTransport {
	return &digestAuthTransport{
		user,
		pass,
		http.DefaultTransport,
	}
}

func (t *digestAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rtreq := new(http.Request)
	*rtreq = *req

	rtreq.Header = make(http.Header)
	for k, s := range req.Header {
		rtreq.Header[k] = s
	}

	reqbody := ""
	if req.Body != nil {
		buf, _ := ioutil.ReadAll(req.Body)
		req.Body = ioutil.NopCloser(bytes.NewBuffer(buf))
		rtreq.Body = ioutil.NopCloser(bytes.NewBuffer(buf))
		reqbody = string(buf)
	}

	resp, err := t.transport.RoundTrip(req)
	if err != nil || resp.StatusCode != 401 {
		return resp, err
	}

	wwwauth := resp.Header.Get("WWW-Authenticate")
	a := newWwwAuthenticate(wwwauth)

	authresp := a.authorize(t, req, reqbody)

	resp.Body.Close()

	rtreq.Header.Set("Authorization", authresp.string())

	return t.transport.RoundTrip(rtreq)
}

type responseStatusAdditionalErrStatusInfo struct {
	ID            string `xml:"id,omitempty" json:"id,omitempty"`
	StatusCode    int    `xml:"statusCode,omitempty" json:"statusCode,omitempty"`
	StatusString  string `xml:"statusString,omitempty" json:"statusString,omitempty"`
	SubStatusCode string `xml:"subStatusCode,omitempty" json:"subStatusCode,omitempty"`
	ErrorCode     int    `xml:"errorCode,omitempty" json:"errorCode,omitempty"`
	ErrorMsg      string `xml:"errorMsg,omitempty" json:"errorMsg,omitempty"`
}

type responseStatusAdditionalErrStatus struct {
	Status responseStatusAdditionalErrStatusInfo `xml:"Status,omitempty" json:"Status,omitempty"`
}

type responseStatusAdditionalErr struct {
	StatusList []responseStatusAdditionalErrStatus `xml:"StatusList,omitempty" json:"StatusList,omitempty"`
}

type ResponseStatus struct {
	XMLName       xml.Name                     `xml:"ResponseStatus,omitempty"`
	XMLVersion    string                       `xml:"version,attr"`
	XMLNamespace  string                       `xml:"xmlns,attr"`
	RequestURL    string                       `xml:"requestURL,omitempty" json:"requestURL,omitempty"`
	StatusCode    int                          `xml:"statusCode,omitempty" json:"statusCode,omitempty"`
	StatusString  string                       `xml:"statusString,omitempty" json:"statusString,omitempty"`
	ID            int                          `xml:"id,omitempty" json:"id,omitempty"`
	SubStatusCode string                       `xml:"subStatusCode,omitempty" json:"subStatusCode,omitempty"`
	ErrorCode     int                          `xml:"errorCode,omitempty" json:"errorCode,omitempty"`
	ErrorMsg      string                       `xml:"errorMsg,omitempty" json:"errorMsg,omitempty"`
	AdditionalErr *responseStatusAdditionalErr `xml:"AdditionalErr,omitempty" json:"AdditionalErr,omitempty"`
}

type IsApiClient struct {
	proto string
	host  string
	net   *http.Client
}

func NewClient(host, user, pass string) *IsApiClient {
	return &IsApiClient{"http", host, &http.Client{
		Transport: newTransport(user, pass),
	}}
}

func (c *IsApiClient) Get(uri string, query url.Values, ret interface{}) error {
	req, err := http.NewRequest(http.MethodGet, "", nil)
	if err != nil {
		return err
	}
	req.URL = &url.URL{Scheme: c.proto, Host: c.host, Path: uri, RawQuery: query.Encode()}
	resp, err := c.net.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		e := ResponseStatus{}
		err = xml.NewDecoder(resp.Body).Decode(&e)
		if err != nil {
			return err
		}
		return errors.New(e.ErrorMsg)
	}

	return xml.NewDecoder(resp.Body).Decode(&ret)
}
