package hikisapi

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"hash"
	"io"
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

func (wa *wwwAuthenticate) authorize(t *digestAuthTransport, req *http.Request) *authorization {

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
	a.Response = a.computeResponse(wa, t, req)

	return a
}

func (a *authorization) computeResponse(wa *wwwAuthenticate, t *digestAuthTransport, req *http.Request) (s string) {

	kdSecret := a.hash(a.computeA1(t))
	kdData := fmt.Sprintf("%s:%08x:%s:%s:%s", a.Nonce, a.Nc, a.Cnonce, a.Qop, a.hash(a.computeA2(wa, t, req)))

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

func (a *authorization) computeA2(wa *wwwAuthenticate, t *digestAuthTransport, req *http.Request) string {

	if strings.Contains(wa.Qop, "auth-int") {
		a.Qop = "auth-int"
		return fmt.Sprintf("%s:%s", req.Method, a.URI)
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
	auth      *wwwAuthenticate
}

func newTransport(user, pass string) *digestAuthTransport {
	return &digestAuthTransport{
		user,
		pass,
		http.DefaultTransport,
		nil,
	}
}

func (t *digestAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rtreq := new(http.Request)
	rtreq.Header = req.Header
	rtreq.Method = req.Method
	rtreq.URL = req.URL

	if t.auth != nil {
		auth := t.auth.authorize(t, req)
		req.Header.Set("Authorization", auth.string())
	}

	resp, err := t.transport.RoundTrip(req)
	if err != nil || resp.StatusCode != 401 {
		return resp, err
	}

	wwwauth := resp.Header.Get("WWW-Authenticate")
	t.auth = newWwwAuthenticate(wwwauth)
	auth := t.auth.authorize(t, req)

	resp.Body.Close()
	rtreq.Header.Set("Authorization", auth.string())

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

type RequestEmpty struct {
	XMLName      xml.Name `xml:"TwoWayAudioChannelList,omitempty"`
	XMLVersion   string   `xml:"version,attr"`
	XMLNamespace string   `xml:"xmlns,attr"`
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

func (c *IsApiClient) do(req *http.Request, ret interface{}) error {
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
		return fmt.Errorf("%d %s err: %s, %s, %s", e.StatusCode, e.RequestURL, e.StatusString, e.SubStatusCode, e.ErrorMsg)
	}

	return xml.NewDecoder(resp.Body).Decode(&ret)
}

func (c *IsApiClient) Get(uri string, query url.Values, ret interface{}) error {
	url := &url.URL{Scheme: c.proto, Host: c.host, Path: uri, RawQuery: query.Encode()}
	req, err := http.NewRequest(http.MethodGet, url.String(), nil)
	if err != nil {
		return err
	}

	return c.do(req, ret)
}

func (c *IsApiClient) Post(uri string, in interface{}, ret interface{}) error {
	buf := bytes.Buffer{}
	err := xml.NewEncoder(&buf).Encode(in)
	if err != nil {
		return err
	}

	url := &url.URL{Scheme: c.proto, Host: c.host, Path: uri}
	req, err := http.NewRequest(http.MethodPost, url.String(), &buf)
	if err != nil {
		return err
	}

	return c.do(req, ret)
}

func (c *IsApiClient) Put(uri string, in interface{}, ret interface{}) error {
	buf := bytes.Buffer{}
	err := xml.NewEncoder(&buf).Encode(in)
	if err != nil {
		return err
	}

	url := &url.URL{Scheme: c.proto, Host: c.host, Path: uri}
	req, err := http.NewRequest(http.MethodPut, url.String(), &buf)
	if err != nil {
		return err
	}

	return c.do(req, ret)
}

type AudioReader struct {
	pr     *io.PipeReader
	length int64
}

func (ar *AudioReader) Read(p []byte) (n int, err error) {
	return ar.pr.Read(p)
}

func NewAudioReader(r io.Reader) *AudioReader {
	b, _ := io.ReadAll(r)
	br := bytes.NewReader(b)
	pr, pw := io.Pipe()
	go func() {
		buf := make([]byte, 8000)
		for {
			n, err := br.Read(buf)
			if err != nil {
				pw.Close()
				break
			}
			pw.Write(buf[:n])
			time.Sleep(time.Second)
		}
	}()
	return &AudioReader{pr, int64(len(b))}
}

func (c *IsApiClient) PutBinary(uri string, r io.Reader, ret interface{}) error {
	url := &url.URL{Scheme: c.proto, Host: c.host, Path: uri}
	req, err := http.NewRequest(http.MethodPut, url.String(), r)
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/octet-stream")
	if ar, ok := r.(*AudioReader); ok {
		req.ContentLength = ar.length
	}

	return c.do(req, ret)
}

func (c *IsApiClient) Delete(uri string, query url.Values, ret interface{}) error {
	url := &url.URL{Scheme: c.proto, Host: c.host, Path: uri, RawQuery: query.Encode()}
	req, err := http.NewRequest(http.MethodDelete, url.String(), nil)
	if err != nil {
		return err
	}

	return c.do(req, ret)
}

type DeviceInfo struct {
	XMLName         xml.Name `xml:"DeviceInfo,omitempty"`
	XMLVersion      string   `xml:"version,attr"`
	XMLNamespace    string   `xml:"xmlns,attr"`
	SerialNumber    string   `xml:"serialNumber" json:"serialNumber"`
	SubSerialNumber string   `xml:"subSerialNumber,omitempty" json:"subSerialNumber,omitempty"`
}

type FTPNotification struct {
	XMLName              xml.Name `xml:"FTPNotification,omitempty"`
	XMLVersion           string   `xml:"version,attr"`
	XMLNamespace         string   `xml:"xmlns,attr"`
	Id                   string   `xml:"id,omitempty"  json:"id,omitempty"`
	Enabled              bool     `xml:"enabled"  json:"enabled"`
	UseSSL               bool     `xml:"useSSL"  json:"useSSL"`
	AddressingFormatType string   `xml:"addressingFormatType,omitempty"  json:"addressingFormatType,omitempty"`
	HostName             string   `xml:"hostName,omitempty"  json:"hostName,omitempty"`
	IpAddress            string   `xml:"ipAddress,omitempty"  json:"ipAddress,omitempty"`
	IpV6Address          string   `xml:"ipV6Address,omitempty"  json:"ipV6Address,omitempty"`
	PortNo               string   `xml:"portNo,omitempty"  json:"portNo,omitempty"`
	UserName             string   `xml:"userName,omitempty"  json:"userName,omitempty"`
	Password             string   `xml:"password,omitempty"  json:"password,omitempty"`
	PassiveModeEnabled   bool     `xml:"passiveModeEnabled"  json:"passiveModeEnabled"`
	AnnoyFtp             bool     `xml:"annoyftp"  json:"annoyftp"`
	UploadPicture        bool     `xml:"uploadPicture"  json:"uploadPicture"`
	UploadVideoClip      bool     `xml:"uploadVideoClip"  json:"uploadVideoClip"`
	UploadPath           struct {
		PathDepth        int    `xml:"pathDepth"  json:"pathDepth"`
		TopDirNameRule   string `xml:"topDirNameRule,omitempty"  json:"topDirNameRule,omitempty"`
		TopDirName       string `xml:"topDirName,omitempty"  json:"topDirName,omitempty"`
		SubDirNameRule   string `xml:"subDirNameRule,omitempty"  json:"subDirNameRule,omitempty"`
		SubDirName       string `xml:"subDirName,omitempty"  json:"subDirName,omitempty"`
		ThreeDirNameRule string `xml:"threeDirNameRule,omitempty"  json:"threeDirNameRule,omitempty"`
		ThreeDirName     string `xml:"threeDirName,omitempty"  json:"threeDirName,omitempty"`
		FourDirNameRule  string `xml:"fourDirNameRule,omitempty"  json:"fourDirNameRule,omitempty"`
		FourDirName      string `xml:"fourDirName,omitempty"  json:"fourDirName,omitempty"`
	} `xml:"uploadPath,omitempty"  json:"uploadPath,omitempty"`
	PicArchivingInterval int    `xml:"picArchivingInterval"  json:"picArchivingInterval"`
	PicNameRuleType      string `xml:"picNameRuleType,omitempty"  json:"picNameRuleType,omitempty"`
	PicNamePrefix        string `xml:"picNamePrefix,omitempty"  json:"picNamePrefix,omitempty"`
	FtpPicNameRuleType   string `xml:"ftpPicNameRuleType,omitempty"  json:"ftpPicNameRuleType,omitempty"`
	FtpPicNameRule       struct {
		ItemList struct {
			Item []struct {
				ItemID        string `xml:"itemID,omitempty"  json:"itemID,omitempty"`
				ItemOrder     string `xml:"itemOrder,omitempty"  json:"itemOrder,omitempty"`
				ItemCustomStr string `xml:"itemCustomStr,omitempty"  json:"itemCustomStr,omitempty"`
			} `xml:"Item,omitempty"  json:"Item,omitempty"`
		} `xml:"ItemList,omitempty"  json:"ItemList,omitempty"`
		Delimiter string `xml:"delimiter,omitempty"  json:"delimiter,omitempty"`
		CustomStr string `xml:"customStr,omitempty"  json:"customStr,omitempty"`
	} `xml:"FtpPicNameRule,omitempty"  json:"FtpPicNameRule,omitempty"`
	UpDataType               int    `xml:"upDataType"  json:"upDataType"`
	UploadPlateEnable        bool   `xml:"uploadPlateEnable"  json:"uploadPlateEnable"`
	Site                     string `xml:"site,omitempty"  json:"site,omitempty"`
	RoadNum                  string `xml:"roadNum,omitempty"  json:"roadNum,omitempty"`
	InstrumentNum            string `xml:"instrumentNum,omitempty"  json:"instrumentNum,omitempty"`
	Direction                string `xml:"direction,omitempty"  json:"direction,omitempty"`
	DirectionDesc            string `xml:"directionDesc,omitempty"  json:"directionDesc,omitempty"`
	MonitoringInfo1          string `xml:"monitoringInfo1,omitempty"  json:"monitoringInfo1,omitempty"`
	UploadAttachedInfomation bool   `xml:"uploadAttachedInfomation"  json:"uploadAttachedInfomation"`
	BrokenNetHttp            bool   `xml:"brokenNetHttp"  json:"brokenNetHttp"`
}

type FTPNotificationList struct {
	XMLName         xml.Name          `xml:"FTPNotificationList,omitempty"`
	XMLVersion      string            `xml:"version,attr"`
	XMLNamespace    string            `xml:"xmlns,attr"`
	FTPNotification []FTPNotification `xml:"FTPNotification,omitempty" json:"FTPNotification,omitempty"`
}

type FTPTestDescription struct {
	XMLName              xml.Name `xml:"FTPTestDescription,omitempty"`
	XMLVersion           string   `xml:"version,attr"`
	XMLNamespace         string   `xml:"xmlns,attr"`
	UseSSL               bool     `xml:"useSSL"  json:"useSSL"`
	AddressingFormatType string   `xml:"addressingFormatType,omitempty"  json:"addressingFormatType,omitempty"`
	HostName             string   `xml:"hostName,omitempty"  json:"hostName,omitempty"`
	IpAddress            string   `xml:"ipAddress,omitempty"  json:"ipAddress,omitempty"`
	IpV6Address          string   `xml:"ipV6Address,omitempty"  json:"ipV6Address,omitempty"`
	PortNo               string   `xml:"portNo,omitempty"  json:"portNo,omitempty"`
	UserName             string   `xml:"userName,omitempty"  json:"userName,omitempty"`
	Password             string   `xml:"password,omitempty"  json:"password,omitempty"`
	PassiveModeEnabled   bool     `xml:"passiveModeEnabled"  json:"passiveModeEnabled"`
	AnnoyFtp             bool     `xml:"annoyftp"  json:"annoyftp"`
	UploadPath           struct {
		PathDepth      int    `xml:"pathDepth"  json:"pathDepth"`
		TopDirNameRule string `xml:"topDirNameRule,omitempty"  json:"topDirNameRule,omitempty"`
		TopDirName     string `xml:"topDirName,omitempty"  json:"topDirName,omitempty"`
		SubDirNameRule string `xml:"subDirNameRule,omitempty"  json:"subDirNameRule,omitempty"`
		SubDirName     string `xml:"subDirName,omitempty"  json:"subDirName,omitempty"`
	} `xml:"uploadPath,omitempty"  json:"uploadPath,omitempty"`
}

type FTPTestResult struct {
	XMLName          xml.Name `xml:"FTPTestResult,omitempty"`
	XMLVersion       string   `xml:"version,attr"`
	XMLNamespace     string   `xml:"xmlns,attr"`
	ErrorCode        int      `xml:"errorCode"  json:"errorCode"`
	ErrorDescription string   `xml:"errorDescription,omitempty"  json:"errorDescription,omitempty"`
}

type ScheduleAction struct {
	Id                      int `xml:"id,omitempty"  json:"id,omitempty"`
	ScheduleActionStartTime struct {
		DayOfWeek string `xml:"DayOfWeek,omitempty"  json:"DayOfWeek,omitempty"`
		TimeOfDay string `xml:"TimeOfDay,omitempty"  json:"TimeOfDay,omitempty"`
	} `xml:"ScheduleActionStartTime,omitempty"  json:"ScheduleActionStartTime,omitempty"`
	ScheduleActionEndTime struct {
		DayOfWeek string `xml:"DayOfWeek,omitempty"  json:"DayOfWeek,omitempty"`
		TimeOfDay string `xml:"TimeOfDay,omitempty"  json:"TimeOfDay,omitempty"`
	} `xml:"ScheduleActionEndTime,omitempty"  json:"ScheduleActionEndTime,omitempty"`
	ScheduleDSTEnable bool   `xml:"ScheduleDSTEnable"  json:"ScheduleDSTEnable"`
	Description       string `xml:"Description,omitempty"  json:"Description,omitempty"`
	Actions           struct {
		Record              bool   `xml:"Record"  json:"Record"`
		Log                 bool   `xml:"Log"  json:"Log"`
		SaveImg             bool   `xml:"SaveImg"  json:"SaveImg"`
		ActionRecordingMode string `xml:"ActionRecordingMode,omitempty"  json:"ActionRecordingMode,omitempty"`
	} `xml:"Actions,omitempty"  json:"Actions,omitempty"`
}

type ScheduleBlock struct {
	ScheduleBlockGUID string           `xml:"ScheduleBlockGUID,omitempty"  json:"ScheduleBlockGUID,omitempty"`
	ScheduleBlockType string           `xml:"ScheduleBlockType,omitempty"  json:"ScheduleBlockType,omitempty"`
	ScheduleAction    []ScheduleAction `xml:"ScheduleAction,omitempty"  json:"ScheduleAction,omitempty"`
}

type Track struct {
	XMLName              xml.Name `xml:"Track,omitempty"`
	XMLVersion           string   `xml:"version,attr"`
	XMLNamespace         string   `xml:"xmlns,attr"`
	Id                   int      `xml:"id"  json:"id"`
	Channel              int      `xml:"Channel"  json:"Channel"`
	Enable               bool     `xml:"Enable"  json:"Enable"`
	Description          string   `xml:"Description,omitempty"  json:"Description,omitempty"`
	TrackGUID            string   `xml:"TrackGUID,omitempty"  json:"TrackGUID,omitempty"`
	DefaultRecordingMode string   `xml:"DefaultRecordingMode,omitempty"  json:"DefaultRecordingMode,omitempty"`
	LoopEnable           string   `xml:"LoopEnable,omitempty"  json:"LoopEnable,omitempty"`
	SrcDescriptor        struct {
		SrcGUID       string `xml:"SrcGUID,omitempty"  json:"SrcGUID,omitempty"`
		SrcChannel    int    `xml:"SrcChannel"  json:"SrcChannel"`
		StreamHint    string `xml:"StreamHint,omitempty"  json:"StreamHint,omitempty"`
		SrcDriver     string `xml:"SrcDriver,omitempty"  json:"SrcDriver,omitempty"`
		SrcType       string `xml:"SrcType,omitempty"  json:"SrcType,omitempty"`
		SrcUrl        string `xml:"SrcUrl,omitempty"  json:"SrcUrl,omitempty"`
		SrcUrlMethods string `xml:"SrcUrlMethods,omitempty"  json:"SrcUrlMethods,omitempty"`
		SrcLogin      string `xml:"SrcLogin,omitempty"  json:"SrcLogin,omitempty"`
	} `xml:"SrcDescriptor,omitempty"  json:"SrcDescriptor,omitempty"`
	TrackSchedule struct {
		ScheduleBlockList struct {
			ScheduleBlock []ScheduleBlock `xml:"ScheduleBlock,omitempty"  json:"ScheduleBlock,omitempty"`
		} `xml:"ScheduleBlockList,omitempty"  json:"ScheduleBlockList,omitempty"`
	} `xml:"TrackSchedule,omitempty"  json:"TrackSchedule,omitempty"`
	CustomExtensionList struct {
		CustomExtension []struct {
			CustomExtensionName   string `xml:"CustomExtensionName,omitempty"  json:"CustomExtensionName,omitempty"`
			EnableSchedule        bool   `xml:"enableSchedule"  json:"enableSchedule"`
			SaveAudio             bool   `xml:"SaveAudio"  json:"SaveAudio"`
			PreRecordTimeSeconds  int    `xml:"PreRecordTimeSeconds"  json:"PreRecordTimeSeconds"`
			PostRecordTimeSeconds int    `xml:"PostRecordTimeSeconds"  json:"PostRecordTimeSeconds"`
		} `xml:"CustomExtension,omitempty"  json:"CustomExtension,omitempty"`
	} `xml:"CustomExtensionList,omitempty"  json:"CustomExtensionList,omitempty"`
	HolidaySchedule struct {
		ScheduleBlock ScheduleBlock `xml:"ScheduleBlock,omitempty"  json:"ScheduleBlock,omitempty"`
	} `xml:"HolidaySchedule,omitempty"  json:"HolidaySchedule,omitempty"`
	IntelligentRecord bool `xml:"IntelligentRecord"  json:"IntelligentRecord"`
	DelayTime         int  `xml:"delayTime"  json:"delayTime"`
	DurationEnabled   bool `xml:"durationEnabled"  json:"durationEnabled"`
}

type TrackList struct {
	XMLName      xml.Name `xml:"TrackList,omitempty"`
	XMLVersion   string   `xml:"version,attr"`
	XMLNamespace string   `xml:"xmlns,attr"`
	Track        []Track  `xml:"Track,omitempty"  json:"Track,omitempty"`
}

type SnapshotCapture struct {
	Enabled         bool `xml:"enabled"  json:"enabled"`
	SupportSchedule bool `xml:"supportSchedule"  json:"supportSchedule"`
	Compress        struct {
		PictureCodecType string `xml:"pictureCodecType,omitempty"  json:"pictureCodecType,omitempty"`
		PictureWidth     int    `xml:"pictureWidth"  json:"pictureWidth"`
		PictureHeight    int    `xml:"pictureHeight"  json:"pictureHeight"`
		Quality          int    `xml:"quality"  json:"quality"`
		CaptureInterval  int    `xml:"captureInterval"  json:"captureInterval"`
		CaptureNumber    int    `xml:"captureNumber"  json:"captureNumber"`
	} `xml:"compress,omitempty"  json:"compress,omitempty"`
}

type SnapshotChannel struct {
	XMLName             xml.Name        `xml:"SnapshotChannel,omitempty"`
	XMLVersion          string          `xml:"version,attr"`
	XMLNamespace        string          `xml:"xmlns,attr"`
	Id                  int             `xml:"id"  json:"id"`
	VideoInputChannelID int             `xml:"videoInputChannelID"  json:"videoInputChannelID"`
	TimingCapture       SnapshotCapture `xml:"timingCapture,omitempty"  json:"timingCapture,omitempty"`
	EventCapture        SnapshotCapture `xml:"eventCapture,omitempty"  json:"eventCapture,omitempty"`
}

type SnapshotChannelList struct {
	XMLName         xml.Name          `xml:"SnapshotChannelList,omitempty"`
	XMLVersion      string            `xml:"version,attr"`
	XMLNamespace    string            `xml:"xmlns,attr"`
	SnapshotChannel []SnapshotChannel `xml:"SnapshotChannel,omitempty"  json:"SnapshotChannel,omitempty"`
}

type TwoWayAudioChannel struct {
	XMLName                     xml.Name `xml:"TwoWayAudioChannel,omitempty"`
	XMLVersion                  string   `xml:"version,attr"`
	XMLNamespace                string   `xml:"xmlns,attr"`
	Id                          string   `xml:"id"  json:"id"`
	Enabled                     bool     `xml:"enabled"  json:"enabled"`
	AudioCompressionType        string   `xml:"audioCompressionType"  json:"audioCompressionType"`
	AudioInboundCompressionType string   `xml:"audioInboundCompressionType,omitempty"  json:"audioInboundCompressionType,omitempty"`
	SpeakerVolume               int      `xml:"speakerVolume,omitempty"  json:"speakerVolume,omitempty"`
	MicrophoneVolume            int      `xml:"microphoneVolume,omitempty"  json:"microphoneVolume,omitempty"`
	Noisereduce                 bool     `xml:"noisereduce,omitempty"  json:"noisereduce,omitempty"`
	AudioBitRate                int      `xml:"audioBitRate,omitempty"  json:"audioBitRate,omitempty"`
	AudioInputType              string   `xml:"audioInputType,omitempty"  json:"audioInputType,omitempty"`
	AssociateVideoInputs        []struct {
		Enabled               bool `xml:"enabled"  json:"enabled"`
		VideoInputChannelList []struct {
			VideoInputChannelID string `xml:"videoInputChannelID,omitempty"  json:"videoInputChannelID,omitempty"`
		} `xml:"videoInputChannelList"  json:"videoInputChannelList"`
	} `xml:"associateVideoInputs,omitempty"  json:"associateVideoInputs,omitempty"`
	LineOutForbidden bool `xml:"lineOutForbidden"  json:"lineOutForbidden"`
	MicInForbidden   bool `xml:"micInForbidden"  json:"micInForbidden"`
}

type TwoWayAudioChannelList struct {
	XMLName            xml.Name             `xml:"TwoWayAudioChannelList,omitempty"`
	XMLVersion         string               `xml:"version,attr"`
	XMLNamespace       string               `xml:"xmlns,attr"`
	TwoWayAudioChannel []TwoWayAudioChannel `xml:"TwoWayAudioChannel,omitempty"  json:"TwoWayAudioChannel,omitempty"`
}

type TwoWayAudioSession struct {
	XMLName      xml.Name `xml:"TwoWayAudioSession,omitempty"`
	XMLVersion   string   `xml:"version,attr"`
	XMLNamespace string   `xml:"xmlns,attr"`
	SessionID    string   `xml:"sessionId,omitempty"  json:"sessionId,omitempty"`
}

type Time struct {
	XMLName           xml.Name `xml:"Time,omitempty"`
	XMLVersion        string   `xml:"version,attr"`
	XMLNamespace      string   `xml:"xmlns,attr"`
	TimeMode          string   `xml:"timeMode"  json:"timeMode"`
	LocalTime         string   `xml:"localTime"  json:"localTime"`
	TimeZone          string   `xml:"timeZone"  json:"timeZone"`
	SatelliteInterval int      `xml:"satelliteInterval"  json:"satelliteInterval"`
}

type NTPServer struct {
	XMLName              xml.Name `xml:"NTPServer,omitempty"`
	XMLVersion           string   `xml:"version,attr"`
	XMLNamespace         string   `xml:"xmlns,attr"`
	Id                   string   `xml:"id"  json:"id"`
	AddressingFormatType string   `xml:"addressingFormatType"  json:"addressingFormatType"`
	HostName             string   `xml:"hostName"  json:"hostName"`
	IpAddress            string   `xml:"ipAddress"  json:"ipAddress"`
	Ipv6Address          string   `xml:"ipv6Address"  json:"ipv6Address"`
	PortNo               int      `xml:"portNo"  json:"portNo"`
	SynchronizeInterval  int      `xml:"synchronizeInterval"  json:"synchronizeInterval"`
}

func (c *IsApiClient) NET_DVR_Login() (*DeviceInfo, error) {
	info := DeviceInfo{}
	err := c.Get("/ISAPI/System/deviceInfo", nil, &info)
	if err != nil {
		return nil, err
	}
	return &info, nil
}

func (c *IsApiClient) NET_DVR_GetFtpConfig(id int) (*FTPNotification, error) {
	ftp := FTPNotification{}
	err := c.Get(fmt.Sprintf("/ISAPI/System/Network/ftp/%d", id), nil, &ftp)
	if err != nil {
		return nil, err
	}
	return &ftp, nil
}

func (c *IsApiClient) NET_DVR_SetFtpConfig(id int, ftp *FTPNotification) (*ResponseStatus, error) {
	ret := ResponseStatus{}
	err := c.Put(fmt.Sprintf("/ISAPI/System/Network/ftp/%d", id), ftp, &ret)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func (c *IsApiClient) Net_DVR_TestFtp(ftp *FTPTestDescription) (*FTPTestResult, error) {
	ret := FTPTestResult{}
	err := c.Post("/ISAPI/System/Network/ftp/test", ftp, &ret)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func (c *IsApiClient) Net_DVR_GetRecordConfig(id int) (*Track, error) {
	track := Track{}
	err := c.Get(fmt.Sprintf("/ISAPI/ContentMgmt/record/tracks/%d", id), nil, &track)
	if err != nil {
		return nil, err
	}
	return &track, nil
}

func (c *IsApiClient) Net_DVR_SetRecordConfig(id int, track *Track) (*ResponseStatus, error) {
	ret := ResponseStatus{}
	err := c.Put(fmt.Sprintf("/ISAPI/ContentMgmt/record/tracks/%d", id), track, &ret)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func (c *IsApiClient) Net_DVR_GetSnapshotConfig(id int) (*SnapshotChannel, error) {
	channel := SnapshotChannel{}
	err := c.Get(fmt.Sprintf("/ISAPI/Snapshot/channels/%d", id), nil, &channel)
	if err != nil {
		return nil, err
	}
	return &channel, nil
}

func (c *IsApiClient) Net_DVR_SetSnapshotConfig(id int, channel *SnapshotChannel) (*ResponseStatus, error) {
	ret := ResponseStatus{}
	err := c.Put(fmt.Sprintf("/ISAPI/Snapshot/channels/%d", id), channel, &ret)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func (c *IsApiClient) Net_DVR_GetTimeConfig() (*Time, error) {
	time := Time{}
	err := c.Get("/ISAPI/System/time", nil, &time)
	if err != nil {
		return nil, err
	}
	return &time, nil
}

func (c *IsApiClient) Net_DVR_SetTimeConfig(time *Time) (*ResponseStatus, error) {
	ret := ResponseStatus{}
	err := c.Put("/ISAPI/System/time", time, &ret)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func (c *IsApiClient) Net_DVR_GetTimeNtpConfig(id int) (*NTPServer, error) {
	ntp := NTPServer{}
	err := c.Get(fmt.Sprintf("/ISAPI/System/time/ntpServers/%d", id), nil, &ntp)
	if err != nil {
		return nil, err
	}
	return &ntp, nil
}

func (c *IsApiClient) Net_DVR_SetTimeNtpConfig(id int, ntp *NTPServer) (*ResponseStatus, error) {
	ret := ResponseStatus{}
	err := c.Put(fmt.Sprintf("/ISAPI/System/time/ntpServers/%d", id), ntp, &ret)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func (c *IsApiClient) Net_DVR_GetAudioChannelList() (*TwoWayAudioChannelList, error) {
	list := TwoWayAudioChannelList{}
	err := c.Get("/ISAPI/System/TwoWayAudio/channels", nil, &list)
	if err != nil {
		return nil, err
	}
	return &list, nil
}

func (c *IsApiClient) Net_DVR_GetAudioChannel(id int) (*TwoWayAudioChannel, error) {
	channel := TwoWayAudioChannel{}
	err := c.Get(fmt.Sprintf("/ISAPI/System/TwoWayAudio/channels/%d", id), nil, &channel)
	if err != nil {
		return nil, err
	}
	return &channel, nil
}

func (c *IsApiClient) Net_DVR_SetAudioChannel(id int, channel *TwoWayAudioChannel) (*ResponseStatus, error) {
	ret := ResponseStatus{}
	err := c.Put(fmt.Sprintf("/ISAPI/System/TwoWayAudio/channels/%d", id), channel, &ret)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func (c *IsApiClient) Net_DVR_StartVoiceCom(id int) (*TwoWayAudioSession, error) {
	dummy := RequestEmpty{}
	session := TwoWayAudioSession{}
	err := c.Put(fmt.Sprintf("/ISAPI/System/TwoWayAudio/channels/%d/open", id), &dummy, &session)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (c *IsApiClient) NET_DVR_VoiceComSendData(id int, r io.Reader) (*ResponseStatus, error) {
	ret := ResponseStatus{}
	ar := NewAudioReader(r)
	err := c.PutBinary(fmt.Sprintf("/ISAPI/System/TwoWayAudio/channels/%d/audioData", id), ar, &ret)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func (c *IsApiClient) NET_DVR_StopVoiceCom(id int) (*ResponseStatus, error) {
	dummy := RequestEmpty{}
	ret := ResponseStatus{}
	err := c.Put(fmt.Sprintf("/ISAPI/System/TwoWayAudio/channels/%d/close", id), &dummy, &ret)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}
