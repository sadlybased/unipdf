package license

import (
	bytes "bytes"
	gzip "compress/gzip"
	crypto "crypto"
	aes "crypto/aes"
	cipher "crypto/cipher"
	hmac "crypto/hmac"
	rand "crypto/rand"
	rsa "crypto/rsa"
	sha256 "crypto/sha256"
	sha512 "crypto/sha512"
	x509 "crypto/x509"
	base64 "encoding/base64"
	hex "encoding/hex"
	json "encoding/json"
	pem "encoding/pem"
	errors "errors"
	fmt "fmt"
	common "github.com/unidoc/unipdf/v5/common"
	io "io"
	net "net"
	http "net/http"
	os "os"
	filepath "path/filepath"
	sort "sort"
	strings "strings"
	sync "sync"
	time "time"
)

type reportState struct {
	Instance      string         `json:"inst"`
	Next          string         `json:"n"`
	Docs          int64          `json:"d"`
	NumErrors     int64          `json:"e"`
	LimitDocs     bool           `json:"ld"`
	RemainingDocs int64          `json:"rd"`
	LastReported  time.Time      `json:"lr"`
	LastWritten   time.Time      `json:"lw"`
	Usage         map[string]int `json:"u"`
	UsageLogs     []interface{}  `json:"ul,omitempty"`
}

func SetMeteredKeyPersistentCache(val bool) { currentLicenseKey.persistentCache = val }

type meteredUsageCheckinForm struct {
	Instance          string         `json:"inst"`
	Next              string         `json:"next"`
	UsageNumber       int            `json:"usage_number"`
	NumFailed         int64          `json:"num_failed"`
	Hostname          string         `json:"hostname"`
	LocalIP           string         `json:"local_ip"`
	MacAddress        string         `json:"mac_address"`
	Package           string         `json:"package"`
	PackageVersion    string         `json:"package_version"`
	Usage             map[string]int `json:"u"`
	IsPersistentCache bool           `json:"is_persistent_cache"`
	Timestamp         int64          `json:"timestamp"`
	UsageLogs         []interface{}  `json:"ul,omitempty"`
}

var minimumCreatedAt = time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)

func gzipJSON(local001 []byte) (io.Reader, error) {
	buffer := new(bytes.Buffer)
	gzipWriter := gzip.NewWriter(buffer)
	gzipWriter.Write(local001)
	err_acb := gzipWriter.Close()
	if err_acb != nil {
		return nil, err_acb
	}
	return buffer, nil
}

type meteredClient struct {
	local002 string
	local003 string
	local004 *http.Client
}
type MeteredStatus struct {
	OK      bool
	Credits int64
	Used    int64
}

func getHomeDir() string {
	homeDir := os.Getenv("HOME")
	if len(homeDir) == 0 {
		homeDir, _ = os.UserHomeDir()
	}
	return homeDir
}
func Track(docKey string, useKey string, docName string) error {
	return trackUsage(docKey, useKey, docName, !currentLicenseKey.persistentCache)
}
func signUsagePayload(local005, local006 string) string {
	keyBytes := []byte(local005)
	mac := hmac.New(sha256.New, keyBytes)
	mac.Write([]byte(local006))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
func SetLicenseKey(content string, customerName string) error {
	license, err_cegd := decodeLicense(content)
	if err_cegd != nil {
		common.Log.Error("License code decode error: %v", err_cegd)
		return err_cegd
	}
	if !strings.EqualFold(license.CustomerName, customerName) {
		common.Log.Error("License code issue - Customer name mismatch, expected '%s', but got '%s'", license.CustomerName, customerName)
		return fmt.Errorf("customer name mismatch, expected '%s', but got '%s'", license.CustomerName, customerName)
	}
	err_cegd = license.Validate()
	if err_cegd != nil {
		common.Log.Error("License code validation error: %v", err_cegd)
		return err_cegd
	}
	currentLicenseKey = &license
	return nil
}

var unipdfValidationDate = time.Date(2019, 6, 6, 0, 0, 0, 0, time.UTC)

func decodeLicense(local007 string) (LicenseKey, error) {
	var local008 LicenseKey
	signedPayload, err_eab := extractSignedPayload(licenseHeader, licenseFooter, local007)
	if err_eab != nil {
		return local008, err_eab
	}
	status, err_eab := verifyLicensePayload(publicKeyPEM, signedPayload)
	if err_eab != nil {
		return local008, err_eab
	}
	err_eab = json.Unmarshal(status, &local008)
	if err_eab != nil {
		return local008, err_eab
	}
	local008.CreatedAt = time.Unix(local008.CreatedAtInt, 0)
	if local008.ExpiresAtInt > 0 {
		local009 := time.Unix(local008.ExpiresAtInt, 0)
		local008.ExpiresAt = &local009
	}
	return local008, nil
}
func getNetworkIdentity() ([]string, []string, error) {
	local010, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	var macAddresses []string
	var ipAddresses []string
	for _, iface := range local010 {
		if iface.Flags&net.FlagUp == 0 || bytes.Equal(iface.HardwareAddr, nil) {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, nil, err
		}
		ipv4Count := 0
		for _, addr := range addresses {
			var ip net.IP
			switch ipAddr := addr.(type) {
			case *net.IPNet:
				ip = ipAddr.IP
			case *net.IPAddr:
				ip = ipAddr.IP
			}
			if ip.IsLoopback() {
				continue
			}
			if ip.To4() == nil {
				continue
			}
			ipAddresses = append(ipAddresses, ip.String())
			ipv4Count++
		}
		mac := iface.HardwareAddr.String()
		if mac != "" && ipv4Count > 0 {
			macAddresses = append(macAddresses, mac)
		}
	}
	return macAddresses, ipAddresses, nil
}

type meteredStatusResp struct {
	Valid        bool  `json:"valid"`
	OrgCredits   int64 `json:"org_credits"`
	OrgUsed      int64 `json:"org_used"`
	OrgRemaining int64 `json:"org_remaining"`
}

var trackedDocKeys map[string]struct{}

type meteredUsageCheckinResp struct {
	Instance      string `json:"inst"`
	Next          string `json:"next"`
	Success       bool   `json:"success"`
	Message       string `json:"message"`
	RemainingDocs int    `json:"rd"`
	LimitDocs     bool   `json:"ld"`
}

func (local011 *LicenseKey) getExpiryDateToCompare() time.Time {
	if local011.Trial {
		return time.Now().UTC()
	}
	return common.ReleasedAt
}

var currentLicenseKey = MakeUnlicensedKey()

const (
	licenseHeader = "-----BEGIN UNIDOC LICENSE KEY-----"
	licenseFooter = "-----END UNIDOC LICENSE KEY-----"
)

var meteredValidationDate = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

func signWithPrivateKey(local012 string, local013 []byte) (string, error) {
	local014, _ := pem.Decode([]byte(local012))
	if local014 == nil {
		return "", fmt.Errorf("PrivKey failed")
	}
	local015, local016 := x509.ParsePKCS1PrivateKey(local014.Bytes)
	if local016 != nil {
		return "", local016
	}
	local017 := sha512.New()
	local017.Write(local013)
	local018 := local017.Sum(nil)
	local019, local016 := rsa.SignPKCS1v15(rand.Reader, local015, crypto.SHA512, local018)
	if local016 != nil {
		return "", local016
	}
	local020 := base64.StdEncoding.EncodeToString(local013)
	local020 += "\n+\n"
	local020 += base64.StdEncoding.EncodeToString(local019)
	return local020, nil
}
func (license *LicenseKey) ToString() string {
	if license.metered {
		return "Metered subscription"
	}
	output := fmt.Sprintf("License Id: %s\n", license.LicenseId)
	output += fmt.Sprintf("Customer Id: %s\n", license.CustomerId)
	output += fmt.Sprintf("Customer Name: %s\n", license.CustomerName)
	output += fmt.Sprintf("Tier: %s\n", license.Tier)
	output += fmt.Sprintf("Created At: %s\n", common.UtcTimeFormat(license.CreatedAt))
	if license.ExpiresAt == nil {
		output += "Expires At: Never\n"
	} else {
		output += fmt.Sprintf("Expires At: %s\n", common.UtcTimeFormat(*license.ExpiresAt))
	}
	output += fmt.Sprintf("Creator: %s <%s>\n", license.CreatorName, license.CreatorEmail)
	return output
}
func extractSignedPayload(local021 string, local022 string, encodedLicense string) (string, error) {
	headerIndex := strings.Index(encodedLicense, local021)
	if headerIndex == -1 {
		return "", fmt.Errorf("header not found")
	}
	footerIndex := strings.Index(encodedLicense, local022)
	if footerIndex == -1 {
		return "", fmt.Errorf("footer not found")
	}
	payloadStart := headerIndex + len(local021) + 1
	return encodedLicense[payloadStart : footerIndex-1], nil
}
func GetMeteredState() (MeteredStatus, error) {
	if currentLicenseKey == nil {
		return MeteredStatus{}, errors.New("license key not set")
	}
	if !currentLicenseKey.metered || len(currentLicenseKey.apiKey) == 0 {
		return MeteredStatus{}, errors.New("api key not set")
	}
	state, local023 := stateStore.loadState(currentLicenseKey.apiKey)
	if local023 != nil {
		common.Log.Debug("ERROR: %v", local023)
		return MeteredStatus{}, local023
	}
	if state.Docs > 0 {
		local024 := trackUsage("", "", "", true)
		if local024 != nil {
			return MeteredStatus{}, local024
		}
	}
	usageMutex.Lock()
	defer usageMutex.Unlock()
	local025 := newMeteredClient()
	local025.local003 = currentLicenseKey.apiKey
	status, local023 := local025.getStatus()
	if local023 != nil {
		return MeteredStatus{}, local023
	}
	if !status.Valid {
		return MeteredStatus{}, errors.New("key not valid")
	}
	meteredStatus := MeteredStatus{OK: true, Credits: status.OrgCredits, Used: status.OrgUsed}
	return meteredStatus, nil
}

var stateStore stateLoader = defaultStateHolder{}

type defaultStateHolder struct{}

func (local026 *LicenseKey) isExpired() bool {
	return local026.getExpiryDateToCompare().After(*local026.ExpiresAt)
}
func (local027 defaultStateHolder) updateState(apiKey, instance, next string, docs int, limitDocs bool, remainingDocs int, numErrors int, lastReported time.Time, usage map[string]int, usageLogs ...interface{}) error {
	local028, err_fd := licenseDirectory()
	if err_fd != nil {
		return err_fd
	}
	if len(apiKey) < 20 {
		return errors.New("invalid key")
	}
	keyBytes := []byte(apiKey)
	keyHash := sha512.Sum512_256(keyBytes[:20])
	keyHashHex := hex.EncodeToString(keyHash[:])
	statePath := filepath.Join(local028, keyHashHex)
	var state reportState
	state.Docs = int64(docs)
	state.NumErrors = int64(numErrors)
	state.LimitDocs = limitDocs
	state.RemainingDocs = int64(remainingDocs)
	state.LastWritten = time.Now().UTC()
	state.LastReported = lastReported
	state.Instance = instance
	state.Next = next
	state.Usage = usage
	state.UsageLogs = usageLogs
	encodedState, err_fd := json.Marshal(state)
	if err_fd != nil {
		return err_fd
	}
	const local029 = "ha9NK8]RbL*m4LKW"
	encodedState, err_fd = encryptState([]byte(local029), encodedState)
	if err_fd != nil {
		return err_fd
	}
	err_fd = os.WriteFile(statePath, encodedState, 0600)
	if err_fd != nil {
		return err_fd
	}
	return nil
}
func (local030 *LicenseKey) TypeToString() string {
	if local030.metered {
		return "Metered subscription"
	}
	if local030.Tier == LicenseTierUnlicensed {
		return "Unlicensed"
	}
	if local030.Tier == LicenseTierCommunity {
		return "AGPLv3 Open Source Community License"
	}
	if local030.Tier == LicenseTierIndividual || local030.Tier == "indie" {
		return "Commercial License - Individual"
	}
	return "Commercial License - Business"
}
func responseBody(local031 *http.Response) (io.ReadCloser, error) {
	var local032 error
	var local033 io.ReadCloser
	switch strings.ToLower(local031.Header.Get("Content-Encoding")) {
	case "gzip":
		local033, local032 = gzip.NewReader(local031.Body)
		if local032 != nil {
			return local033, local032
		}
		defer local033.Close()
	default:
		local033 = local031.Body
	}
	return local033, nil
}

const customerNameEnv = "UNIPDF_CUSTOMER_NAME"
const publicKeyPEM = "\n-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmFUiyd7b5XjpkP5Rap4w\nDc1dyzIQ4LekxrvytnEMpNUbo6iA74V8ruZOvrScsf2QeN9/qrUG8qEbUWdoEYq+\notFNAFNxlGbxbDHcdGVaM0OXdXgDyL5aIEagL0c5pwjIdPGIn46f78eMJ+JkdcpD\nDJaqYXdrz5KeshjSiIaa7menBIAXS4UFxNfHhN0HCYZYqQG7bK+s5rRHonydNWEG\nH8Myvr2pya2KrMumfmAxUB6fenC/4O0Wr8gfPOU8RitmbDvQPIRXOL4vTBrBdbaA\n9nwNP+i//20MT2bxmeWB+gpcEhGpXZ733azQxrC3J4v3CZmENStDK/KDSPKUGfu6\nfwIDAQAB\n-----END PUBLIC KEY-----\n"

func SetMeteredKeyUsageLogVerboseMode(val bool) { currentLicenseKey.verboseUsageLog = val }
func (local034 defaultStateHolder) loadState(local035 string) (reportState, error) {
	dir, err_cfgbd := licenseDirectory()
	if err_cfgbd != nil {
		return reportState{}, err_cfgbd
	}
	err_cfgbd = os.MkdirAll(dir, 0777)
	if err_cfgbd != nil {
		return reportState{}, err_cfgbd
	}
	if len(local035) < 20 {
		return reportState{}, errors.New("invalid key")
	}
	local036 := []byte(local035)
	local037 := sha512.Sum512_256(local036[:20])
	local038 := hex.EncodeToString(local037[:])
	statePath := filepath.Join(dir, local038)
	encryptedState, err_cfgbd := os.ReadFile(statePath)
	if err_cfgbd != nil {
		if os.IsNotExist(err_cfgbd) {
			return reportState{}, nil
		}
		common.Log.Debug("ERROR: %v", err_cfgbd)
		return reportState{}, errors.New("invalid data")
	}
	const local039 = "ha9NK8]RbL*m4LKW"
	encryptedState, err_cfgbd = decryptState([]byte(local039), encryptedState)
	if err_cfgbd != nil {
		return reportState{}, err_cfgbd
	}
	var state reportState
	err_cfgbd = json.Unmarshal(encryptedState, &state)
	if err_cfgbd != nil {
		common.Log.Debug("ERROR: Invalid data: %v", err_cfgbd)
		return reportState{}, errors.New("invalid data")
	}
	return state, nil
}

const (
	LicenseTierUnlicensed = "unlicensed"
	LicenseTierCommunity  = "community"
	LicenseTierIndividual = "individual"
	LicenseTierBusiness   = "business"
)

func (client *meteredClient) getStatus() (meteredStatusResp, error) {
	var response meteredStatusResp
	local040 := client.local002 + "/metered/status"
	var form meteredStatusForm
	body, err_agff := json.Marshal(form)
	if err_agff != nil {
		return response, err_agff
	}
	compressedBody, err_agff := gzipJSON(body)
	if err_agff != nil {
		return response, err_agff
	}
	request, err_agff := http.NewRequest("POST", local040, compressedBody)
	if err_agff != nil {
		return response, err_agff
	}
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Content-Encoding", "gzip")
	request.Header.Add("Accept-Encoding", "gzip")
	request.Header.Add("X-API-KEY", client.local003)
	httpResponse, err_agff := client.local004.Do(request)
	if err_agff != nil {
		return response, err_agff
	}
	defer httpResponse.Body.Close()
	if httpResponse.StatusCode != 200 {
		return response, fmt.Errorf("failed to checkin, status code is: %d", httpResponse.StatusCode)
	}
	body, err_agff = readResponseBody(httpResponse)
	if err_agff != nil {
		return response, err_agff
	}
	err_agff = json.Unmarshal(body, &response)
	if err_agff != nil {
		return response, err_agff
	}
	return response, nil
}

var usageLogEntries []interface{}

func SetMeteredKey(apiKey string) error {
	if len(apiKey) == 0 {
		common.Log.Error("Metered License API Key must not be empty")
		common.Log.Error("- Grab one in the Free Tier at https://cloud.unidoc.io")
		return fmt.Errorf("metered license api key must not be empty: create one at https://cloud.unidoc.io")
	}
	if currentLicenseKey != nil && (currentLicenseKey.metered || currentLicenseKey.Tier != LicenseTierUnlicensed) {
		common.Log.Error("ERROR: Cannot set license key twice - Should just initialize once")
		return errors.New("license key already set")
	}
	client := newMeteredClient()
	client.local003 = apiKey
	status, err_da := client.getStatus()
	if err_da != nil {
		return err_da
	}
	if !status.Valid {
		return errors.New("key not valid")
	}
	license := &LicenseKey{metered: true, apiKey: apiKey, persistentCache: true}
	currentLicenseKey = license
	return nil
}

type meteredStatusForm struct{}
type LicenseKey struct {
	LicenseId       string     `json:"license_id"`
	CustomerId      string     `json:"customer_id"`
	CustomerName    string     `json:"customer_name"`
	Tier            string     `json:"tier"`
	CreatedAt       time.Time  `json:"-"`
	CreatedAtInt    int64      `json:"created_at"`
	ExpiresAt       *time.Time `json:"-"`
	ExpiresAtInt    int64      `json:"expires_at"`
	CreatedBy       string     `json:"created_by"`
	CreatorName     string     `json:"creator_name"`
	CreatorEmail    string     `json:"creator_email"`
	UniPDF          bool       `json:"unipdf"`
	UniOffice       bool       `json:"unioffice"`
	UniHTML         bool       `json:"unihtml"`
	Trial           bool       `json:"trial"`
	metered         bool
	apiKey          string
	persistentCache bool
	verboseUsageLog bool
}

func encryptState(local041, local042 []byte) ([]byte, error) {
	local043, local044 := aes.NewCipher(local041)
	if local044 != nil {
		return nil, local044
	}
	encrypted := make([]byte, aes.BlockSize+len(local042))
	iv := encrypted[:aes.BlockSize]
	if _, local045 := io.ReadFull(rand.Reader, iv); local045 != nil {
		return nil, local045
	}
	encrypter := cipher.NewCFBEncrypter(local043, iv)
	encrypter.XORKeyStream(encrypted[aes.BlockSize:], local042)
	encoded := make([]byte, base64.URLEncoding.EncodedLen(len(encrypted)))
	base64.URLEncoding.Encode(encoded, encrypted)
	return encoded, nil
}
func (local046 *LicenseKey) Validate() error {
	if local046.metered {
		return nil
	}
	if len(local046.LicenseId) < 10 {
		return fmt.Errorf("invalid license: License Id")
	}
	if len(local046.CustomerId) < 10 {
		return fmt.Errorf("invalid license: Customer Id")
	}
	if len(local046.CustomerName) < 1 {
		return fmt.Errorf("invalid license: Customer Name")
	}
	if minimumCreatedAt.After(local046.CreatedAt) {
		return fmt.Errorf("invalid license: Created At is invalid")
	}
	if local046.ExpiresAt == nil {
		local047 := local046.CreatedAt.AddDate(1, 0, 0)
		if meteredValidationDate.After(local047) {
			local047 = meteredValidationDate
		}
		local046.ExpiresAt = &local047
	}
	if local046.CreatedAt.After(*local046.ExpiresAt) {
		return fmt.Errorf("invalid license: Created At cannot be Greater than Expires At")
	}
	if local046.isExpired() {
		local048 := "The license has already expired.\n" + "You may need to update the license key to the newest license key for your organization.\n" + "To find your newest license key, go to https://cloud.unidoc.io and go to the license menu."
		return fmt.Errorf("invalid license: %s", local048)
	}
	if len(local046.CreatorName) < 1 {
		return fmt.Errorf("invalid license: Creator name")
	}
	if len(local046.CreatorEmail) < 1 {
		return fmt.Errorf("invalid license: Creator email")
	}
	if local046.CreatedAt.After(unipdfValidationDate) {
		if !local046.UniPDF {
			return fmt.Errorf("invalid license: This UniDoc key is invalid for UniPDF")
		}
	}
	return nil
}

const licenseDirEnv = "UNIDOC_LICENSE_DIR"

func licenseDirectory() (string, error) {
	licenseDir := strings.TrimSpace(os.Getenv(licenseDirEnv))
	if licenseDir == "" {
		common.Log.Debug("$%s environment variable not found. Will use home directory to store license information.", licenseDirEnv)
		homeDir := getHomeDir()
		if len(homeDir) == 0 {
			return "", fmt.Errorf("required $%s environment variable or home directory not found", licenseDirEnv)
		}
		licenseDir = filepath.Join(homeDir, ".unidoc")
	}
	err := os.MkdirAll(licenseDir, 0777)
	if err != nil {
		return "", err
	}
	return licenseDir, nil
}

var usageCounts map[string]int

func decryptState(local049, local050 []byte) ([]byte, error) {
	decoded := make([]byte, base64.URLEncoding.DecodedLen(len(local050)))
	decodedLen, err_aad := base64.URLEncoding.Decode(decoded, local050)
	if err_aad != nil {
		return nil, err_aad
	}
	decoded = decoded[:decodedLen]
	block, err_aad := aes.NewCipher(local049)
	if err_aad != nil {
		return nil, err_aad
	}
	if len(decoded) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := decoded[:aes.BlockSize]
	decoded = decoded[aes.BlockSize:]
	decryptor := cipher.NewCFBDecrypter(block, iv)
	decryptor.XORKeyStream(decoded, decoded)
	return decoded, nil
}
func MakeUnlicensedKey() *LicenseKey {
	license := LicenseKey{}
	license.CustomerName = "Business"
	license.Tier = LicenseTierBusiness
	license.CreatedAt = time.Now().UTC()
	license.CreatedAtInt = license.CreatedAt.Unix()
	return &license
}
func readResponseBody(local051 *http.Response) ([]byte, error) {
	var local052 []byte
	body, err_dgcd := responseBody(local051)
	if err_dgcd != nil {
		return local052, err_dgcd
	}
	return io.ReadAll(body)
}
func (local053 *meteredClient) checkinUsage(checkin meteredUsageCheckinForm) (meteredUsageCheckinResp, error) {
	checkin.Package = "unipdf"
	checkin.PackageVersion = common.Version
	var local054 meteredUsageCheckinResp
	url := local053.local002 + "/metered/usage_checkin"
	body, err_dbg := json.Marshal(checkin)
	if err_dbg != nil {
		return local054, err_dbg
	}
	compressedBody, err_dbg := gzipJSON(body)
	if err_dbg != nil {
		return local054, err_dbg
	}
	request, err_dbg := http.NewRequest("POST", url, compressedBody)
	if err_dbg != nil {
		return local054, err_dbg
	}
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Content-Encoding", "gzip")
	request.Header.Add("Accept-Encoding", "gzip")
	request.Header.Add("X-API-KEY", local053.local003)
	response, err_dbg := local053.local004.Do(request)
	if err_dbg != nil {
		return local054, err_dbg
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		local055, err_bac := readResponseBody(response)
		if err_bac != nil {
			return local054, err_bac
		}
		err_bac = json.Unmarshal(local055, &local054)
		if err_bac != nil {
			return local054, err_bac
		}
		return local054, fmt.Errorf("failed to checkin, status code is: %d", response.StatusCode)
	}
	local056 := response.Header.Get("X-UC-Signature")
	local057 := signUsagePayload(checkin.MacAddress, string(body))
	if local057 != local056 {
		common.Log.Error("Invalid response signature, set the license server to https://cloud.unidoc.io/api")
		return local054, errors.New("failed to checkin, invalid server response")
	}
	local058, err_dbg := readResponseBody(response)
	if err_dbg != nil {
		return local054, err_dbg
	}
	err_dbg = json.Unmarshal(local058, &local054)
	if err_dbg != nil {
		return local054, err_dbg
	}
	return local054, nil
}
func getExternalIP() (net.IP, error) {
	local059, local060 := net.Dial("udp", "8.8.8.8:80")
	if local060 != nil {
		return nil, local060
	}
	defer local059.Close()
	local061 := local059.LocalAddr().(*net.UDPAddr)
	return local061.IP, nil
}
func init() {
	licensePath := os.Getenv(licensePathEnv)
	customerName := os.Getenv(customerNameEnv)
	if len(licensePath) == 0 || len(customerName) == 0 {
		return
	}
	licenseBytes, err_fcdd := os.ReadFile(licensePath)
	if err_fcdd != nil {
		common.Log.Error("Unable to read license code file: %v", err_fcdd)
		return
	}
	err_fcdd = SetLicenseKey(string(licenseBytes), customerName)
	if err_fcdd != nil {
		common.Log.Error("Unable to load license code: %v", err_fcdd)
		return
	}
}
func verifyLicensePayload(publicKey string, signedData string) ([]byte, error) {
	var (
		separatorIndex int
		separator      string
	)
	for _, separator = range []string{"\n+\n", "\r\n+\r\n", " + "} {
		if separatorIndex = strings.Index(signedData, separator); separatorIndex != -1 {
			break
		}
	}
	if separatorIndex == -1 {
		return nil, fmt.Errorf("invalid input, signature separator")
	}
	encodedOriginal := signedData[:separatorIndex]
	signatureStart := separatorIndex + len(separator)
	encodedSignature := signedData[signatureStart:]
	if encodedOriginal == "" || encodedSignature == "" {
		return nil, fmt.Errorf("invalid input, missing original or signature")
	}
	original, err_cac := base64.StdEncoding.DecodeString(encodedOriginal)
	if err_cac != nil {
		return nil, fmt.Errorf("invalid input original")
	}
	signature, err_cac := base64.StdEncoding.DecodeString(encodedSignature)
	if err_cac != nil {
		return nil, fmt.Errorf("invalid input signature")
	}
	publicKeyBlock, _ := pem.Decode([]byte(publicKey))
	if publicKeyBlock == nil {
		return nil, fmt.Errorf("PubKey failed")
	}
	parsedKey, err_cac := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err_cac != nil {
		return nil, err_cac
	}
	rsaPublicKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok || rsaPublicKey == nil {
		return nil, fmt.Errorf("PubKey conversion failed")
	}
	hash := sha512.New()
	hash.Write(original)
	digest := hash.Sum(nil)
	err_cac = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA512, digest, signature)
	if err_cac != nil {
		return nil, err_cac
	}
	return original, nil
}

type stateLoader interface {
	loadState(local062 string) (reportState, error)
	updateState(local063, local064, local065 string, local066 int, local067 bool, local068 int, local069 int, local070 time.Time, local071 map[string]int, local072 ...interface{}) error
}

func GetLicenseKey() *LicenseKey {
	if currentLicenseKey == nil {
		return nil
	}
	local073 := *currentLicenseKey
	return &local073
}
func (local074 *LicenseKey) IsLicensed() bool {
	return local074.Tier != LicenseTierUnlicensed || local074.metered
}
func newMeteredClient() *meteredClient {
	local075 := meteredClient{local002: "https://cloud.unidoc.io/api", local004: &http.Client{Timeout: 30 * time.Second}}
	if local076 := os.Getenv("UNIDOC_LICENSE_SERVER_URL"); strings.HasPrefix(local076, "http") {
		local075.local002 = local076
	}
	return &local075
}
func trackUsage(local077 string, local078 string, local079 string, local080 bool) error {
	if currentLicenseKey == nil {
		return errors.New("no license key")
	}
	if !currentLicenseKey.metered || len(currentLicenseKey.apiKey) == 0 {
		return nil
	}
	if len(local077) == 0 && !local080 {
		return errors.New("docKey not set")
	}
	usageMutex.Lock()
	defer usageMutex.Unlock()
	if trackedDocKeys == nil {
		trackedDocKeys = map[string]struct{}{}
	}
	if usageCounts == nil {
		usageCounts = map[string]int{}
	}
	creditCost := 0
	if len(local077) > 0 {
		_, local081 := trackedDocKeys[local077]
		if !local081 {
			trackedDocKeys[local077] = struct{}{}
			creditCost++
		}
		if currentLicenseKey.verboseUsageLog {
			usageLogEntries = append(usageLogEntries, map[string]interface{}{"time": time.Now().String(), "func": local078, "ref": local077[:8], "file": local079, "cost": creditCost})
			if local081 && creditCost == 0 {
				common.Log.Info("%s Ref: %s | %s | No credit used", time.Now().String(), local077[:8], local078)
			}
		}
	}
	if creditCost == 0 && !local080 {
		return nil
	}
	usageCounts[local078]++
	now := time.Now()
	state, err := stateStore.loadState(currentLicenseKey.apiKey)
	if err != nil {
		common.Log.Debug("ERROR: %v", err)
		return err
	}
	state.UsageLogs = append(state.UsageLogs, usageLogEntries...)
	if state.Usage == nil {
		state.Usage = map[string]int{}
	}
	for local082, local083 := range usageCounts {
		if local082 != "" {
			state.Usage[local082] += local083
		}
	}
	usageCounts = nil
	const local084 = 24 * time.Hour
	const local085 = 3 * 24 * time.Hour
	if len(state.Instance) == 0 || now.Sub(state.LastReported) > local084 || (state.LimitDocs && state.RemainingDocs <= state.Docs+int64(creditCost)) || local080 {
		hostname, err_cfd := os.Hostname()
		if err_cfd != nil {
			return err_cfd
		}
		usageNumber := state.Docs
		macAddresses, ipAddresses, err_cfd := getNetworkIdentity()
		if err_cfd != nil {
			common.Log.Debug("Unable to get local address: %s", err_cfd.Error())
			macAddresses = append(macAddresses, "information not available")
			ipAddresses = append(ipAddresses, "information not available")
		} else {
			sort.Strings(ipAddresses)
			sort.Strings(macAddresses)
			externalIP, err_eaeb := getExternalIP()
			if err_eaeb != nil {
				return err_eaeb
			}
			found := false
			for _, ip := range ipAddresses {
				if ip == externalIP.String() {
					found = true
				}
			}
			if !found {
				ipAddresses = append(ipAddresses, externalIP.String())
			}
		}
		client := newMeteredClient()
		client.local003 = currentLicenseKey.apiKey
		usageNumber += int64(creditCost)
		checkin := meteredUsageCheckinForm{Instance: state.Instance, Next: state.Next, UsageNumber: int(usageNumber), NumFailed: state.NumErrors, Hostname: hostname, LocalIP: strings.Join(ipAddresses, ", "), MacAddress: strings.Join(macAddresses, ", "), Package: "unipdf", PackageVersion: common.Version, Usage: state.Usage, IsPersistentCache: currentLicenseKey.persistentCache, Timestamp: now.Unix()}
		if len(macAddresses) == 0 {
			checkin.MacAddress = "none"
		}
		if currentLicenseKey.verboseUsageLog {
			checkin.UsageLogs = state.UsageLogs
		}
		reportedDocs := int64(0)
		numErrors := state.NumErrors
		lastReported := now
		remainingDocs := 0
		limitDocs := state.LimitDocs
		checkinResponse, err_cfd := client.checkinUsage(checkin)
		if err_cfd != nil {
			if now.Sub(state.LastReported) > local085 {
				if !checkinResponse.Success {
					return errors.New(checkinResponse.Message)
				}
				return errors.New("too long since last successful checkin")
			}
			reportedDocs = usageNumber
			numErrors++
			lastReported = state.LastReported
		} else {
			limitDocs = checkinResponse.LimitDocs
			remainingDocs = checkinResponse.RemainingDocs
			numErrors = 0
		}
		if len(checkinResponse.Instance) == 0 {
			checkinResponse.Instance = checkin.Instance
		}
		if len(checkinResponse.Next) == 0 {
			checkinResponse.Next = checkin.Next
		}
		err_cfd = stateStore.updateState(client.local003, checkinResponse.Instance, checkinResponse.Next, int(reportedDocs), limitDocs, remainingDocs, int(numErrors), lastReported, nil)
		if err_cfd != nil {
			return err_cfd
		}
		if !checkinResponse.Success {
			return fmt.Errorf("error: %s", checkinResponse.Message)
		}
	} else {
		err = stateStore.updateState(currentLicenseKey.apiKey, state.Instance, state.Next, int(state.Docs)+creditCost, state.LimitDocs, int(state.RemainingDocs), int(state.NumErrors), state.LastReported, state.Usage, state.UsageLogs...)
		if err != nil {
			return err
		}
	}
	if currentLicenseKey.verboseUsageLog && len(local077) > 0 {
		local086 := ""
		if local079 != "" {
			local086 = fmt.Sprintf("File %s |", local079)
		}
		common.Log.Info("%s | %s Ref: %s | %s | %d credit(s) used", now.String(), local086, local077[:8], local078, creditCost)
	}
	return nil
}

const licensePathEnv = "UNIPDF_LICENSE_PATH"

func TrackUse(useKey string) {
	if currentLicenseKey == nil {
		return
	}
	if !currentLicenseKey.metered || len(currentLicenseKey.apiKey) == 0 {
		return
	}
	if len(useKey) == 0 {
		return
	}
	usageMutex.Lock()
	defer usageMutex.Unlock()
	if usageCounts == nil {
		usageCounts = map[string]int{}
	}
	usageCounts[useKey]++
}

var usageMutex = &sync.Mutex{}
