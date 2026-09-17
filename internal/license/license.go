package license

const (
	LicenseTierUnlicensed = "unlicensed"
	LicenseTierCommunity  = "community"
	LicenseTierIndividual = "individual"
	LicenseTierBusiness   = "business"
)

type MeteredStatus struct{}

type LicenseKey struct{}

var businessLicense = &LicenseKey{}

func SetLicenseKey(string, string) error      { return nil }
func SetMeteredKey(string) error              { return nil }
func SetMeteredKeyPersistentCache(bool)       {}
func SetMeteredKeyUsageLogVerboseMode(bool)   {}
func GetMeteredState() (MeteredStatus, error) { return MeteredStatus{}, nil }

func MakeUnlicensedKey() *LicenseKey { return businessLicense }
func GetLicenseKey() *LicenseKey     { return businessLicense }
func TrackUse(string)                {}
func Track(string, string, string) error {
	return nil
}

func (*LicenseKey) IsLicensed() bool     { return true }
func (*LicenseKey) TypeToString() string { return "Commercial License - Business" }
