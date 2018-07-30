package main

type Armor struct {
	Users       *[]UsersResponse
	Permissions *[]PermissionsResponse
	Roles       *[]RoleResponse
}

type UsersResponse struct {
	ApiKeyCount        float64   `json:"apiKeyCount,omitempty"`
	Culture            string    `json:"culture,omitempty"`
	Email              string    `json:"email,omitempty"`
	FirstName          string    `json:"firstName,omitempty"`
	ID                 float64   `json:"id,omitempty"`
	IsMfaEnabled       bool      `json:"isMfaEnabled,omitempty"`
	LastLogin          string    `json:"lastLogin,omitempty"`
	LastModified       string    `json:"lastModified,omitempty"`
	LastName           string    `json:"lastName,omitempty"`
	MfaMode            string    `json:"mfaMode,omitempty"`
	MfaPinMode         string    `json:"mfaPinMode,omitempty"`
	MustChangePassword bool      `json:"mustChangePassword,omitempty"`
	PasswordLastSet    string    `json:"passwordLastSet,omitempty"`
	Permissions        []float64 `json:"permissions,omitempty"`
	PhonePrimary       struct {
		CountryCode    float64     `json:"countryCode,omitempty"`
		CountryIsoCode interface{} `json:"countryIsoCode,omitempty"`
		Number         string      `json:"number,omitempty"`
		PhoneExt       interface{} `json:"phoneExt,omitempty"`
	} `json:"phonePrimary,omitempty"`
	Status   string `json:"status,omitempty"`
	Timezone string `json:"timezone,omitempty"`
	Title    string `json:"title,omitempty"`
}

type RoleResponse struct {
	Created string  `json:"created,omitempty"`
	Default bool    `json:"default,omitempty"`
	ID      float64 `json:"id,omitempty"`
	Members []struct {
		Added     string  `json:"added,omitempty"`
		Email     string  `json:"email,omitempty"`
		Enabled   bool    `json:"enabled,omitempty"`
		FirstName string  `json:"firstName,omitempty"`
		ID        float64 `json:"id,omitempty"`
		LastName  string  `json:"lastName,omitempty"`
	} `json:"members,omitempty"`
	Modified    interface{} `json:"modified,omitempty"`
	Name        string      `json:"name,omitempty"`
	Permissions []float64   `json:"permissions,omitempty"`
}

type PermissionsResponse struct {
	Name        string `json:"name,omitempty"`
	Permissions []struct {
		Description string `json:"description,omitempty"`
		Endpoints   []struct {
			Method string `json:"method,omitempty"`
			Route  string `json:"route,omitempty"`
		} `json:"endpoints,omitempty"`
		ID       float64 `json:"id,omitempty"`
		Name     string  `json:"name,omitempty"`
		Resource string  `json:"resource,omitempty"`
		System   string  `json:"system,omitempty"`
	} `json:"permissions,omitempty"`
}

type CoreAVAM struct {
	AccountId                      float64     `json:"accountId,omitempty"`
	AlternativeBiosUuid            string      `json:"alternativeBiosUuid,omitempty"`
	AvamRealTimeScan               bool        `json:"avamRealTimeScan,omitempty"`
	BiosUuid                       string      `json:"biosUuid,omitempty"`
	CoreInstanceId                 string      `json:"coreInstanceId,omitempty"`
	CreatedDate                    interface{} `json:"createdDate,omitempty"`
	CustomLocatiom                 interface{} `json:"customLocatiom,omitempty"`
	CustomProvider                 interface{} `json:"customProvider,omitempty"`
	HostId                         float64     `json:"hostId,omitempty"`
	IsActive                       bool        `json:"isActive,omitempty"`
	LastAgentCommunicationData     interface{} `json:"lastAgentCommunicationData,omitempty"`
	LastAgentCommunicationDate     string      `json:"lastAgentCommunicationDate,omitempty"`
	LastAgentCommunicationSeverity float64     `json:"lastAgentCommunicationSeverity,omitempty"`
	LastScannedData                interface{} `json:"lastScannedData,omitempty"`
	LastScannedDate                string      `json:"lastScannedDate,omitempty"`
	LastScannedSeverity            float64     `json:"lastScannedSeverity,omitempty"`
	Location                       interface{} `json:"location,omitempty"`
	Os                             string      `json:"os,omitempty"`
	OverallAntiMalwareStatus       string      `json:"overallAntiMalwareStatus,omitempty"`
	ProviderFullName               interface{} `json:"providerFullName,omitempty"`
	VmName                         string      `json:"vmName,omitempty"`
	VmProvider                     string      `json:"vmProvider,omitempty"`
}

type CreateUser struct {
	First string `json:firstName`
	Last  string `json:lastName`
	Email string `json:email`
	Roles []CreateUserRoles
}
type CreateUserRoles struct {
	ID string `json:id`
}

type Authentication struct {
	Code        string `json:"code,omitempty"`
	RedirectURI string `json:"redirect_uri,omitempty"`
	Success     bool   `json:"success,omitempty"`
}
type Token struct {
	AccessToken string `json:"access_token,omitempty"`
	ExpiresIn   int    `json:"expires_in,omitempty"`
	IDToken     string `json:"id_token,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
}
