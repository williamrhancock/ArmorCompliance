package armor

/*
https://docs.armor.com/display/KBSS/Log+into+Armor+API
https://developer.armor.com/#/
*/

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dchest/uniuri"
)

var (
	baseurl = "https://api.armor.com"
	account string
	appid   string
	secret  string
)

//NewClient supports the api & bearer calls
func NewClient(accounts, appids, secrets string) *Armor {
	account = accounts
	appid = appids
	secret = secrets
	return &Armor{}
}

//Accounts Return a list of accounts and the products related to the account id
func (a *Armor) Accounts() []byte {
	return GetArmor("/accounts", nil)
}

//AccountContacts Return a list of accounts and the products related to the account id
func (a *Armor) AccountContacts() []byte {
	return GetArmor("/account/contacts", nil)
}

//AccountID Return a list of accounts and the products related to the account id
func (a *Armor) AccountID(id string) []byte {
	return GetArmor("/accounts/"+id, nil)
}

//Invoices Retrieve invoices for an account
func (a *Armor) Invoices() []byte {
	return GetArmor("/invoices", nil)
}

//InvoiceID Retrieve invoices for an account
func (a *Armor) InvoiceID(id string) []byte {
	return GetArmor("/invoices/"+id, nil)
}

//InvoiceIDDetail Retrieve invoices for an account
func (a *Armor) InvoiceIDDetail(id string) []byte {
	return GetArmor("/invoices/"+id+"/detail", nil)
}

//NotificationsAlerts Retrieve notification alerts for an account. Notifications are generated when certain actions are taken on an account, such as updates to a ticket or when a scheduled event happens.
func (a *Armor) NotificationsAlerts() []byte {
	return GetArmor("/notifications/alerts", nil)
}

func (a *Armor) Permissions() []byte {
	return GetArmor("/permissions", nil)
}

func (a *Armor) Products() []byte {
	return GetArmor("/products", nil)
}

func (a *Armor) ProductID(id string) []byte {
	return GetArmor("/products/"+id, nil)
}

func (a *Armor) Roles() []byte {
	return GetArmor("/roles", nil)
}

func (a *Armor) RoleID(id string) []byte {
	return GetArmor("/role/"+id, nil)
}

func (a *Armor) Usage() []byte {
	return GetArmor("/usage", nil)
}

func (a *Armor) Users() []byte {
	return GetArmor("/users", nil)
}

func (a *Armor) Apps() []byte {
	return GetArmor("/apps", nil)
}

func (a *Armor) AppID(id string) []byte {
	return GetArmor("/app/"+id, nil)
}

func (a *Armor) Locations() []byte {
	return GetArmor("/locations", nil)
}

func (a *Armor) Orders() []byte {
	return GetArmor("/orders", nil)
}

func (a *Armor) OrderID(id string) []byte {
	return GetArmor("/order/"+id, nil)
}
func (a *Armor) Vms() []byte {
	return GetArmor("/vms", nil)
}
func (a *Armor) VmDetails(id string) []byte {
	return GetArmor("/vms/"+id, nil)
}
func (a *Armor) VmID(id string) []byte {
	return GetArmor("/stats/vms/"+id, nil)
}
func (a *Armor) StorageSummary() []byte {
	return GetArmor("/storage/summary", nil)
}
func (a *Armor) VmsHybrid() []byte {
	return GetArmor("/vms/hybridVmList", nil)
}

//PostArmor generic POST function the properly deals with the API key/secret/hmac stuff.
func PostArmor(bodyToSend interface{}, path string, fhauth *string) []byte {
	client := &http.Client{}

	byteToSend, err := json.Marshal(bodyToSend)
	if err != nil {
		log.Println(err)
	}

	request, error := http.NewRequest("POST", baseurl+path, bytes.NewBuffer(byteToSend))

	if fhauth == nil {
		armorPSK := armorRequest("POST", path, byteToSend)
		request.Header.Set("Authorization", armorPSK)
	} else {
		request.Header.Set("Authorization", *fhauth)
	}
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("X-Account-Context", account)

	response, error := client.Do(request)
	if error != nil {
		log.Fatal(error)
	}

	defer response.Body.Close()
	byteBody, _ := ioutil.ReadAll(response.Body)

	return byteBody
}

//GetArmor generic Get function the properly deals with the API key/secret/hmac stuff.
func GetArmor(path string, fhauth *string) []byte {
	client := &http.Client{}
	var bodyToSend []byte

	request, error := http.NewRequest("GET", baseurl+path, bytes.NewBuffer(bodyToSend))

	if fhauth == nil {
		armorPSK := armorRequest("GET", path, bodyToSend)
		request.Header.Set("Authorization", armorPSK)
	} else {
		request.Header.Set("Authorization", *fhauth)
	}
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("X-Account-Context", account)

	response, error := client.Do(request)
	if error != nil {
		log.Fatal(error)
	}

	defer response.Body.Close()
	byteBody, _ := ioutil.ReadAll(response.Body)

	return byteBody
}

func armorRequest(method, path string, bodyByte []byte) string {
	nonce := uniuri.NewLen(10)
	var bodyobj string
	reqTime := strconv.FormatInt(time.Now().Unix(), 10)

	if bodyByte != nil {
		obj := sha512.New()
		obj.Write(bodyByte)
		bodyobj = base64.StdEncoding.EncodeToString(obj.Sum(nil))
	}

	toHash := fmt.Sprintf("%v%v%v%v%v%v", appid, method, path, nonce, reqTime, bodyobj)

	hashObj := hmac.New(sha512.New, []byte(secret))
	hashObj.Write([]byte(toHash))
	hmac := base64.StdEncoding.EncodeToString(hashObj.Sum(nil))

	armorPSK := fmt.Sprintf("ARMOR-PSK %v:%v:%v:%v", appid, hmac, nonce, reqTime)

	return armorPSK
}

func ArmorBearer(username, password string) string {
	authReq := struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{username, password}

	authResp := PostArmor(authReq, "/auth/authorize", nil)
	authentication := &Authentication{}
	json.Unmarshal(authResp, authentication)

	tokenReq := struct {
		GrantType string `json:"grant_type"`
		Code      string `json:"code"`
	}{"authorization_code", authentication.Code}

	tokenResp := PostArmor(tokenReq, "/auth/token", nil)
	tokenData := &Token{}
	json.Unmarshal(tokenResp, tokenData)

	return "FH-AUTH " + tokenData.AccessToken
}

//JQP just expells the returned []byte in a jq friendly format with out the []s
func (a *Armor) JQP(b []byte) {
	fmt.Printf("%v\n",
		strings.Trim(string(b), "[]"),
	)
}
