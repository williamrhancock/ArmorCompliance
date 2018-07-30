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
	"time"

	"github.com/dchest/uniuri"
)

var (
	baseurl = "https://api.armor.com"
	account int
	appid   string
	secret  string
)

func armor() *Armor {
	return &Armor{}
}

//PostArmor generic POST function the properly deals with the API key/secret/hmac stuff.
func PostArmor(bodyToSend interface{}, path string, fhauth *string) []byte {
	client := &http.Client{}

	byteToSend, err := json.Marshal(bodyToSend)
	if err != nil {
		log.Println(err)
	}

	armorPSK := armorRequest("POST", path, byteToSend)
	request, error := http.NewRequest("POST", baseurl+path, bytes.NewBuffer(byteToSend))

	if fhauth == nil {
		request.Header.Set("Authorization", armorPSK)
	} else {
		request.Header.Set("Authorization", *fhauth)
	}
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("X-Account-Context", string(account))

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

	armorPSK := armorRequest("GET", path, bodyToSend)

	request, error := http.NewRequest("GET", baseurl+path, bytes.NewBuffer(bodyToSend))

	if fhauth == nil {
		request.Header.Set("Authorization", armorPSK)
	} else {
		request.Header.Set("Authorization", *fhauth)
	}
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("X-Account-Context", string(account))

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

func armorBearer(username, password string) string {
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
