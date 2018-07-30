package main

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

func main() {
	//coreAVAM()
	//roleToUserTest()
	//getPermissionTest()

	//fmt.Println(string(GetArmor("/tickets/573730", nil)))

	/*
		for the routes that are not allowed using the apikey, use armorBearer and it will 2fa you.
		code := armorBearer("whancock@homeaway.com", "wlB291,laurel!")
		fmt.Println(string(GetArmor("/me", &code)))

	*/
	/*
		{ // This looks like a by design limitation of the api role in armor.  Keep getting: {"Message":"Permission Denied to requested resource."}
			bodyToSend := CreateUser{First: "Home", Last: "Away", Email: "williamrhancock@gmail.com", Roles: []CreateUserRoles{{ID: "1"}}}
			byteBody := PostArmor(bodyToSend, "/users")
			fmt.Println(string(byteBody))
		}
	*/

	fmt.Println(string(GetArmor("/me", nil)))
}

func coreAVAM() {
	byteBody := GetArmor("/core/avam", nil)
	c := &[]CoreAVAM{}
	json.Unmarshal(byteBody, c)

	for _, v := range *c {
		fmt.Printf("%v: %v AntiMalwareStatus: %v\n", v.VmName, v.Os, v.OverallAntiMalwareStatus)
	}

}

func roleToUserTest() {
	userToRole := make(map[string][]string)

	byteBody := GetArmor(armoruri["r"], nil)
	roles := &[]RoleResponse{}
	json.Unmarshal(byteBody, roles)
	for _, v := range *roles {
		for _, vv := range v.Members {
			userToRole[v.Name] = append(userToRole[v.Name], vv.Email)
		}
	}
	for k, v := range userToRole {
		fmt.Printf("%v,%v\n", k, strings.Join(v, ","))
	}

}

func getPermissionTest() {
	permissionsMap := make(map[float64]string)

	byteBody := GetArmor(armoruri["p"], nil)
	permissions := &[]PermissionsResponse{}
	json.Unmarshal(byteBody, permissions)

	for _, v := range *permissions {
		for _, vv := range v.Permissions {
			if vv.Description != "" {
				permissionsMap[vv.ID] = vv.Name + "-" + vv.Description
			}
		}
	}

	byteBody = GetArmor(armoruri["u"], nil)
	users := &[]UsersResponse{}
	json.Unmarshal(byteBody, users)

	for _, v := range *users {
		fmt.Printf("%v,", v.Email)
		for _, p := range v.Permissions {
			if str, ok := permissionsMap[p]; ok == true {
				fmt.Printf(`"%v",`, str)
			}
		}
		fmt.Println()
	}

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
	request.Header.Add("X-Account-Context", account["Homeaway"])

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
	request.Header.Add("X-Account-Context", account["Homeaway"])

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
