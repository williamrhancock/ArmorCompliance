package main

/*
https://docs.armor.com/display/KBSS/Log+into+Armor+API
https://developer.armor.com/#/
*/

import (
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

//Auth creds are kept as vars in ./auth.go

func main() {
	//coreAVAM()
	//roleToUserTest()
	getPermissionTest()

	/* { // Create user test - make this a function with easy entry cost.
		bodyToSend := CreateUser{First: "Home", Last: "Away", Email: "williamrhancock@gmail.com", Roles: []CreateUserRoles{{ID: "5914"}}}
		byteBody := PostArmor(bodyToSend)
		fmt.Println(string(byteBody))
	} */

	//fmt.Println(string(GetArmor("/tickets/573730")))

}

func coreAVAM() {
	byteBody := GetArmor("/core/avam")
	c := &[]CoreAVAM{}
	json.Unmarshal(byteBody, c)
	for _, v := range *c {
		fmt.Printf("%v: %v AntiMalwareStatus: %v\n", v.VmName, v.Os, v.OverallAntiMalwareStatus)

	}
}

func roleToUserTest() {
	userToRole := make(map[string][]string)

	byteBody := GetArmor(armoruri["r"])
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

	byteBody := GetArmor(armoruri["p"])
	permissions := &[]PermissionsResponse{}
	json.Unmarshal(byteBody, permissions)

	for _, v := range *permissions {
		for _, vv := range v.Permissions {
			if vv.Description != "" {
				permissionsMap[vv.ID] = vv.Name + "-" + vv.Description
			}
		}
	}

	byteBody = GetArmor(armoruri["u"])
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
func PostArmor(bodyToSend interface{}) []byte {
	client := &http.Client{}
	path := "/users"

	byteToSend, err := json.Marshal(bodyToSend)
	if err != nil {
		log.Println(err)
	}

	bodyReader := strings.NewReader(string(byteToSend))

	armorPSK := armorRequest("POST", path, &byteToSend)
	request, error := http.NewRequest("POST", baseurl+path, bodyReader)

	request.Header.Set("Authorization", armorPSK)
	request.Header.Add("X-Account-Context", account["Homeaway"])

	response, error := client.Do(request)
	if error != nil {
		log.Fatal(error)
	}

	defer response.Body.Close()
	byteBody, _ := ioutil.ReadAll(response.Body)

	fmt.Println(request)
	fmt.Println(response)

	return byteBody
}

//GetArmor generic Get function the properly deals with the API key/secret/hmac stuff.
func GetArmor(path string) []byte {
	client := &http.Client{}
	var bodyToSend []byte

	armorPSK := armorRequest("GET", path, &bodyToSend)

	request, error := http.NewRequest("GET", baseurl+path, nil)

	request.Header.Set("Authorization", armorPSK)
	request.Header.Add("X-Account-Context", account["Homeaway"])

	response, error := client.Do(request)
	if error != nil {
		log.Fatal(error)
	}

	defer response.Body.Close()
	byteBody, _ := ioutil.ReadAll(response.Body)

	fmt.Println(request)
	fmt.Println(response)

	return byteBody
}

func armorRequest(method, path string, bodyByte *[]byte) string {
	var bodyobj *string
	nonce := uniuri.NewLen(10)
	reqTime := strconv.FormatInt(time.Now().Unix(), 10)

	if bodyByte != nil {
		obj := sha512.New()
		obj.Write(*bodyByte)
		bodyobjpre := base64.StdEncoding.EncodeToString(obj.Sum(nil))
		bodyobj = &bodyobjpre
	} else {
		bodyobjpre := ""
		bodyobj = &bodyobjpre
	}

	toHash := fmt.Sprintf("%v%v%v%v%v%v", appid, method, path, nonce, reqTime, *bodyobj) //string(*bodyByte))

	hashObj := hmac.New(sha512.New, []byte(secret))
	hashObj.Write([]byte(toHash))
	hmac := base64.StdEncoding.EncodeToString(hashObj.Sum(nil))

	armorPSK := fmt.Sprintf("ARMOR-PSK %v:%v:%v:%v", appid, hmac, nonce, reqTime)

	return armorPSK
}
