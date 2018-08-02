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
	// For api usages
	appid  string
	secret string
	// For bearer generation
	user     string
	password string
)

//NewClient supports the api & bearer calls
func NewClient(accounts, appids, secrets string) *Armor {
	account = accounts
	appid = appids
	secret = secrets
	return &Armor{}
}

//Accounts Return a list of accounts and the products related to the account id
func (a *Armor) Accounts(psk *string) []byte {
	return GetArmor("/accounts", nil)
}

//AccountContacts Return a list of accounts and the products related to the account id
func (a *Armor) AccountContacts(psk *string) []byte {
	return GetArmor("/account/contacts", nil)
}

//AccountID Return a list of accounts and the products related to the account id
func (a *Armor) AccountID(id string, psk *string) []byte {
	return GetArmor("/accounts/"+id, nil)
}

//Invoices Retrieve invoices for an account
func (a *Armor) Invoices(psk *string) []byte {
	return GetArmor("/invoices", nil)
}

//InvoiceID Retrieve invoices for an account
func (a *Armor) InvoiceID(id string, psk *string) []byte {
	return GetArmor("/invoices/"+id, nil)
}

//InvoiceIDDetail Retrieve invoices for an account
func (a *Armor) InvoiceIDDetail(id string, psk *string) []byte {
	return GetArmor("/invoices/"+id+"/detail", nil)
}

//NotificationsAlerts Retrieve notification alerts for an account. Notifications are generated when certain actions are taken on an account, such as updates to a ticket or when a scheduled event happens.
func (a *Armor) NotificationsAlerts(psk *string) []byte {
	return GetArmor("/notifications/alerts", nil)
}

func (a *Armor) Permissions(psk *string) []byte {
	return GetArmor("/permissions", nil)
}

func (a *Armor) Products(psk *string) []byte {
	return GetArmor("/products", nil)
}

func (a *Armor) ProductID(id string, psk *string) []byte {
	return GetArmor("/products/"+id, nil)
}

func (a *Armor) Roles(psk *string) []byte {
	return GetArmor("/roles", nil)
}

func (a *Armor) RoleID(id string, psk *string) []byte {
	return GetArmor("/role/"+id, nil)
}

func (a *Armor) Usage(psk *string) []byte {
	return GetArmor("/usage", nil)
}

func (a *Armor) Users(psk *string) []byte {
	return GetArmor("/users", nil)
}

func (a *Armor) UsersID(id string, psk *string) []byte {
	return GetArmor("/users/"+id, psk)
}

func (a *Armor) Apps(psk *string) []byte {
	return GetArmor("/apps", nil)
}

func (a *Armor) AppID(id string, psk *string) []byte {
	return GetArmor("/app/"+id, nil)
}

func (a *Armor) Locations(psk *string) []byte {
	return GetArmor("/locations", nil)
}

func (a *Armor) Orders(psk *string) []byte {
	return GetArmor("/orders", nil)
}

func (a *Armor) OrderID(id string, psk *string) []byte {
	return GetArmor("/order/"+id, nil)
}
func (a *Armor) Vms(psk *string) []byte {
	return GetArmor("/vms", psk)
}
func (a *Armor) VmDetails(id string, psk *string) []byte {
	return GetArmor("/vms/"+id, nil)
}
func (a *Armor) VmID(id string, psk *string) []byte {
	return GetArmor("/stats/vms/"+id, nil)
}
func (a *Armor) StorageSummary(psk *string) []byte {
	return GetArmor("/storage/summary", nil)
}
func (a *Armor) VmsHybrid(psk *string) []byte {
	return GetArmor("/vms/hybridVmList", nil)
}

func (a *Armor) Tickets(psk *string) []byte {
	return GetArmor("/tickets", nil)
}

func (a *Armor) TicketID(id string, psk *string) []byte {
	return GetArmor("/tickets/"+id, nil)
}

func (a *Armor) TicketAttachments(id string, psk *string) []byte {
	return GetArmor("/tickets/"+id+"/attachments", nil)
}

func (a *Armor) ResetInitiate(psk *string) []byte {
	return GetArmor("/reset/initiate", nil)
}

func (a *Armor) VulnerabilityScan(psk *string) []byte {
	return GetArmor("/vulnerability-scan", nil)
}

func (a *Armor) VulnerabilityScanReportStats(psk *string) []byte {
	return GetArmor("/vulnerability-scan/reportstats/{scanReportId}", nil)
}

func (a *Armor) VulnerabilityScanStatistics(psk *string) []byte {
	return GetArmor("/vulnerability-scan/statistics", nil)
}

func (a *Armor) CorePackagesID(psk *string) []byte {
	return GetArmor("/core/packages/{coreInstanceId}", nil)
}

func (a *Armor) CoreSecurityDashboardStatsOverview(psk *string) []byte {
	return GetArmor("/core/security-dashboard/stats/overview", nil)
}

func (a *Armor) UsersNotifications(psk *string) []byte {
	return GetArmor("/users/notifications", nil)
}

func (a *Armor) StatsSecurityTimeSeries(psk *string) []byte {
	return GetArmor("/stats/security/time-series", nil)
}

func (a *Armor) VulerabilityScan(id string, psk *string) []byte {
	return GetArmor("/vulnerability-scan/"+id, nil)
}

func (a *Armor) NotificationPreferences(accountID string, psk *string) []byte {
	return GetArmor("/notifications/preferences/"+accountID, nil)
}

func (a *Armor) IPsPublicIPsQuantity(quantity string, psk *string) []byte {
	return GetArmor("/ips/publicIps/quantity/"+quantity, nil)
}

func (a *Armor) LogManagementLogSources(psk *string) []byte {
	return GetArmor("/log-management/logsources", nil)
}

func (a *Armor) TicketsEntries(psk *string) []byte {
	return GetArmor("/tickets/entries", nil)
}

func (a *Armor) VMs(psk *string) []byte {
	return GetArmor("/vms", nil)
}

func (a *Armor) VMIDDisk(vmID string, psk *string) []byte {
	return GetArmor("/vms/"+vmID+"/disk", nil)
}

/*
func (a *Armor) Apps(psk *string) []byte {
	return GetArmor("/apps", nil)
}
*/

func (a *Armor) CoreAVAMStatistics(psk *string) []byte {
	return GetArmor("/core/avam/statistics", nil)
}

func (a *Armor) VulnerabilityScanVMReportID(scanReportId string, psk *string) []byte {
	return GetArmor("/vulnerability-scan/vm/"+scanReportId, nil)
}

func (a *Armor) TicketIDRate(ticketNumber string, psk *string) []byte {
	return GetArmor("/tickets/"+ticketNumber+"/rate", nil)
}

func (a *Armor) UsersStatus(psk *string) []byte {
	return GetArmor("/users/status", nil)
}

func (a *Armor) name(psk *string) []byte {
	return GetArmor("/usersecurity/validatemfaphone", nil)
}

func (a *Armor) IPRMLookup(psk *string) []byte {
	return GetArmor("/iprm/lookup", nil)
}

func (a *Armor) RecoveryCompleteSMS(psk *string) []byte {
	return GetArmor("/recovery/completesms", nil)
}

func (a *Armor) TicketsID(ticketNumber string, psk *string) []byte {
	return GetArmor("/tickets/"+ticketNumber, nil)
}

func (a *Armor) UsersIDKeys(id string, psk *string) []byte {
	return GetArmor("/users/"+id+"/keys", nil)
}

func (a *Armor) LogManagementLogDepotDeactivate(psk *string) []byte {
	return GetArmor("/log-management/log-depot/deactivate", nil)
}

func (a *Armor) FirewallIDRules(ovdcId string, psk *string) []byte {
	return GetArmor("/firewall/"+ovdcId+"/rules", nil)
}

func (a *Armor) LogManagementUpdateLogRetentionPlan(psk *string) []byte {
	return GetArmor("/log-management/update-logretentionplan", nil)
}

func (a *Armor) NotificaitonAlerts(psk *string) []byte {
	return GetArmor("/notifications/alerts", nil)
}

func (a *Armor) RecoveryIDActionsValidate(recoveryId string, psk *string) []byte {
	return GetArmor("/recovery/"+recoveryId+"/actions/validate", nil)
}

func (a *Armor) TicketsIDCommentFeedback(ticketNumber string, psk *string) []byte {
	return GetArmor("/tickets/"+ticketNumber+"/comment/feedback", nil)
}

func (a *Armor) CloudConnectionsSaveCloudConnections(psk *string) []byte {
	return GetArmor("/cloud-connections/savecloudconnection", nil)
}

func (a *Armor) UserIDInvite(id string, psk *string) []byte {
	return GetArmor("/users/"+id+"/invite", nil)
}

func (a *Armor) FirewallIDServicesServiceGroupID(ovdcId, serviceGroupId string, psk *string) []byte {
	return GetArmor("/firewall/"+ovdcId+"/services/"+serviceGroupId, nil)
}

func (a *Armor) Paymentmethods(id string, psk *string) []byte {
	return GetArmor("/paymentmethods/"+id, nil)
}

func (a *Armor) Nats(psk *string) []byte {
	return GetArmor("/nats", nil)
}

func (a *Armor) SolutionsOrders(psk *string) []byte {
	return GetArmor("/solutionsOrders", nil)
}

func (a *Armor) VMsCoreIDProfile(coreInstanceId string, psk *string) []byte {
	return GetArmor("/vms/core/"+coreInstanceId+"/profile", nil)
}

func (a *Armor) IPRMCustomRuleID(id string, psk *string) []byte {
	return GetArmor("/iprm/custom-rule/"+id, nil)
}

func (a *Armor) LogManagement(psk *string) []byte {
	return GetArmor("/log-management", nil)
}

func (a *Armor) TicketsCount(psk *string) []byte {
	return GetArmor("/tickets/count", nil)
}

func (a *Armor) LogManagementProductsID(id string, psk *string) []byte {
	return GetArmor("/log-management/products/"+id, nil)
}

func (a *Armor) SecurityAnalyticsActiveRepsonse(psk *string) []byte {
	return GetArmor("/security-analytics/active-response", nil)
}

func (a *Armor) RecoverUserContectUsername(username string, psk *string) []byte {
	return GetArmor("/recovery/usercontext/"+username, nil)
}

func (a *Armor) LogManagementSourcesInsightNotification(psk *string) []byte {
	return GetArmor("/log-management/logsources/log-insight/notification", nil)
}

func (a *Armor) OrdersSubscriptions(psk *string) []byte {
	return GetArmor("/orders/subscriptions", nil)
}

func (a *Armor) IPRMUsers(psk *string) []byte {
	return GetArmor("/iprm/users", nil)
}

func (a *Armor) ProductsIDCategory(id, category string, psk *string) []byte {
	return GetArmor("/products/"+id+"/"+category, nil)
}

func (a *Armor) SecurityIncidents(psk *string) []byte {
	return GetArmor("/security-incidents", nil)
}

func (a *Armor) SybscriptionsActionCancel(psk *string) []byte {
	return GetArmor("/subscriptions/actions/cancel", nil)
}

func (a *Armor) VMsIDPowerAction(id, powerAction string, psk *string) []byte {
	return GetArmor("/vms/"+id+"/power/"+powerAction, nil)
}

func (a *Armor) VulnerabilityScanLatest(psk *string) []byte {
	return GetArmor("/vulnerability-scan/latest", nil)
}

func (a *Armor) CoreFIMStatistics(psk *string) []byte {
	return GetArmor("/core/fim/statistics", nil)
}

func (a *Armor) NotificationsAlertsNotified(psk *string) []byte {
	return GetArmor("/notifications/alerts/notified", nil)
}

func (a *Armor) TicketsIDRecipients(id string, psk *string) []byte {
	return GetArmor("/tickets/"+id+"/recipients", nil)
}

func (a *Armor) TicketsIDTag(ticketNumber string, psk *string) []byte {
	return GetArmor("/tickets/"+ticketNumber+"/tag", nil)
}

func (a *Armor) LogSearchTemplatedSearch(psk *string) []byte {
	return GetArmor("/log-search/templatedsearch", nil)
}

func (a *Armor) LogManagementStorageTotals(psk *string) []byte {
	return GetArmor("/log-management/log-storage-totals", nil)
}

func (a *Armor) TicketIDClose(ticketNumber string, psk *string) []byte {
	return GetArmor("/tickets/"+ticketNumber+"/close", nil)
}

func (a *Armor) AppsIDTiers(appId string, psk *string) []byte {
	return GetArmor("/apps/"+appId+"/tiers", nil)
}

func (a *Armor) FirewallIDGroups(ovdcId string, psk *string) []byte {
	return GetArmor("/firewall/"+ovdcId+"/groups", nil)
}

func (a *Armor) L2LID(id string, psk *string) []byte {
	return GetArmor("/l2l/"+id, nil)
}

func (a *Armor) SSLVPN(psk *string) []byte {
	return GetArmor("/sslvpn", nil)
}

func (a *Armor) VMsID(id string, psk *string) []byte {
	return GetArmor("/vms/"+id, nil)
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

func (a *Armor) ArmorBearer(username, password string) string {
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
