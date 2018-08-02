# armor



```
package main

import (
	"fmt"

	"github.homeawaycorp.com/TDO/armor"
)

func main() {
	armors := armor.NewClient("4780",
		"Generate this on armor's portal",
		"Generate this on armor's portal")
    
    // A bearer token is only needed for sensitive methods in the armor swagger api. 
    //It won't be needed 99% of the time so dont' use it as it causes a 2fa event.
    //Show here for example's sake.
	bearer := armors.ArmorBearer("user@armor.com", "passwerd")
    vms := armors.Vms(&bearer))

	ticketdata := string(armors.TicketID("578832", nil))
	userdatea := string(armors.UsersID("13060", nil))
	fmt.Println(string(armors.Users(nil)))

}
```

This is as far as I've had time to do, POST and GET calls work fine.  When I get a bit of time I'll add DELETE, PUT and potentialy PATCH (can't recall if they use this).

Primary use cases:

```
    func NewClient(accounts, appids, secrets string) *Armor { ... }
```

For custom calling:
```
    func GetArmor(path string, fhauth *string) []byte { ... }
    
    func PostArmor(bodyToSend interface{}, path string, fhauth *string) []byte { ... }

    // returns a propertly formated PSK token
    func (a *Armor) ArmorBearer(username, password string) string { ... }
```

For GSD:
```func (a *Armor) Accounts(psk *string) []byte { ... }
func (a *Armor) AccountContacts(psk *string) []byte { ... }
func (a *Armor) AccountID(id string, psk *string) []byte { ... }
func (a *Armor) Invoices(psk *string) []byte { ... }
func (a *Armor) InvoiceID(id string, psk *string) []byte { ... }
func (a *Armor) InvoiceIDDetail(id string, psk *string) []byte { ... }
func (a *Armor) NotificationsAlerts(psk *string) []byte { ... }
func (a *Armor) Permissions(psk *string) []byte { ... }
func (a *Armor) Products(psk *string) []byte { ... }
func (a *Armor) ProductID(id string, psk *string) []byte { ... }
func (a *Armor) Roles(psk *string) []byte { ... }
func (a *Armor) RoleID(id string, psk *string) []byte { ... }
func (a *Armor) Usage(psk *string) []byte { ... }
func (a *Armor) Users(psk *string) []byte { ... }
func (a *Armor) UsersID(id string, psk *string) []byte { ... }
func (a *Armor) Apps(psk *string) []byte { ... }
func (a *Armor) AppID(id string, psk *string) []byte { ... }
func (a *Armor) Locations(psk *string) []byte { ... }
func (a *Armor) Orders(psk *string) []byte { ... }
func (a *Armor) OrderID(id string, psk *string) []byte { ... }
func (a *Armor) Vms(psk *string) []byte { ... }
func (a *Armor) VmDetails(id string, psk *string) []byte { ... }
func (a *Armor) VmID(id string, psk *string) []byte { ... }
func (a *Armor) StorageSummary(psk *string) []byte { ... }
func (a *Armor) VmsHybrid(psk *string) []byte { ... }
func (a *Armor) Tickets(psk *string) []byte { ... }
func (a *Armor) TicketID(id string, psk *string) []byte { ... }
func (a *Armor) TicketAttachments(id string, psk *string) []byte { ... }
func (a *Armor) ResetInitiate(psk *string) []byte { ... }
func (a *Armor) VulnerabilityScan(psk *string) []byte { ... }
func (a *Armor) VulnerabilityScanReportStats(psk *string) []byte { ... }
func (a *Armor) VulnerabilityScanStatistics(psk *string) []byte { ... }
func (a *Armor) CorePackagesID(psk *string) []byte { ... }
func (a *Armor) CoreSecurityDashboardStatsOverview(psk *string) []byte { ... }
func (a *Armor) UsersNotifications(psk *string) []byte { ... }
func (a *Armor) StatsSecurityTimeSeries(psk *string) []byte { ... }
func (a *Armor) VulerabilityScan(id string, psk *string) []byte { ... }
func (a *Armor) NotificationPreferences(accountID string, psk *string) []byte { ... }
func (a *Armor) IPsPublicIPsQuantity(quantity string, psk *string) []byte { ... }
func (a *Armor) LogManagementLogSources(psk *string) []byte { ... }
func (a *Armor) TicketsEntries(psk *string) []byte { ... }
func (a *Armor) VMs(psk *string) []byte { ... }
func (a *Armor) VMIDDisk(vmID string, psk *string) []byte { ... }
func (a *Armor) Apps(psk *string) []byte { ... }
func (a *Armor) CoreAVAMStatistics(psk *string) []byte { ... }
func (a *Armor) VulnerabilityScanVMReportID(scanReportId string, psk *string) []byte { ... }
func (a *Armor) TicketIDRate(ticketNumber string, psk *string) []byte { ... }
func (a *Armor) UsersStatus(psk *string) []byte { ... }
func (a *Armor) name(psk *string) []byte { ... }
func (a *Armor) IPRMLookup(psk *string) []byte { ... }
func (a *Armor) RecoveryCompleteSMS(psk *string) []byte { ... }
func (a *Armor) TicketsID(ticketNumber string, psk *string) []byte { ... }
func (a *Armor) UsersIDKeys(id string, psk *string) []byte { ... }
func (a *Armor) LogManagementLogDepotDeactivate(psk *string) []byte { ... }
func (a *Armor) FirewallIDRules(ovdcId string, psk *string) []byte { ... }
func (a *Armor) LogManagementUpdateLogRetentionPlan(psk *string) []byte { ... }
func (a *Armor) NotificaitonAlerts(psk *string) []byte { ... }
func (a *Armor) RecoveryIDActionsValidate(recoveryId string, psk *string) []byte { ... }
func (a *Armor) TicketsIDCommentFeedback(ticketNumber string, psk *string) []byte { ... }
func (a *Armor) CloudConnectionsSaveCloudConnections(psk *string) []byte { ... }
func (a *Armor) UserIDInvite(id string, psk *string) []byte { ... }
func (a *Armor) FirewallIDServicesServiceGroupID(ovdcId, serviceGroupId string, psk *string) []byte { ... }
func (a *Armor) Paymentmethods(id string, psk *string) []byte { ... }
func (a *Armor) Nats(psk *string) []byte { ... }
func (a *Armor) SolutionsOrders(psk *string) []byte { ... }
func (a *Armor) VMsCoreIDProfile(coreInstanceId string, psk *string) []byte { ... }
func (a *Armor) IPRMCustomRuleID(id string, psk *string) []byte { ... }
func (a *Armor) LogManagement(psk *string) []byte { ... }
func (a *Armor) TicketsCount(psk *string) []byte { ... }
func (a *Armor) LogManagementProductsID(id string, psk *string) []byte { ... }
func (a *Armor) SecurityAnalyticsActiveRepsonse(psk *string) []byte { ... }
func (a *Armor) RecoverUserContectUsername(username string, psk *string) []byte { ... }
func (a *Armor) LogManagementSourcesInsightNotification(psk *string) []byte { ... }
func (a *Armor) OrdersSubscriptions(psk *string) []byte { ... }
func (a *Armor) IPRMUsers(psk *string) []byte { ... }
func (a *Armor) ProductsIDCategory(id, category string, psk *string) []byte { ... }
func (a *Armor) SecurityIncidents(psk *string) []byte { ... }
func (a *Armor) SybscriptionsActionCancel(psk *string) []byte { ... }
func (a *Armor) VMsIDPowerAction(id, powerAction string, psk *string) []byte { ... }
func (a *Armor) VulnerabilityScanLatest(psk *string) []byte { ... }
func (a *Armor) CoreFIMStatistics(psk *string) []byte { ... }
func (a *Armor) NotificationsAlertsNotified(psk *string) []byte { ... }
func (a *Armor) TicketsIDRecipients(id string, psk *string) []byte { ... }
func (a *Armor) TicketsIDTag(ticketNumber string, psk *string) []byte { ... }
func (a *Armor) LogSearchTemplatedSearch(psk *string) []byte { ... }
func (a *Armor) LogManagementStorageTotals(psk *string) []byte { ... }
func (a *Armor) TicketIDClose(ticketNumber string, psk *string) []byte { ... }
func (a *Armor) AppsIDTiers(appId string, psk *string) []byte { ... }
func (a *Armor) FirewallIDGroups(ovdcId string, psk *string) []byte { ... }
func (a *Armor) L2LID(id string, psk *string) []byte { ... }
func (a *Armor) SSLVPN(psk *string) []byte { ... }
func (a *Armor) VMsID(id string, psk *string) []byte { ... }
```