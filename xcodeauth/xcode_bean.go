package xcode

import "time"

type XcodeToken struct {
	//Email string `json:"email"`
	//gsa 业务逻辑请求中需要用到的头X-Apple-GS-token
	XAppleGSToken string `json:"X-Apple-GS-token"`
	//gsa请求中需要用到的头X-Apple-I-Identity-Id
	Adsid string `json:"Adsid"`
}
type XCodeTeam struct {
	CurrentTeamMember struct {
		DeveloperStatus string `plist:"developerStatus"`
		Email           string `plist:"email"`
		FirstName       string `plist:"firstName"`
		LastName        string `plist:"lastName"`
		PersonId        int    `plist:"personId"`
		Privileges      struct {
		} `plist:"privileges"`
		Roles        []string `plist:"roles"`
		TeamMemberId string   `plist:"teamMemberId"`
	} `plist:"currentTeamMember"`
	DateCreated            time.Time `plist:"dateCreated"`
	ExtendedTeamAttributes struct {
	} `plist:"extendedTeamAttributes"`
	Memberships []struct {
		DateStart              time.Time `plist:"dateStart"`
		DeleteDevicesOnExpiry  bool      `plist:"deleteDevicesOnExpiry"`
		InIosDeviceResetWindow bool      `plist:"inIosDeviceResetWindow"`
		InRenewalWindow        bool      `plist:"inRenewalWindow"`
		MembershipId           string    `plist:"membershipId"`
		MembershipProductId    string    `plist:"membershipProductId"`
		Name                   string    `plist:"name"`
		Platform               string    `plist:"platform"`
		Status                 string    `plist:"status"`
	} `plist:"memberships"`
	Name      string `plist:"name"`
	Status    string `plist:"status"`
	TeamAgent struct {
		DeveloperStatus string `plist:"developerStatus"`
		Email           string `plist:"email"`
		FirstName       string `plist:"firstName"`
		LastName        string `plist:"lastName"`
		PersonId        int    `plist:"personId"`
		TeamMemberId    string `plist:"teamMemberId"`
	} `plist:"teamAgent"`
	TeamId        string `plist:"teamId"`
	Type          string `plist:"type"`
	XcodeFreeOnly bool   `plist:"xcodeFreeOnly"`
}
type DevTeam struct {
	TeamId        string `json:"teamId"`
	Name          string `json:"name"`
	Status        string `json:"status"`
	Type          string `plist:"type"`
	XcodeFreeOnly bool   `plist:"xcodeFreeOnly"`
	ProviderId    string `plist:"type"`
}
