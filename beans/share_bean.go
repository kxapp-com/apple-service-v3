package beans

import "time"

type BundleIDBean struct {
	Type          string               `json:"type"`
	Id            string               `json:"id"`
	Attributes    ListBundleAttributes `json:"attributes"`
	Relationships struct {
		BundleIdCapabilities struct {
			Meta struct {
				Paging struct {
					Total int `json:"total"`
					Limit int `json:"limit"`
				} `json:"paging"`
			} `json:"meta"`
			Links struct {
				Self    string `json:"self"`
				Related string `json:"related"`
			} `json:"links"`
		} `json:"bundleIdCapabilities"`
		Profiles struct {
			Meta struct {
				Paging struct {
					Total int `json:"total"`
					Limit int `json:"limit"`
				} `json:"paging"`
			} `json:"meta"`
			Links struct {
				Self    string `json:"self"`
				Related string `json:"related"`
			} `json:"links"`
		} `json:"profiles"`
	} `json:"relationships"`
	Links struct {
		Self string `json:"self"`
	} `json:"links"`
}
type ListBundleAttributes struct {
	Identifier                        string      `json:"identifier"`
	DateModified                      time.Time   `json:"dateModified"`
	EntitlementGroupName              interface{} `json:"entitlementGroupName"`
	BundleType                        string      `json:"bundleType"`
	Platform                          string      `json:"platform"`
	Wildcard                          bool        `json:"wildcard"`
	DateCreated                       time.Time   `json:"dateCreated"`
	BundleIdCapabilitiesSettingOption interface{} `json:"bundleIdCapabilitiesSettingOption"`
	SeedId                            string      `json:"seedId"`
	Name                              string      `json:"name"`
	PlatformName                      string      `json:"platformName"`
	DeploymentDataNotice              interface{} `json:"deploymentDataNotice"`
	ResponseId                        string      `json:"responseId"`
}
