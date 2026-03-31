package unifi

import (
	"context"
	"fmt"
	"strings"
)

// Guest struct holds return API device values
type Guest struct {
	Data []struct {
		SiteID          string `json:"site_id"`
		AssocTime       int    `json:"assoc_time"`
		LatestAssocTime int    `json:"latest_assoc_time"`
		Oui             string `json:"oui"`
		UserID          string `json:"user_id"`
		ID              string `json:"_id"`
		Mac             string `json:"mac"`
		IsGuest         bool   `json:"is_guest"`
		FirstSeen       int    `json:"first_seen"`
		LastSeen        int    `json:"last_seen"`
		IsWired         bool   `json:"is_wired"`
		Hostname        string `json:"hostname"`
		UptimeByUap     int    `json:"_uptime_by_uap"`
		LastSeenByUap   int    `json:"_last_seen_by_uap"`
		IsGuestByUap    bool   `json:"_is_guest_by_uap"`
		ApMac           string `json:"ap_mac"`
		Channel         int    `json:"channel"`
		Radio           string `json:"radio"`
		RadioName       string `json:"radio_name"`
		Essid           string `json:"essid"`
		Bssid           string `json:"bssid"`
		PowersaveEnabled bool  `json:"powersave_enabled"`
		Is11R           bool   `json:"is_11r"`
		Ccq             int    `json:"ccq"`
		Rssi            int    `json:"rssi"`
		Noise           int    `json:"noise"`
		Signal          int    `json:"signal"`
		TxRate          int    `json:"tx_rate"`
		RxRate          int    `json:"rx_rate"`
		TxPower         int    `json:"tx_power"`
		Idletime        int    `json:"idletime"`
		IP              string `json:"ip"`
		DhcpendTime     int    `json:"dhcpend_time"`
		Satisfaction    int    `json:"satisfaction"`
		Anomalies       int    `json:"anomalies"`
		Vlan            int    `json:"vlan"`
		RadioProto      string `json:"radio_proto"`
		Uptime          int    `json:"uptime"`
		TxBytes         int    `json:"tx_bytes"`
		RxBytes         int    `json:"rx_bytes"`
		TxPackets       int    `json:"tx_packets"`
		TxRetries       int    `json:"tx_retries"`
		WifiTxAttempts  int    `json:"wifi_tx_attempts"`
		RxPackets       int    `json:"rx_packets"`
		BytesR          int    `json:"bytes-r"`
		TxBytesR        int    `json:"tx_bytes-r"`
		RxBytesR        int    `json:"rx_bytes-r"`
		QosPolicyApplied bool  `json:"qos_policy_applied"`
		UptimeByUgw     int    `json:"_uptime_by_ugw"`
		LastSeenByUgw   int    `json:"_last_seen_by_ugw"`
		IsGuestByUgw    bool   `json:"_is_guest_by_ugw"`
		GwMac           string `json:"gw_mac"`
		Network         string `json:"network"`
		NetworkID       string `json:"network_id"`
		RoamCount       int    `json:"roam_count"`
		UptimeByUsw     int    `json:"_uptime_by_usw,omitempty"`
		LastSeenByUsw   int    `json:"_last_seen_by_usw,omitempty"`
		IsGuestByUsw    bool   `json:"_is_guest_by_usw,omitempty"`
		SwMac           string `json:"sw_mac,omitempty"`
		SwDepth         int    `json:"sw_depth,omitempty"`
		SwPort          int    `json:"sw_port,omitempty"`
		DevCat          int    `json:"dev_cat,omitempty"`
		DevFamily       int    `json:"dev_family,omitempty"`
		DevID           int    `json:"dev_id,omitempty"`
		OsClass         int    `json:"os_class,omitempty"`
		OsName          int    `json:"os_name,omitempty"`
		DevVendor       int    `json:"dev_vendor,omitempty"`
	} `json:"data"`
}

// ListGuests returns an array of device objects - provide a MAC for a specific device
func (c *Client) ListGuests(ctx context.Context, site, mac string) (*[]Guest, error) {
	var respBody struct {
		Meta meta    `json:"meta"`
		Data []Guest `json:"data"`
	}

	if err := c.do(ctx, "GET", fmt.Sprintf("s/%s/stat/sta/%s", site, strings.ToLower(strings.Trim(mac, " "))), nil, &respBody); err != nil {
		return &[]Guest{}, err
	}

	return &respBody.Data, nil
}
