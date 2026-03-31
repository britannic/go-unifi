package unifi

import (
	"context"
	"fmt"
)

type Site struct {
	ID string `json:"_id,omitempty"`

	// Hidden   bool   `json:"attr_hidden,omitempty"`
	// HiddenID string `json:"attr_hidden_id,omitempty"`
	// NoDelete bool   `json:"attr_no_delete,omitempty"`
	// NoEdit   bool   `json:"attr_no_edit,omitempty"`

	Name        string `json:"name"`
	Description string `json:"desc"`

	// Role string `json:"role"`
}

// SiteHealth struct holds return API device values
type SiteHealth struct {
	Subsystem               string   `json:"subsystem"`
	NumUser                 int      `json:"num_user,omitempty"`
	NumGuest                int      `json:"num_guest,omitempty"`
	NumIot                  int      `json:"num_iot,omitempty"`
	TxBytesR                int      `json:"tx_bytes-r,omitempty"`
	RxBytesR                int      `json:"rx_bytes-r,omitempty"`
	Status                  string   `json:"status"`
	NumAp                   int      `json:"num_ap,omitempty"`
	NumAdopted              int      `json:"num_adopted,omitempty"`
	NumDisabled             int      `json:"num_disabled,omitempty"`
	NumDisconnected         int      `json:"num_disconnected,omitempty"`
	NumPending              int      `json:"num_pending,omitempty"`
	NumGw                   int      `json:"num_gw,omitempty"`
	WanIP                   string   `json:"wan_ip,omitempty"`
	Gateways                []string `json:"gateways,omitempty"`
	Netmask                 string   `json:"netmask,omitempty"`
	Nameservers             []string `json:"nameservers,omitempty"`
	NumSta                  int      `json:"num_sta,omitempty"`
	GwMac                   string   `json:"gw_mac,omitempty"`
	GwName                  string   `json:"gw_name,omitempty"`
	GwSystemStats           struct {
		CPU    string `json:"cpu"`
		Mem    string `json:"mem"`
		Uptime string `json:"uptime"`
	} `json:"gw_system-stats,omitempty"`
	GwVersion               string  `json:"gw_version,omitempty"`
	Latency                 int     `json:"latency,omitempty"`
	Uptime                  int     `json:"uptime,omitempty"`
	Drops                   int     `json:"drops,omitempty"`
	XputUp                  float64 `json:"xput_up,omitempty"`
	XputDown                float64 `json:"xput_down,omitempty"`
	SpeedtestStatus         string  `json:"speedtest_status,omitempty"`
	SpeedtestLastrun        int     `json:"speedtest_lastrun,omitempty"`
	SpeedtestPing           int     `json:"speedtest_ping,omitempty"`
	LanIP                   string  `json:"lan_ip,omitempty"`
	NumSw                   int     `json:"num_sw,omitempty"`
	RemoteUserEnabled       bool    `json:"remote_user_enabled,omitempty"`
	RemoteUserNumActive     int     `json:"remote_user_num_active,omitempty"`
	RemoteUserNumInactive   int     `json:"remote_user_num_inactive,omitempty"`
	RemoteUserRxBytes       int     `json:"remote_user_rx_bytes,omitempty"`
	RemoteUserTxBytes       int     `json:"remote_user_tx_bytes,omitempty"`
	RemoteUserRxPackets     int     `json:"remote_user_rx_packets,omitempty"`
	RemoteUserTxPackets     int     `json:"remote_user_tx_packets,omitempty"`
	SiteToSiteEnabled       bool    `json:"site_to_site_enabled,omitempty"`
	SiteToSiteNumActive     int     `json:"site_to_site_num_active,omitempty"`
	SiteToSiteNumInactive   int     `json:"site_to_site_num_inactive,omitempty"`
	SiteToSiteRxBytes       int     `json:"site_to_site_rx_bytes,omitempty"`
	SiteToSiteTxBytes       int     `json:"site_to_site_tx_bytes,omitempty"`
	SiteToSiteRxPackets     int     `json:"site_to_site_rx_packets,omitempty"`
	SiteToSiteTxPackets     int     `json:"site_to_site_tx_packets,omitempty"`
}

func (c *Client) ListSites(ctx context.Context) ([]Site, error) {
	var respBody struct {
		Meta meta   `json:"meta"`
		Data []Site `json:"data"`
	}

	err := c.do(ctx, "GET", "self/sites", nil, &respBody)
	if err != nil {
		return nil, err
	}

	return respBody.Data, nil
}

func (c *Client) GetSite(ctx context.Context, id string) (*Site, error) {
	sites, err := c.ListSites(ctx)
	if err != nil {
		return nil, err
	}

	for _, s := range sites {
		if s.ID == id {
			return &s, nil
		}
	}

	return nil, &NotFoundError{}
}

func (c *Client) CreateSite(ctx context.Context, description string) ([]Site, error) {
	reqBody := struct {
		Cmd  string `json:"cmd"`
		Desc string `json:"desc"`
	}{
		Cmd:  "add-site",
		Desc: description,
	}

	var respBody struct {
		Meta meta   `json:"meta"`
		Data []Site `json:"data"`
	}

	err := c.do(ctx, "POST", "s/default/cmd/sitemgr", reqBody, &respBody)
	if err != nil {
		return nil, err
	}

	return respBody.Data, nil
}

func (c *Client) DeleteSite(ctx context.Context, id string) ([]Site, error) {
	reqBody := struct {
		Cmd  string `json:"cmd"`
		Site string `json:"site"`
	}{
		Cmd:  "delete-site",
		Site: id,
	}

	var respBody struct {
		Meta meta   `json:"meta"`
		Data []Site `json:"data"`
	}

	err := c.do(ctx, "POST", "s/default/cmd/sitemgr", reqBody, &respBody)
	if err != nil {
		return nil, err
	}

	return respBody.Data, nil
}

func (c *Client) UpdateSite(ctx context.Context, name, description string) ([]Site, error) {
	reqBody := struct {
		Cmd  string `json:"cmd"`
		Desc string `json:"desc"`
	}{
		Cmd:  "update-site",
		Desc: description,
	}

	var respBody struct {
		Meta meta   `json:"meta"`
		Data []Site `json:"data"`
	}

	err := c.do(ctx, "POST", fmt.Sprintf("s/%s/cmd/sitemgr", name), reqBody, &respBody)
	if err != nil {
		return nil, err
	}

	return respBody.Data, nil
}

// GetHealth lists health metrics for the logged in UniFi site
func (c *Client) GetHealth(ctx context.Context, site string) (*[]SiteHealth, error) {
	var respBody struct {
		Meta meta          `json:"meta"`
		Data []SiteHealth `json:"data"`
	}

	err := c.do(ctx, "GET", fmt.Sprintf("s/%s/stat/health", site), nil, &respBody)
	if err != nil {
		return &[]SiteHealth{}, err
	}

	return &respBody.Data, nil
}
