package pfsensehandler

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
)

type HostOverrideReturn struct {
	Code       int    `json:"code"`
	Status     string `json:"status"`
	ResponseID string `json:"response_id"`
	Message    string `json:"message"`
	Data       struct {
		ID      int      `json:"id"`
		Host    string   `json:"host"`
		Domain  string   `json:"domain"`
		IP      []string `json:"ip"`
		Descr   string   `json:"descr"`
		Aliases any      `json:"aliases"`
	} `json:"data"`
}

type HostOverrideReturnFailed struct {
	Code       int    `json:"code"`
	Status     string `json:"status"`
	ResponseID string `json:"response_id"`
	Message    string `json:"message"`
	Data       []any  `json:"data"`
}

type DhcpLeases struct {
	Code       int    `json:"code"`
	Status     string `json:"status"`
	ResponseID string `json:"response_id"`
	Message    string `json:"message"`
	Data       []struct {
		ID           int    `json:"id"`
		IP           string `json:"ip"`
		Mac          string `json:"mac"`
		Hostname     string `json:"hostname"`
		If           any    `json:"if"`
		Starts       string `json:"starts"`
		Ends         string `json:"ends"`
		ActiveStatus string `json:"active_status"`
		OnlineStatus string `json:"online_status"`
		Descr        any    `json:"descr"`
	} `json:"data"`
}

type PfSenseHandler struct {
	url        string
	creds      string
	httpClient *http.Client
}

type HostOverride struct {
	Host    string   `json:"host"`
	Domain  string   `json:"domain"`
	IP      []string `json:"ip"`
	Descr   string   `json:"descr"`
	Aliases []any    `json:"aliases"`
}

func Create(url string, creds string) *PfSenseHandler {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := http.Client{Transport: transport}
	pfSenseAPIHandler := &PfSenseHandler{
		creds:      creds,
		url:        url,
		httpClient: &client,
	}
	return pfSenseAPIHandler
}

func (pf *PfSenseHandler) GetDnsResolverHosts(id int) (HostOverrideReturn, error) {
	req, err := http.NewRequest("GET", pf.url+"/api/v2/services/dns_resolver/host_override?id="+strconv.Itoa(id), nil)
	if err != nil {
		return HostOverrideReturn{}, err
	}

	req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(pf.creds)))
	resp, err := pf.httpClient.Do(req)
	if err != nil {
		return HostOverrideReturn{}, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return HostOverrideReturn{}, err
	}

	hostOverrideReturn := HostOverrideReturn{}
	err = json.Unmarshal(body, &hostOverrideReturn)
	if err != nil {
		ret := HostOverrideReturnFailed{}
		err := json.Unmarshal(body, &ret)
		if err != nil {
			return HostOverrideReturn{}, err
		}

		return HostOverrideReturn{
			Code: ret.Code,
		}, nil

	}

	if hostOverrideReturn.Code != 200 {
		return HostOverrideReturn{}, errors.New("Status code is different then 200, status code: " + hostOverrideReturn.Status)
	}

	return hostOverrideReturn, nil
}

func (pf *PfSenseHandler) DnsResolverOverrideHost(hostOverride HostOverride) error {
	jsonBody, err := json.Marshal(hostOverride)
	if err != nil {
		log.Println("Failed to Marshal hostOverride into json")
	}

	buffer := bytes.NewBuffer(jsonBody)
	req, err := http.NewRequest("POST", pf.url+"/api/v2/services/dns_resolver/host_override", buffer)
	req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(pf.creds)))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("accept", "application/json")
	log.Println(req.Method)
	if err != nil {
		log.Println("Failed to create request due to: ", err.Error())
		return err
	}

	resp, err := pf.httpClient.Do(req)
	b, _ := io.ReadAll(resp.Body)
	log.Println(string(b))
	if err != nil {
		return err
	}

	return nil
}

func (pf *PfSenseHandler) DhcpLeases() (DhcpLeases, error) {
	req, err := http.NewRequest("GET", pf.url+"/api/v2/status/dhcp_server/leases?limit=0&offset=0", nil)
	if err != nil {
		log.Println("Failed to create request due to: ", err.Error())
		return DhcpLeases{}, err
	}

	req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(pf.creds)))
	resp, err := pf.httpClient.Do(req)
	if err != nil {
		return DhcpLeases{}, err
	}

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return DhcpLeases{}, err
	}

	dhcpLeases := DhcpLeases{}
	err = json.Unmarshal(bytes, &dhcpLeases)
	if err != nil {
		return DhcpLeases{}, err
	}

	if dhcpLeases.Code != 200 {
		return DhcpLeases{}, errors.New("Status code is different then 200, status code: " + dhcpLeases.Status)
	}

	return dhcpLeases, nil
}
