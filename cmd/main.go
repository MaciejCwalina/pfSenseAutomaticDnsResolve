package main

import (
	"log"
	"os"
	"pfSenseAutomaticDnsResolve/pkg/pfsensehandler"
	"time"
)

var pfSenseHandler *pfsensehandler.PfSenseHandler

func GetAllHosts() []pfsensehandler.HostOverrideReturn {
	hosts := []pfsensehandler.HostOverrideReturn{}
	for i := 0; i < 100_000_000; i++ {
		host, err := pfSenseHandler.GetDnsResolverHosts(i)
		if err != nil {
			continue
		}

		if host.Code != 200 {
			break
		}

		hosts = append(hosts, host)
	}

	return hosts
}

func SetRedirects() {
	overrridenHosts := GetAllHosts()
	overrridenHostsMap := make(map[string]bool)
	leases, err := pfSenseHandler.DhcpLeases()
	if err != nil {
		log.Println(err.Error())
	}

	for _, host := range overrridenHosts {
		overrridenHostsMap[host.Data.IP[0]] = true
	}

	for _, lease := range leases.Data {
		if ok := overrridenHostsMap[lease.IP]; ok {
			continue
		}

		hostOverwrite := pfsensehandler.HostOverride{
			Host:    lease.Hostname,
			Domain:  "proxmox.local",
			IP:      []string{lease.IP},
			Descr:   lease.Hostname + " Proxmox VM",
			Aliases: []any{},
		}

		err = pfSenseHandler.DnsResolverOverrideHost(hostOverwrite)
		if err != nil {
			log.Println(err.Error())
			return
		}
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Starting")
	data, err := os.ReadFile("../creds") // Create an actual config system
	if err != nil {
		log.Fatal("Unable to upon the creds file")
	}

	if len(data) == 0 {
		log.Fatal("creds file is empty")
	}

	pfSenseHandler = pfsensehandler.Create("https://pfsense.maciej.com", string(data))
	for {
		go func() {
			SetRedirects()
			time.Sleep(5 * time.Second)
		}()
	}
}
