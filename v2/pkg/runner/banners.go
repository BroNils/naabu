package runner

import (
	"github.com/BroNils/naabu/v2/pkg/privileges"
	"github.com/BroNils/naabu/v2/pkg/scan"
	osutil "github.com/projectdiscovery/utils/os"
	updateutils "github.com/projectdiscovery/utils/update"
	"net"
)

const banner = `
                  __
  ___  ___  ___ _/ /  __ __
 / _ \/ _ \/ _ \/ _ \/ // /
/_//_/\_,_/\_,_/_.__/\_,_/
`

// Version is the current version of naabu
const version = `2.2.0`

// showBanner is used to show the banner to the user
func showBanner() {
	//gologger.Print().Msgf("%s\n", banner)
	//gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")
}

// showNetworkCapabilities shows the network capabilities/scan types possible with the running user
func showNetworkCapabilities(options *Options) {
	var _, _ string

	switch {
	case privileges.IsPrivileged && options.ScanType == SynScan:
		_ = "root"
		if osutil.IsLinux() {
			_ = "CAP_NET_RAW"
		}
		_ = "SYN"
	case options.Passive:
		_ = "non root"
		_ = "PASSIVE"
	default:
		_ = "non root"
		_ = "CONNECT"
	}

	switch {
	case options.OnlyHostDiscovery:
		_ = "Host Discovery"
		//gologger.Info().Msgf("Running %s\n", scanType)
	case options.Passive:
		_ = "PASSIVE"
		//gologger.Info().Msgf("Running %s scan\n", scanType)
	default:
		//gologger.Info().Msgf("Running %s scan with %s privileges\n", scanType, accessLevel)
	}
}

func showHostDiscoveryInfo() {
	//gologger.Info().Msgf("Running host discovery scan\n")
}

func showNetworkInterfaces() error {
	// Interfaces List
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, itf := range interfaces {
		addresses, addErr := itf.Addrs()
		if addErr != nil {
			//gologger.Warning().Msgf("Could not retrieve addresses for %s: %s\n", itf.Name, addErr)
			continue
		}
		var addrstr []string
		for _, address := range addresses {
			addrstr = append(addrstr, address.String())
		}
		//gologger.Info().Msgf("Interface %s:\nMAC: %s\nAddresses: %s\nMTU: %d\nFlags: %s\n", itf.Name, itf.HardwareAddr, strings.Join(addrstr, " "), itf.MTU, itf.Flags.String())
	}
	// External ip
	_, err = scan.WhatsMyIP()
	if err != nil {
		//gologger.Warning().Msgf("Could not obtain public ip: %s\n", err)
	}
	//gologger.Info().Msgf("External Ip: %s\n", externalIP)

	return nil
}

// GetUpdateCallback returns a callback function that updates naabu
func GetUpdateCallback() func() {
	return func() {
		showBanner()
		updateutils.GetUpdateToolCallback("naabu", version)()
	}
}
