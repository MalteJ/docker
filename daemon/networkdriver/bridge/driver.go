package bridge

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker/daemon/networkdriver"
	"github.com/docker/docker/daemon/networkdriver/ipallocator"
	"github.com/docker/docker/daemon/networkdriver/portallocator"
	"github.com/docker/docker/daemon/networkdriver/portmapper"
	"github.com/docker/docker/engine"
	"github.com/docker/docker/nat"
	"github.com/docker/docker/pkg/iptables"
	"github.com/docker/docker/pkg/networkfs/resolvconf"
	"github.com/docker/docker/pkg/parsers/kernel"
	"github.com/docker/libcontainer/netlink"
)

const (
	DefaultNetworkBridge     = "docker0"
	MaxAllocatedPortAttempts = 10
)

// Network interface represents the networking stack of a container
type networkInterface struct {
	IP           net.IP
	IPv6         net.IP
	PortMappings []net.Addr // there are mappings to the host interfaces
}

type ifaces struct {
	c map[string]*networkInterface
	sync.Mutex
}

func (i *ifaces) Set(key string, n *networkInterface) {
	i.Lock()
	i.c[key] = n
	i.Unlock()
}

func (i *ifaces) Get(key string) *networkInterface {
	i.Lock()
	res := i.c[key]
	i.Unlock()
	return res
}

var (
	addrs = []string{
		// Here we don't follow the convention of using the 1st IP of the range for the gateway.
		// This is to use the same gateway IPs as the /24 ranges, which predate the /16 ranges.
		// In theory this shouldn't matter - in practice there's bound to be a few scripts relying
		// on the internal addressing or other stupid things like that.
		// They shouldn't, but hey, let's not break them unless we really have to.
		"172.17.42.1/16", // Don't use 172.16.0.0/16, it conflicts with EC2 DNS 172.16.0.23
		"10.0.42.1/16",   // Don't even try using the entire /8, that's too intrusive
		"10.1.42.1/16",
		"10.42.42.1/16",
		"172.16.42.1/24",
		"172.16.43.1/24",
		"172.16.44.1/24",
		"10.0.42.1/24",
		"10.0.43.1/24",
		"192.168.42.1/24",
		"192.168.43.1/24",
		"192.168.44.1/24",
	}

	bridgeIface     string
	bridgeNetwork   *net.IPNet
	globalV6Network *net.IPNet
	bridgeIPv6      string

	defaultBindingIP  = net.ParseIP("0.0.0.0")
	currentInterfaces = ifaces{c: make(map[string]*networkInterface)}
)

func InitDriver(job *engine.Job) engine.Status {
	var (
		networkv4      *net.IPNet
		networkv6      *net.IPNet
		addrv4         net.Addr
		addrv6         net.Addr
		enableIPTables = job.GetenvBool("EnableIptables")
		enableIPv6     = job.GetenvBool("EnableIPv6")
		icc            = job.GetenvBool("InterContainerCommunication")
		ipMasq         = job.GetenvBool("EnableIpMasq")
		ipForward      = job.GetenvBool("EnableIpForward")
		bridgeIP       = job.Getenv("BridgeIP")
		fixedCIDR      = job.Getenv("FixedCIDR")
		fixedCIDRv6    = job.Getenv("FixedCIDRv6")
	)

	if defaultIP := job.Getenv("DefaultBindingIP"); defaultIP != "" {
		defaultBindingIP = net.ParseIP(defaultIP)
	}

	bridgeIface = job.Getenv("BridgeIface")
	usingDefaultBridge := false
	if bridgeIface == "" {
		usingDefaultBridge = true
		bridgeIface = DefaultNetworkBridge
	}

	log.Infof("getting local bridge device's IP...")
	addrv4, addrv6, err := networkdriver.GetIfaceAddr(bridgeIface, enableIPv6)

	if err != nil {
		log.Infof("Creating Bridge interface...")
		// No Bridge existant. Create one
		// If we're not using the default bridge, fail without trying to create it
		if !usingDefaultBridge {
			return job.Error(err)
		}

		mac := randMacAddr()
		bridgeIPv6Network, err := linkLocalIPv6FromMac(mac)
		if err != nil {
			return job.Error(err)
		}

		// If the iface is not found, try to create it
		if err := configureBridge(bridgeIP, mac, bridgeIPv6Network, enableIPv6); err != nil {
			return job.Error(err)
		}

		addrv4, addrv6, err = networkdriver.GetIfaceAddr(bridgeIface, enableIPv6)
		if err != nil {
			return job.Error(err)
		}
	} else {
		log.Infof("Bridge exists already. Getting info...")
		// validate that the bridge ip matches the ip specified by BridgeIP
		if bridgeIP != "" {
			bip, _, err := net.ParseCIDR(bridgeIP)
			if err != nil {
				return job.Error(err)
			}
			if !networkv4.IP.Equal(bip) {
				return job.Errorf("bridge ip (%s) does not match existing bridge configuration %s", networkv4.IP, bip)
			}
		}
	}

	networkv4 = addrv4.(*net.IPNet)

	log.Infof("enableIPv6 = %t", enableIPv6)
	if enableIPv6 {
		if addrv6 == nil {
			return job.Error(errors.New("IPv6 enabled but no IPv6 detected #6"))
		}
		networkv6 = addrv6.(*net.IPNet)
		bridgeIPv6 = networkv6.IP.String()
	}

	// Configure iptables for link support
	if enableIPTables {
		if err := setupIPTables(addrv4, icc, ipMasq); err != nil {
			return job.Error(err)
		}

		// TODO: Implement IP6Tables
	}

	if ipForward {
		// Enable IPv4 forwarding
		if err := ioutil.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte{'1', '\n'}, 0644); err != nil {
			job.Logf("WARNING: unable to enable IPv4 forwarding: %s\n", err)
		}

		if enableIPv6 {
			// Enable IPv6 forwarding
			if err := ioutil.WriteFile("/proc/sys/net/ipv6/conf/default/forwarding", []byte{'1', '\n'}, 0644); err != nil {
				job.Logf("WARNING: unable to enable IPv6 default forwarding: %s\n", err)
			}
			if err := ioutil.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte{'1', '\n'}, 0644); err != nil {
				job.Logf("WARNING: unable to enable IPv6 all forwarding: %s\n", err)
			}
		}
	}

	// We can always try removing the iptables
	if err := iptables.RemoveExistingChain("DOCKER"); err != nil {
		return job.Error(err)
	}

	/*
		if enableIPv6 {
			if err := ip6tables.RemoveExistingChain("DOCKER"); err != nil {
				return job.Error(err)
			}
		}
	*/

	if enableIPTables {
		chain, err := iptables.NewChain("DOCKER", bridgeIface)
		if err != nil {
			return job.Error(err)
		}
		portmapper.SetIptablesChain(chain)

		/*
			if enableIPv6 {
				return errors.New("IPv6 + iptables is not supported yet")
				chainv6, err := ip6tables.NewChain("DOCKER", bridgeIface)
				if err != nil {
					return job.Error(err)
				}

				chainv6 = nil
				portmapper.SetIp6tablesChain(chainv6)
			}
		*/
	}

	bridgeNetwork = networkv4
	if fixedCIDR != "" {
		_, subnet, err := net.ParseCIDR(fixedCIDR)
		if err != nil {
			return job.Error(err)
		}
		log.Debugf("Subnet: %v", subnet)
		if err := ipallocator.RegisterSubnet(bridgeNetwork, subnet); err != nil {
			return job.Error(err)
		}
	}

	if fixedCIDRv6 != "" {
		_, subnet, err := net.ParseCIDR(fixedCIDRv6)
		if err != nil {
			return job.Error(err)
		}
		log.Debugf("Subnet: %v", subnet)
		if err := ipallocator.RegisterSubnet(subnet, subnet); err != nil {
			return job.Error(err)
		}
		globalV6Network = subnet
	}

	// https://github.com/docker/docker/issues/2768
	job.Eng.Hack_SetGlobalVar("httpapi.bridgeIP", bridgeNetwork.IP)
	if enableIPv6 {
		job.Eng.Hack_SetGlobalVar("httpapi.bridgeIPv6", globalV6Network.IP)
	}

	for name, f := range map[string]engine.Handler{
		"allocate_interface": Allocate,
		"release_interface":  Release,
		"allocate_port":      AllocatePort,
		"link":               LinkContainers,
	} {
		if err := job.Eng.Register(name, f); err != nil {
			return job.Error(err)
		}
	}
	return engine.StatusOK
}

// TODO: Implement IP6Tables support
func setupIPTables(addr net.Addr, icc, ipmasq bool) error {
	// Enable NAT
	return nil

	if ipmasq {
		natArgs := []string{"POSTROUTING", "-t", "nat", "-s", addr.String(), "!", "-o", bridgeIface, "-j", "MASQUERADE"}

		if !iptables.Exists(natArgs...) {
			if output, err := iptables.Raw(append([]string{"-I"}, natArgs...)...); err != nil {
				return fmt.Errorf("Unable to enable network bridge NAT: %s", err)
			} else if len(output) != 0 {
				return fmt.Errorf("Error iptables postrouting: %s", output)
			}
		}
	}

	var (
		args       = []string{"FORWARD", "-i", bridgeIface, "-o", bridgeIface, "-j"}
		acceptArgs = append(args, "ACCEPT")
		dropArgs   = append(args, "DROP")
	)

	if !icc {
		iptables.Raw(append([]string{"-D"}, acceptArgs...)...)

		if !iptables.Exists(dropArgs...) {
			log.Debugf("Disable inter-container communication")
			if output, err := iptables.Raw(append([]string{"-I"}, dropArgs...)...); err != nil {
				return fmt.Errorf("Unable to prevent intercontainer communication: %s", err)
			} else if len(output) != 0 {
				return fmt.Errorf("Error disabling intercontainer communication: %s", output)
			}
		}
	} else {
		iptables.Raw(append([]string{"-D"}, dropArgs...)...)

		if !iptables.Exists(acceptArgs...) {
			log.Debugf("Enable inter-container communication")
			if output, err := iptables.Raw(append([]string{"-I"}, acceptArgs...)...); err != nil {
				return fmt.Errorf("Unable to allow intercontainer communication: %s", err)
			} else if len(output) != 0 {
				return fmt.Errorf("Error enabling intercontainer communication: %s", output)
			}
		}
	}

	// Accept all non-intercontainer outgoing packets
	outgoingArgs := []string{"FORWARD", "-i", bridgeIface, "!", "-o", bridgeIface, "-j", "ACCEPT"}
	if !iptables.Exists(outgoingArgs...) {
		if output, err := iptables.Raw(append([]string{"-I"}, outgoingArgs...)...); err != nil {
			return fmt.Errorf("Unable to allow outgoing packets: %s", err)
		} else if len(output) != 0 {
			return fmt.Errorf("Error iptables allow outgoing: %s", output)
		}
	}

	// Accept incoming packets for existing connections
	existingArgs := []string{"FORWARD", "-o", bridgeIface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}

	if !iptables.Exists(existingArgs...) {
		if output, err := iptables.Raw(append([]string{"-I"}, existingArgs...)...); err != nil {
			return fmt.Errorf("Unable to allow incoming packets: %s", err)
		} else if len(output) != 0 {
			return fmt.Errorf("Error iptables allow incoming: %s", output)
		}
	}
	return nil
}

// configureBridge attempts to create and configure a network bridge interface named `ifaceName` on the host
// If bridgeIP is empty, it will try to find a non-conflicting IP from the Docker-specified private ranges
// If the bridge `ifaceName` already exists, it will only perform the IP address association with the existing
// bridge (fixes issue #8444)
// If an address which doesn't conflict with existing interfaces can't be found, an error is returned.
func configureBridge(bridgeIP string, mac string, bridgeIPv6 string, enableIPv6 bool) error {
	nameservers := []string{}
	resolvConf, _ := resolvconf.Get()
	// we don't check for an error here, because we don't really care
	// if we can't read /etc/resolv.conf. So instead we skip the append
	// if resolvConf is nil. It either doesn't exist, or we can't read it
	// for some reason.
	if resolvConf != nil {
		nameservers = append(nameservers, resolvconf.GetNameserversAsCIDR(resolvConf)...)
	}

	var ifaceAddr string
	if len(bridgeIP) != 0 {
		_, _, err := net.ParseCIDR(bridgeIP)
		if err != nil {
			return err
		}
		ifaceAddr = bridgeIP
	} else {
		for _, addr := range addrs {
			_, dockerNetwork, err := net.ParseCIDR(addr)
			if err != nil {
				return err
			}
			if err := networkdriver.CheckNameserverOverlaps(nameservers, dockerNetwork); err == nil {
				if err := networkdriver.CheckRouteOverlaps(dockerNetwork); err == nil {
					ifaceAddr = addr
					break
				} else {
					log.Debugf("%s %s", addr, err)
				}
			}
		}
	}

	if ifaceAddr == "" {
		return fmt.Errorf("Could not find a free IP address range for interface '%s'. Please configure its address manually and run 'docker -b %s'", bridgeIface, bridgeIface)
	}
	log.Debugf("Creating bridge %s with network %s", bridgeIface, ifaceAddr)

	if err := createBridgeIface(bridgeIface, mac, enableIPv6); err != nil {
		// the bridge may already exist, therefore we can ignore an "exists" error
		if !os.IsExist(err) {
			return err
		}
	}

	iface, err := net.InterfaceByName(bridgeIface)
	if err != nil {
		return err
	}

	ipAddr, ipNet, err := net.ParseCIDR(ifaceAddr)
	if err != nil {
		return err
	}

	if netlink.NetworkLinkAddIp(iface, ipAddr, ipNet); err != nil {
		return fmt.Errorf("Unable to add private network: %s", err)
	}

	if enableIPv6 {
		ipAddr6, ipNet6, err := net.ParseCIDR(bridgeIPv6)
		if err != nil {
			log.Errorf("BridgeIPv6 parsing failed")
			return err
		}

		if netlink.NetworkLinkAddIp(iface, ipAddr6, ipNet6); err != nil {
			return fmt.Errorf("Unable to add private IPv6 network: %s", err)
		}
	}

	if err := netlink.NetworkLinkUp(iface); err != nil {
		return fmt.Errorf("Unable to start network bridge: %s", err)
	}
	return nil
}

func randMacAddr() string {
	hw := make(net.HardwareAddr, 6)
	for i := 0; i < 6; i++ {
		hw[i] = byte(rand.Intn(255))
	}
	hw[0] &^= 0x1 // clear multicast bit
	hw[0] |= 0x2  // set local assignment bit (IEEE802)

	return hw.String()
}

func linkLocalIPv6FromMac(mac string) (string, error) {
	hx := strings.Replace(mac, ":", "", -1)
	hw, err := hex.DecodeString(hx)
	if err != nil {
		return "", errors.New("Could not parse MAC address " + mac)
	}

	hw[0] ^= 0x2

	return fmt.Sprintf("fe80::%x%x:%xff:fe%x:%x%x/64", hw[0], hw[1], hw[2], hw[3], hw[4], hw[5]), nil
}

func createBridgeIface(name string, mac string, forceMac bool) error {
	if e := netlink.CreateBridge(name, false); e != nil {
		return e
	}
	kv, err := kernel.GetKernelVersion()
	if err != nil {
		return err
	}
	// only set the bridge's mac address if the kernel version is > 3.3
	// before that it was not supported
	setBridgeMacAddr := (kv.Kernel >= 3 && kv.Major >= 3)
	if forceMac && !setBridgeMacAddr {
		return errors.New("Could not set MAC to bridge interface due to Kernel version < 3.3")
	}
	log.Debugf("setting bridge mac address = %v", setBridgeMacAddr)
	return netlink.SetMacAddress(name, mac)
}

// Generate a IEEE802 compliant MAC address from the given IP address.
//
// The generator is guaranteed to be consistent: the same IP will always yield the same
// MAC address. This is to avoid ARP cache issues.
func generateMacAddr(ip net.IP) net.HardwareAddr {
	hw := make(net.HardwareAddr, 6)

	// The first byte of the MAC address has to comply with these rules:
	// 1. Unicast: Set the least-significant bit to 0.
	// 2. Address is locally administered: Set the second-least-significant bit (U/L) to 1.
	// 3. As "small" as possible: The veth address has to be "smaller" than the bridge address.
	hw[0] = 0x02

	// The first 24 bits of the MAC represent the Organizationally Unique Identifier (OUI).
	// Since this address is locally administered, we can do whatever we want as long as
	// it doesn't conflict with other addresses.
	hw[1] = 0x42

	// Insert the IP address into the last 32 bits of the MAC address.
	// This is a simple way to guarantee the address will be consistent and unique.
	copy(hw[2:], ip.To4())

	return hw
}

// Allocate a network interface
func Allocate(job *engine.Job) engine.Status {
	enableGlobalIPv6 := job.GetenvBool("EnableGlobalIPv6")
	var (
		ip            net.IP
		globalIPv6    net.IP
		mac           string
		err           error
		id            = job.Args[0]
		requestedIP   = net.ParseIP(job.Getenv("RequestedIP"))   // may be nil
		requestedIPv6 = net.ParseIP(job.Getenv("RequestedIPv6")) // may be nil
	)

	if requestedMac == "" {
		mac = randMacAddr()
		log.Infof("Using new generated MAC address %s", mac)
	} else {
		mac = requestedMac
		log.Infof("Using requested MAC address %s", mac)
	}

	ip, err = ipallocator.RequestIP(bridgeNetwork, requestedIP)
	if err != nil {
		return job.Error(err)
	}

	// If no explicit mac address was given, generate a random one.
	if mac, err = net.ParseMAC(job.Getenv("RequestedMac")); err != nil {
		mac = generateMacAddr(ip)
	}

	if enableGlobalIPv6 {
		log.Infof("Allocate: IPv6 enabled")
		if globalV6Network == nil {
			log.Errorf("ERROR: Allocate: globalV6Network = nil!\n")
		}
		globalIPv6, err = ipallocator.RequestIP(globalV6Network, requestedIPv6)
		if err != nil {
			log.Errorf("Allocator: RequestIP v6: %s", err.Error())
			return job.Error(err)
		}
		log.Infof("Allocated IPv6 %s", globalIPv6)
	} else {
		log.Infof("Allocate: IPv6 disabled")
	}

	out := engine.Env{}
	out.Set("IP", ip.String())
	out.Set("Mask", bridgeNetwork.Mask.String())
	out.Set("Gateway", bridgeNetwork.IP.String())
	out.Set("MacAddress", mac.String())
	out.Set("Bridge", bridgeIface)

	size, _ := bridgeNetwork.Mask.Size()
	out.SetInt("IPPrefixLen", size)

	// if linklocal IPv6
	localIPv6Net, err := linkLocalIPv6FromMac(mac)
	if err != nil {
		return job.Error(err)
	}
	localIPv6, _, _ := net.ParseCIDR(localIPv6Net)
	out.Set("LinkLocalIPv6", localIPv6.String())
	out.Set("MacAddress", mac)

	if enableGlobalIPv6 {
		out.SetBool("EnableGlobalIPv6", true)
		out.Set("GlobalIPv6", globalIPv6.String())
		out.Set("Maskv6", globalV6Network.Mask.String())
		sizev6, _ := globalV6Network.Mask.Size()
		out.SetInt("GlobalIPv6PrefixLen", sizev6)
		out.Set("IPv6Gateway", bridgeIPv6)
		log.Infof("Setting IPv6Gateway: %s", bridgeIPv6)
	}

	currentInterfaces.Set(id, &networkInterface{
		IP:   ip,
		IPv6: globalIPv6,
	})

	out.WriteTo(job.Stdout)

	return engine.StatusOK
}

// release an interface for a select ip
func Release(job *engine.Job) engine.Status {
	enableGlobalIPv6 := job.GetenvBool("EnableGlobalIPv6")

	var (
		id                 = job.Args[0]
		containerInterface = currentInterfaces.Get(id)
	)

	if containerInterface == nil {
		return job.Errorf("No network information to release for %s", id)
	}

	for _, nat := range containerInterface.PortMappings {
		if err := portmapper.Unmap(nat); err != nil {
			log.Infof("Unable to unmap port %s: %s", nat, err)
		}
	}

	if err := ipallocator.ReleaseIP(bridgeNetwork, containerInterface.IP); err != nil {
		log.Infof("Unable to release IPv4 %s", err)
	}
	if enableGlobalIPv6 {
		if err := ipallocator.ReleaseIP(globalV6Network, containerInterface.IPv6); err != nil {
			log.Infof("Unable to release IPv6 %s", err)
		}
	}
	return engine.StatusOK
}

// Allocate an external port and map it to the interface
func AllocatePort(job *engine.Job) engine.Status {
	var (
		err error

		ip            = defaultBindingIP
		id            = job.Args[0]
		hostIP        = job.Getenv("HostIP")
		hostPort      = job.GetenvInt("HostPort")
		containerPort = job.GetenvInt("ContainerPort")
		proto         = job.Getenv("Proto")
		network       = currentInterfaces.Get(id)
	)

	if hostIP != "" {
		ip = net.ParseIP(hostIP)
		if ip == nil {
			return job.Errorf("Bad parameter: invalid host ip %s", hostIP)
		}
	}

	// host ip, proto, and host port
	var container net.Addr
	switch proto {
	case "tcp":
		container = &net.TCPAddr{IP: network.IP, Port: containerPort}
	case "udp":
		container = &net.UDPAddr{IP: network.IP, Port: containerPort}
	default:
		return job.Errorf("unsupported address type %s", proto)
	}

	//
	// Try up to 10 times to get a port that's not already allocated.
	//
	// In the event of failure to bind, return the error that portmapper.Map
	// yields.
	//

	var host net.Addr
	for i := 0; i < MaxAllocatedPortAttempts; i++ {
		if host, err = portmapper.Map(container, ip, hostPort); err == nil {
			break
		}

		if allocerr, ok := err.(portallocator.ErrPortAlreadyAllocated); ok {
			// There is no point in immediately retrying to map an explicitly
			// chosen port.
			if hostPort != 0 {
				job.Logf("Failed to bind %s for container address %s: %s", allocerr.IPPort(), container.String(), allocerr.Error())
				break
			}

			// Automatically chosen 'free' port failed to bind: move on the next.
			job.Logf("Failed to bind %s for container address %s. Trying another port.", allocerr.IPPort(), container.String())
		} else {
			// some other error during mapping
			job.Logf("Received an unexpected error during port allocation: %s", err.Error())
			break
		}
	}

	if err != nil {
		return job.Error(err)
	}

	network.PortMappings = append(network.PortMappings, host)

	out := engine.Env{}
	switch netAddr := host.(type) {
	case *net.TCPAddr:
		out.Set("HostIP", netAddr.IP.String())
		out.SetInt("HostPort", netAddr.Port)
	case *net.UDPAddr:
		out.Set("HostIP", netAddr.IP.String())
		out.SetInt("HostPort", netAddr.Port)
	}
	if _, err := out.WriteTo(job.Stdout); err != nil {
		return job.Error(err)
	}

	return engine.StatusOK
}

func LinkContainers(job *engine.Job) engine.Status {
	var (
		action       = job.Args[0]
		childIP      = job.Getenv("ChildIP")
		parentIP     = job.Getenv("ParentIP")
		ignoreErrors = job.GetenvBool("IgnoreErrors")
		ports        = job.GetenvList("Ports")
	)
	for _, value := range ports {
		port := nat.Port(value)
		if output, err := iptables.Raw(action, "FORWARD",
			"-i", bridgeIface, "-o", bridgeIface,
			"-p", port.Proto(),
			"-s", parentIP,
			"--dport", strconv.Itoa(port.Int()),
			"-d", childIP,
			"-j", "ACCEPT"); !ignoreErrors && err != nil {
			return job.Error(err)
		} else if len(output) != 0 {
			return job.Errorf("Error toggle iptables forward: %s", output)
		}

		if output, err := iptables.Raw(action, "FORWARD",
			"-i", bridgeIface, "-o", bridgeIface,
			"-p", port.Proto(),
			"-s", childIP,
			"--sport", strconv.Itoa(port.Int()),
			"-d", parentIP,
			"-j", "ACCEPT"); !ignoreErrors && err != nil {
			return job.Error(err)
		} else if len(output) != 0 {
			return job.Errorf("Error toggle iptables forward: %s", output)
		}
	}
	return engine.StatusOK
}
