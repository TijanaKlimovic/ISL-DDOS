package main

import (
    "os"
    "student.ch/netsec/isl/defense/common"
    //"reflect"
    //"fmt"
    "time"
    "strconv"

)

const (
    // Global constants
    ADDR_THRESHOLD = 4
    IA_THRESHOLD = 15
    ADDR_BAD_TIME = time.Second * 13
    IA_BAD_TIME = time.Second * 5
    TIME_INTERVAL = time.Second 
)

type FilterSourceAddr struct{
    TimeStamp   time.Time   
    Done        bool
    Amount      int
}

type SourceAddr struct {
    //Sport       uint16
    Sip         string 
    IA          SourceIA
}

type SourceIA struct{
    SrcISD    uint16
    SrcAS     string
}

type FilterSourceIA struct{
    Done        bool
    TimeStamp   time.Time       //the amount of time we are droping it for
    Amount      int               
}

var (
    FilteredAddrs   map[SourceAddr]FilterSourceAddr
    FilteredIAs     map[SourceIA]FilterSourceIA
    time_interval   time.Time
)


func removePendingAddrs(){
    for key, element := range FilteredAddrs {
        if !element.Done{
            delete(FilteredAddrs, key)
        }
    }
}


func removePendingIAs(){
    for key, element := range FilteredIAs {
        if !element.Done{
            delete(FilteredIAs, key)
        }
    }
}


// Helper function for inspecting packets. Feel free to change / remove this
func printPkt(packet *common.Pkt) {
    printPktSCION(packet.SCION)
    printPktUDP(packet.UDP)
}


// Decide whether to forward or drop a packet based on SCION / UDP header.
// This function receives all packets with the customer as destination
func ForwardPacket(packet *common.Pkt) bool {
    // Print packet contents (disable this before submitting your code)
    //printPkt(packet)

    as := "" ; ip := ""
    for k := 0; k < len(packet.SCION.SrcAS) ; k++ {
        as = as + strconv.Itoa(int(packet.SCION.SrcAS[k]))
    }
    for k := 0; k < len(packet.SCION.SrcHost); k++ {
        ip = ip + strconv.Itoa(int(packet.SCION.SrcHost[k]))
    }

    IA := SourceIA{ SrcISD: packet.SCION.SrcISD, SrcAS: as }
    Addr := SourceAddr{ Sip: ip, IA: IA }
    difference := time.Now().Sub(time_interval)

    //check if the time interval expired to limit rate
    if difference > TIME_INTERVAL {
        removePendingAddrs()
        removePendingIAs()   
        time_interval = time.Now()
    }

    //check if Addr and IA is registered
    entryAddr , found := FilteredAddrs[Addr]
    entryIA , foundIA := FilteredIAs[IA]

    if found{
        //is the registered address a filtered one?
        if entryAddr.Done{
            if time.Since(entryAddr.TimeStamp) > ADDR_BAD_TIME {
                delete(FilteredAddrs, Addr) //remove the Addr from the ones we registered
                }
        //if its not done
        }else{
            //check if the threshold is reached
            if entryAddr.Amount >= ADDR_THRESHOLD{
                entryAddr.TimeStamp = time.Now()
                entryAddr.Done = true               //label as filtered addr
                FilteredAddrs[Addr] = entryAddr
            }else{
                entryAddr.Amount = entryAddr.Amount + 1
                FilteredAddrs[Addr] = entryAddr
                }  
        }
    }else{
        //add a big amount of time so that the 113 check doesnt pass
        timeAddr := time.Now().Add(time.Hour * 24 * 10)
        FilteredAddrs[Addr] = FilterSourceAddr{Amount: 1, TimeStamp: timeAddr, Done: false}
    }
    
    //is the IA part registered? 
    if foundIA{
        if entryIA.Amount >= IA_THRESHOLD{
            entryIA.Done = true
            FilteredIAs[IA] = entryIA
        }else{
            //threshold not reached yet check if we can increase amount
            address := FilteredAddrs[Addr]
            if !address.Done{
                entryIA.Amount = entryIA.Amount + 1
                FilteredIAs[IA] = entryIA
            }
        }
    }else{
        FilteredIAs[IA] = FilterSourceIA{Amount: 1, Done: false}
    }
    
    dangerous_addr := FilteredAddrs[Addr]
    dangerous_IA := FilteredIAs[IA]

    if dangerous_addr.Done || dangerous_IA.Done{
        return false
    }else{
        return true

    }

    // Decision
    // | true  -> forward packet
    // | false -> drop packet
    //return true
}

func main() {
    done := make(chan int, 1)
    FilteredAddrs = make(map[SourceAddr]FilterSourceAddr)
    FilteredIAs = make(map[SourceIA]FilterSourceIA)
    time_interval = time.Now()
    go runFirewall("/usr/local/lib/firewall.so", done) // start the firewall
    code := <-done // wait for an exit code on the channel
    os.Exit(code)
}

