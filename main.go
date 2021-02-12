package main

import (
    "os"
    "student.ch/netsec/isl/defense/common"
    //"reflect"
    //"fmt"
    "time"
)

const (
    // Global constants
    ADDR_THRESHOLD = 2
    IA_THRESHOLD = 4
    ADDR_BAD_TIME = time.Second 
    IA_BAD_TIME = time.Second * 3

)

//filtered address struct
type FilterSourceAddr struct{
    TimeStamp   time.Time   //time until the addr is considered malicious
    //Addr        SourceAddr 
    Amount      int
}

type SourceAddr struct {
    Sport       uint16
    Sip         []byte
    IA            SIA
    //SrcISD      uint16
    //SrcAS       []byte
}

type SourceIA struct{
    SrcISD    uint16
    SrcAS     []byte
}

//filtered IA struct
type FilterSourceIA struct{
    //IA          SourceIApath    //IA we are filtering from
    TimeStamp   time.Time       //the amount of time we are droping it for
    Amount      int             //current amount fo hosts coming from this IA until the threshold is reached   
}

var (
    // Here, you can define variables that keep state for your firewall
    //filtered []FilterSourceAddr   
    //filteredIAs []FilterSourceIA
    FilteredAddrs   map[SourceAddr]FilterSourceAddr
    FilteredIAs     map[SourceIA]FilterSourceIA
)
/*
func printPkt(packet *common.Pkt) {
    printPktSCION(packet.SCION)
    printPktUDP(packet.UDP)
}


func FindAddr(set []FilterSourceAddr, val SourceAddr)(int, *FilterSourceAddr){
    for i, item := range set {
        if reflect.DeepEqual(item.Addr, val) {
            return i, &item    //return pointer to item so we can check its timestamp and Drop field
        }
    }
    return 0, nil
}

func FindIA(set []FilterSourceIA, val SourceIApath)(int, *FilterSourceIA){
    for i, item := range set {
        if reflect.DeepEqual(item.IA, val) {
            return i, &item    //return pointer to item so we can check its timestamp and Drop field
        }
    }
    return 0, nil
}    
*/
// Decide whether to forward or drop a packet based on SCION / UDP header.
// This function receives all packets with the customer as destination
func ForwardPacket(packet *common.Pkt) bool {
    // Print packet contents (disable this before submitting your code)
    //printPkt(packet)
    //check if the packet is related to a dangerous addr(def1) or dangerous IA(def2)
    //packet is dangerous if dangerous_addr is true or dangerous_IA is true and we dont forward it in that case
    //address found only dangerous if the threshold is passed and timeout is not passed
    dangerous_addr = false
    dangerous_IA = false

    IA := SourceIApath{ SrcISD: packet.SCION.SrcISD, SrcAS: packet.SCION.SrcAS }
    Addr := SourceAddr{Sport: packet.UDP.SrcPort,  Sip: packet.SCION.SrcHost, IA: SIA }

    //check if Addr is registered
    entryAddr , found := FilteredAddrs[Addr]
    entryIA , foundIA := FilteredIAs[IA]

    if found{
        if entryAddr.Amount >= ADDR_THRESHOLD {
            if entryAddr.TimeStamp.Before(time.Now()) {
                delete(FilteredAddrs, Addr) //remove the Addr from the ones we registered
            }else{
                dangerous_addr = true
            }
        //if threshold not passed but the address is still registered increase amount
        }else{
            entryAddr.Amount = entryAddr.Amount + 1
            entryAddr.TimeStamp = time.Now().Add(ADDR_BAD_TIME)
        } 
    }else{ 
        //address not present at all
        timeAddr := time.Now().Add(ADDR_BAD_TIME)
        FilteredAddrs[Addr] = FilterSourceAddr{TimeStamp: timeAddr, Amount: 1}
    }

    //is the IA part registered?
    if foundIA{
        if entryIA.Amount >= IA_THRESHOLD{
            if entryIA.TimeStamp.Before(time.Now()) {
                delete(FilteredIAs, IA) //remove the IA from the ones we registered
            }else{
                dangerous_IA = true
            }
        //threshold not passed
        }else{
            entryIA.Amount = entryIA.Amount + 1
            entryIA.TimeStamp = time.Now().Add(IA_BAD_TIME)
        }
    }else{
        timeIA := time.Now().Add(IA_BAD_TIME)
        FilteredIAs[IA] = FilterSourceAddr{TimeStamp: timeIA, Amount: 1}
    }

    if dangerous_addr || dangerous_IA{
        return false
    }else{
        return true
    }

    /*
    SIA := SourceIApath{ SrcISD: packet.SCION.SrcISD, SrcAS: packet.SCION.SrcAS }
    Source := SourceAddr{Sport: packet.UDP.SrcPort,  Sip: packet.SCION.SrcHost, IA: SIA }

    //check if addr or IA is saved
    i, filterAddr := FindAddr(filtered, Source)
    j, filterIA := FindIA(filteredIAs, SIA)


    //we havent seen this IA+Host before for some time, add it 
    if filterAddr == nil {
        time := time.Now().Add(time.Millisecond * 100)
        dropAddr := FilterSourceAddr{ Addr: Source, Drop: true,  TimeStamp: time}
        filtered = append(filtered, dropAddr)
        return true

    }else{
        if filterAddr.TimeStamp.Before(time.Now()){ //if the timestamp is in the past remove address from being filtered
            filtered[i] = filtered[len(filtered)-1] // Copy last element to index i.
            filtered = filtered[:len(filtered)-1]   // Truncate slice.
            return true
        }else{ 
            return false            
        }         
    }

    if filterIA == nil {
        time := time.Now().Add(time.Second)
        dropIA := FilterSourceIA{ IA: SIA, TimeStamp: time}
        filteredIAs = append(filteredIAs, dropIA)
        return true

    }else{
        if filterIA.TimeStamp.Before(time.Now()){ //if the timestamp is in the past remove address from being filtered
            filteredIAs[j] = filteredIAs[len(filteredIAs)-1] // Copy last element to index i.
            filteredIAs = filteredIAs[:len(filteredIAs)-1]   // Truncate slice.
            return true
        }else{ 
            return false            
        }         
    }
    

    //we havent seen this IA+Host before for some time, add it 
    if filterAddr == nil {
        //add the address to the list of addresses we consider bad
        timeaddr := time.Now().Add(time.Millisecond * 100)
        dropAddr := FilterSourceAddr{ Addr: Source, Drop: true,  TimeStamp: timeaddr}
        filtered = append(filtered, dropAddr)

        // check if the IA has been seen recently 
        if filterIA == nil {
            //if no add it to the IAs we have seen recently
            timeIA := time.Now().Add(time.Second)
            dropIA := FilterSourceIA{ IA: SIA, TimeStamp: timeIA, Amount: 1}
            filteredIAs = append(filteredIAs, dropIA)
            return true

        }else{
            //if yes check if the threshold is reached 
            if filterIA.Amount < THRESHOLD{
                filterIA.Amount = filterIA.Amount+1
                filterIA.TimeStamp = time.Now().Add(time.Second)
                return true 
            }else{ //threshold is reached checked the time since the burst
                    //if yes check if its very recent or a while ago if yes drop it if not pass it
                if filterIA.TimeStamp.Before(time.Now()){ 
                    filteredIAs[j] = filteredIAs[len(filteredIAs)-1] 
                    filteredIAs = filteredIAs[:len(filteredIAs)-1]   
                    return true
                }else{ 
                    return false            
                }
            }
        }
    //the chance of the same HOST=IP+PORT being used in the same IA is very low for def2 so we inspect this for def1 only
    }else{
        if filterAddr.TimeStamp.Before(time.Now()){ //if the timestamp is in the past remove address from being filtered
            filtered[i] = filtered[len(filtered)-1] // Copy last element to index i.
            filtered = filtered[:len(filtered)-1]   // Truncate slice.
            return true
        }else{ 
            return false            
        }         
    }

    */




    // Decision
    // | true  -> forward packet
    // | false -> drop packet
    return true
}

func main() {
    done := make(chan int, 1)
    FilteredAddrs := make(map[SourceAddr]FilterSourceAddr)
    FilteredIAs := make(map[SourceIA]FilterSourceIA)
    go runFirewall("/usr/local/lib/firewall.so", done) // start the firewall
    code := <-done // wait for an exit code on the channel
    os.Exit(code)
}

