/*
 * Copyright (c) 2017 Jason Lowe-Power
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer;
 * redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution;
 * neither the name of the copyright holders nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "dogrudanonbellek.hh"

#include "base/compiler.hh"
#include "base/random.hh"
#include "debug/DogrudanOnbellek.hh"
#include "sim/system.hh"

#include <iostream>  // just testing purpose
using namespace std;

namespace gem5
{

DogrudanOnbellek::DogrudanOnbellek(const DogrudanOnbellekParams &params) :
    ClockedObject(params),
    latency(params.gecikme),
    blockSize(params.system->cacheLineSize()),
    capacity(params.boyut / blockSize),
    memPort(params.name + ".mem_side", this),
    blocked(false), originalPacket(nullptr), waitingPortId(-1), stats(this)
{
    // Since the CPU side ports are a vector of ports, create an instance of
    // the CPUSidePort for each connection. This member of params is
    // automatically created depending on the name of the vector port and
    // holds the number of connections to this port name
    for (int i = 0; i < params.port_cpu_side_connection_count; ++i) {
        cpuPorts.emplace_back(name() + csprintf(".cpu_side[%d]", i), i, this);
    }

    this->yazpolitika = params.yazpolitika; // get information whether write allocate or write no allocate

}

Port &
DogrudanOnbellek::getPort(const std::string &if_name, PortID idx)
{
    // This is the name from the Python SimObject declaration in DogrudanOnbellek.py
    if (if_name == "mem_side") {
        panic_if(idx != InvalidPortID,
                 "Mem side of simple cache not a vector port");
        return memPort;
    } else if (if_name == "cpu_side" && idx < cpuPorts.size()) {
        // We should have already created all of the ports in the constructor
        return cpuPorts[idx];
    } else {
        // pass it along to our super class
        return ClockedObject::getPort(if_name, idx);
    }
}

void
DogrudanOnbellek::CPUSidePort::sendPacket(PacketPtr pkt)
{
    // Note: This flow control is very simple since the cache is blocking.

    panic_if(blockedPacket != nullptr, "Should never try to send if blocked!");

    // If we can't send the packet across the port, store it for later.
    DPRINTF(DogrudanOnbellek, "Sending %s to CPU\n", pkt->print());
    if (!sendTimingResp(pkt)) {  
        DPRINTF(DogrudanOnbellek, "failed!\n");
        blockedPacket = pkt;
    }
}

AddrRangeList
DogrudanOnbellek::CPUSidePort::getAddrRanges() const
{
    return owner->getAddrRanges();
}

void
DogrudanOnbellek::CPUSidePort::trySendRetry()
{
    if (needRetry && blockedPacket == nullptr) {
        // Only send a retry if the port is now completely free
        needRetry = false;
        DPRINTF(DogrudanOnbellek, "Sending retry req.\n");
        sendRetryReq();
    }
}

void
DogrudanOnbellek::CPUSidePort::recvFunctional(PacketPtr pkt)
{
    // Just forward to the cache.
    return owner->handleFunctional(pkt);
}

bool
DogrudanOnbellek::CPUSidePort::recvTimingReq(PacketPtr pkt)
{
    DPRINTF(DogrudanOnbellek, "Got request %s\n", pkt->print());

    if (blockedPacket || needRetry) {
        // The cache may not be able to send a reply if this is blocked
        DPRINTF(DogrudanOnbellek, "Request blocked\n");
        needRetry = true;
        return false;
    }
    // Just forward to the cache.
    if (!owner->handleRequest(pkt, id)) {
        DPRINTF(DogrudanOnbellek, "Request failed\n");
        // stalling
        needRetry = true;
        return false;
    } else {
        DPRINTF(DogrudanOnbellek, "Request succeeded\n");
        return true;
    }
}

void
DogrudanOnbellek::CPUSidePort::recvRespRetry()
{
    // We should have a blocked packet if this function is called.
    assert(blockedPacket != nullptr);

    // Grab the blocked packet.
    PacketPtr pkt = blockedPacket;
    blockedPacket = nullptr;

    DPRINTF(DogrudanOnbellek, "Retrying response pkt %s\n", pkt->print());
    // Try to resend it. It's possible that it fails again.
    sendPacket(pkt);

    // We may now be able to accept new packets
    trySendRetry();
}

void
DogrudanOnbellek::MemSidePort::sendPacket(PacketPtr pkt)
{
    // Note: This flow control is very simple since the cache is blocking.

    panic_if(blockedPacket != nullptr, "Should never try to send if blocked!");

    // If we can't send the packet across the port, store it for later.
    if (!sendTimingReq(pkt)) {  
        blockedPacket = pkt;  
    }
}

bool
DogrudanOnbellek::MemSidePort::recvTimingResp(PacketPtr pkt)
{
    // Just forward to the cache.
    return owner->handleResponse(pkt);
}

void
DogrudanOnbellek::MemSidePort::recvReqRetry()
{
    // We should have a blocked packet if this function is called.
    assert(blockedPacket != nullptr);

    // Grab the blocked packet.
    PacketPtr pkt = blockedPacket;
    blockedPacket = nullptr;

    // Try to resend it. It's possible that it fails again.
    sendPacket(pkt);
}

void
DogrudanOnbellek::MemSidePort::recvRangeChange()
{
    owner->sendRangeChange();
}

bool
DogrudanOnbellek::handleRequest(PacketPtr pkt, int port_id)
{
    if (blocked) {
        // There is currently an outstanding request so we can't respond. Stall
        return false;
    }

    DPRINTF(DogrudanOnbellek, "Got request for addr %#x\n", pkt->getAddr());

    // Here just for debugging purposes
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    Addr addr = pkt->getAddr();
    CacheData *cache_data = new CacheData(addr,this->blockSize,this->capacity * this->blockSize,0);
    DPRINTF(DogrudanOnbellek,"Addres hexa %s\n",cache_data->toHexadecimal(addr));
    DPRINTF(DogrudanOnbellek, "Which row : %llu\n",cache_data->row_index);
    DPRINTF(DogrudanOnbellek,"Addres tag %s\n",cache_data->address_tag);
    DPRINTF(DogrudanOnbellek,"Block size : %#x\n",this->blockSize);
    DPRINTF(DogrudanOnbellek,"Size access : %#x\n",this->capacity * this->blockSize);
    DPRINTF(DogrudanOnbellek,"Policy %s\n",this->yazpolitika);
    if(pkt->isWrite() == 1){
        DPRINTF(DogrudanOnbellek,"Yazma isteği\n");
    }
    else if(pkt->isRead()){
        DPRINTF(DogrudanOnbellek,"Okuma isteği\n");
    }
    delete cache_data; // because there is no need to store
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // This cache is now blocked waiting for the response to this packet.
    blocked = true;

    // Store the port for when we get the response
    assert(waitingPortId == -1);
    waitingPortId = port_id;

    // Schedule an event after cache access latency to actually access
    schedule(new EventFunctionWrapper([this, pkt]{ accessTiming(pkt); },
                                      name() + ".accessEvent", true),
             clockEdge(latency));

    return true;
}

bool
DogrudanOnbellek::handleResponse(PacketPtr pkt)
{
    assert(blocked);
    DPRINTF(DogrudanOnbellek, "Got response for addr %#x\n", pkt->getAddr());
    
    // For now assume that inserts are off of the critical path and don't count
    // for any added latency.

    if(originalPacket != nullptr && (originalPacket->isRead() || (originalPacket->isWrite() && this->yazpolitika == "YAZVEAYIR"))){

        // ıf yazpolitika is YAZVEAYIRMA then do not insert. However we need to write the data to memory in acesstiming function miss handling section

        insert(pkt);

        stats.missLatency.sample(curTick() - missTime);

        // If we had to upgrade the request packet to a full cache line, now we
        // can use that packet to construct the response.
        if (originalPacket != nullptr) {
            DPRINTF(DogrudanOnbellek, "Copying data from new packet to old\n");
            DPRINTF(DogrudanOnbellek,"Address for old packet %#x\n",originalPacket->getAddr());
            // We had to upgrade a previous packet. We can functionally deal with
            // the cache access now. It better be a hit.
            [[maybe_unused]] bool hit = accessFunctional(originalPacket);
            panic_if(!hit, "Should always hit after inserting");
            originalPacket->makeResponse();
            delete pkt; // We may need to delay this, I'm not sure.
            pkt = originalPacket;
            originalPacket = nullptr;

        } // else, pkt contains the data it needs

    }

    sendResponse(pkt);
    return true;

}

void DogrudanOnbellek::sendResponse(PacketPtr pkt)
{

    assert(blocked);
    DPRINTF(DogrudanOnbellek, "Sending resp for addr %#x\n", pkt->getAddr());

    int port = waitingPortId;

    // The packet is now done. We're about to put it in the port, no need for
    // this object to continue to stall.
    // We need to free the resource before sending the packet in case the CPU
    // tries to send another request immediately (e.g., in the same callchain).
    blocked = false;
    waitingPortId = -1;

    // Simply forward to the memory port
    cpuPorts[port].sendPacket(pkt);

    // For each of the cpu ports, if it needs to send a retry, it should do it
    // now since this memory object may be unblocked now.
    for (auto& port : cpuPorts) {
        port.trySendRetry();
    }
}

void
DogrudanOnbellek::handleFunctional(PacketPtr pkt)
{
    if (accessFunctional(pkt)) {
        pkt->makeResponse();
    } else {
        memPort.sendFunctional(pkt);
    }
}

void
DogrudanOnbellek::accessTiming(PacketPtr pkt)
{
    bool hit = accessFunctional(pkt);

    DPRINTF(DogrudanOnbellek, "%s for packet: %s\n", hit ? "Hit" : "Miss",
            pkt->print());

    if (hit) {
        // Respond to the CPU side
        stats.bulmaSayisi++; // update stats
        DDUMP(DogrudanOnbellek, pkt->getConstPtr<uint8_t>(), pkt->getSize());
        pkt->makeResponse();
        sendResponse(pkt);
    } else {
        
        stats.iskaSayisi++; // update stats
        missTime = curTick();
        // Forward to the memory side.
        // We can't directly forward the packet unless it is exactly the size
        // of the cache line, and aligned. Check for that here.
        Addr addr = pkt->getAddr();
        Addr block_addr = pkt->getBlockAddr(blockSize);
        unsigned size = pkt->getSize();
        if (addr == block_addr && size == blockSize) {
            // Aligned and block size. We can just forward.
            DPRINTF(DogrudanOnbellek, "forwarding already aligned packet\n");
            memPort.sendPacket(pkt);
        } else {
            if(pkt->isWrite())
                DPRINTF(DogrudanOnbellek,"YAZMA MISS\n");
            else
                DPRINTF(DogrudanOnbellek,"OKUMA MISS\n");

            DPRINTF(DogrudanOnbellek, "Upgrading packet to block size\n");
            panic_if(addr - block_addr + size > blockSize,
                     "Cannot handle accesses that span multiple cache lines");
            // Unaligned access to one cache block
            assert(pkt->needsResponse());
            MemCmd cmd;
            if (pkt->isWrite() || pkt->isRead()) {
                // Read the data from memory to write into the block.
                // We'll write the data in the cache (i.e., a writeback cache)
                cmd = MemCmd::ReadReq;
            } else {
                panic("Unknown packet type in upgrade size");
            }

            // Create a new packet that is blockSize
            PacketPtr new_pkt = new Packet(pkt->req, cmd, blockSize);
            new_pkt->allocate();

            // Should now be block aligned
            assert(new_pkt->getAddr() == new_pkt->getBlockAddr(blockSize));

            // Save the old packet
            originalPacket = pkt;

            DPRINTF(DogrudanOnbellek,"Original packet addr %#x\n",originalPacket->getAddr());
            DPRINTF(DogrudanOnbellek,"Original packet write %d and read %d\n",originalPacket->isWrite(),originalPacket->isRead());
            DPRINTF(DogrudanOnbellek,"New packet addr %#x\n",new_pkt->getAddr());


            /*
                Here and handleResponseFunctions are important for implementing yazpolitika PAY ATTENTION Crucial  !!!!!!!!!!!!!!!!!!!!!!!            
            
            */

            // ıf writing policy yazveayır simply send new packet otherwise direcly write the data into the memory
            if(originalPacket->isRead() || (originalPacket->isWrite() && this->yazpolitika == "YAZVEAYIR")){
                DPRINTF(DogrudanOnbellek, "forwarding packet\n");
                memPort.sendPacket(new_pkt);
            }
            else{
                DPRINTF(DogrudanOnbellek, "Not forward write directly to memory\n");
                // Write back the data.
                memPort.sendPacket(pkt);  // important to send pkt not new_pkt crucial!!!!!!!!!!!!!!!!!!
            }

        }
        
    }
}
 

bool
DogrudanOnbellek::accessFunctional(PacketPtr pkt)
{
    // get packet address
    Addr addr = pkt->getAddr();
    // produce row_index and address tag and not create data becasue we do not insert
    CacheData *cache_data = new CacheData(addr,this->blockSize,this->capacity * this->blockSize,0);
    // search for given address via row index in cache data
    auto iterator = direct_map_cacheStore.find(cache_data->row_index);
    // if given row is not empty and given address tag is equal to cache data address tag then continue go if
    if (iterator != direct_map_cacheStore.end() && iterator->second->address_tag == cache_data->address_tag) {

        if (pkt->isWrite()) {
            // Write the data into the block in the cache
            DPRINTF(DogrudanOnbellek,"Cache data was changed\n");
            pkt->writeDataToBlock(iterator->second->data, blockSize);
        } else if (pkt->isRead()) {
            // Read the data out of the cache block into the packet
            DPRINTF(DogrudanOnbellek,"Cache data was read\n");
            pkt->setDataFromBlock(iterator->second->data, blockSize);
        } else {
            panic("Unknown packet type!");
        }

        delete cache_data; // we can delete beacuse we do not need any more
        return true;
    }

    delete cache_data; // we can delete beacuse we do not need any more

    return false;
}


void
DogrudanOnbellek::insert(PacketPtr pkt)
{

    // The packet should be aligned.
    assert(pkt->getAddr() ==  pkt->getBlockAddr(blockSize));
    // get packet address
    Addr addr = pkt->getAddr();
    // produce row_index and address tag and create data becasue we will insert important
    CacheData *cache_data = new CacheData(addr,this->blockSize,this->capacity * this->blockSize,1);
    // The address should not be in the cache if there their tag should be different                                // very important section
    assert(direct_map_cacheStore.find(cache_data->row_index) == direct_map_cacheStore.end() || direct_map_cacheStore.find(cache_data->row_index)->second->address_tag != cache_data->address_tag );
    // The pkt should be a response
    assert(pkt->isResponse());
    
    DDUMP(DogrudanOnbellek, pkt->getConstPtr<uint8_t>(), blockSize);

    // if there is already cache data in cache given row index get and deallocate it 
    // we know that if there is already another data in given row_index their tag should be different but their row index should be same beacuse we have direct mapped cache
    auto iterator = direct_map_cacheStore.find(cache_data->row_index);
    if(iterator != direct_map_cacheStore.end()){
        CacheData *removedCache_data = iterator->second;
        DPRINTF(DogrudanOnbellek, "Removing addr %#x\n", removedCache_data->address);
        DPRINTF(DogrudanOnbellek, "Removing\n");
        DPRINTF(DogrudanOnbellek,"Removed Addres hexa %#x\n",removedCache_data->toHexadecimal(removedCache_data->address));
        DPRINTF(DogrudanOnbellek, "Removed Which row : %llu\n",removedCache_data->row_index);
        DPRINTF(DogrudanOnbellek,"Removed Addres tag %s\n",removedCache_data->address_tag);

        // Write back the data.
        // Create a new request-packet pair
        RequestPtr req = std::make_shared<Request>(
            removedCache_data->address, blockSize, 0, 0);

        PacketPtr new_pkt = new Packet(req, MemCmd::WritebackDirty, blockSize);
        new_pkt->dataDynamic(removedCache_data->data); // This will be deleted later

        DPRINTF(DogrudanOnbellek, "Writing packet back %s\n", pkt->print());
        // Send the write to memory
        memPort.sendPacket(new_pkt);

        // Delete this entry
        direct_map_cacheStore.erase(cache_data->row_index);
    }
     
    // Insert the data and address into the cache store
    DPRINTF(DogrudanOnbellek, "Inserting %s\n", pkt->print());
    DPRINTF(DogrudanOnbellek,"Inserted Addres hexa %s\n",cache_data->toHexadecimal(addr));
    DPRINTF(DogrudanOnbellek, "Inserted Which row : %llu\n",cache_data->row_index);
    DPRINTF(DogrudanOnbellek,"Inserted Addres tag %s\n",cache_data->address_tag);

    direct_map_cacheStore[cache_data->row_index] = cache_data; // very important section
    // Write the data into the cache
    pkt->writeDataToBlock(cache_data->data, blockSize);  // also important
            
}

AddrRangeList
DogrudanOnbellek::getAddrRanges() const
{
    DPRINTF(DogrudanOnbellek, "Sending new ranges\n");
    // Just use the same ranges as whatever is on the memory side.
    return memPort.getAddrRanges();
}

void
DogrudanOnbellek::sendRangeChange() const
{
    for (auto& port : cpuPorts) {
        port.sendRangeChange();
    }
}

DogrudanOnbellek::DogrudanOnbellekStats::DogrudanOnbellekStats(statistics::Group *parent)
      : statistics::Group(parent),
      ADD_STAT(bulmaSayisi, statistics::units::Count::get(), "Number of bulma"),
      ADD_STAT(iskaSayisi, statistics::units::Count::get(), "Number of iska"),
      ADD_STAT(missLatency, statistics::units::Tick::get(),
               "Ticks for iska to the cache"),
      ADD_STAT(hitRatio, statistics::units::Ratio::get(),
               "The ratio of bulma to the total accesses to the cache",
               bulmaSayisi / (bulmaSayisi + iskaSayisi))
{
    missLatency.init(16); // number of buckets
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
DogrudanOnbellek::CacheData::CacheData(Addr addr,uint64_t block_size,uint64_t cache_size,bool allocate_data){

    if(allocate_data == 1)
        this->data = new uint8_t[block_size];  // create data depends on flag allocate

    this->address = addr;  // stores the address

    string address = toHexadecimal(addr); // get addres as string hexadecimal
    //prune the 0x section
    //address = address.substr(2);
    // store the how many bit need to be allocated for byte choosing
    uint64_t which_byte_choose = (uint64_t) log2(block_size);
    // store the total_row number information
    uint64_t number_of_rows = (uint64_t)(cache_size /  (double) block_size);
    // store the how many bit need to be allocated for row choosing
    uint64_t which_row_choose = (uint64_t) log2(number_of_rows);
    //convert hexadecimal address to binary address
    address = fromHexaDecimalToBinary(address);
    // get index info as string from address and store the index information
    string index_str = address.substr(64-(which_row_choose+which_byte_choose),which_row_choose);
    this->row_index = fromBinaryToUint64(index_str);
    // get tag info and store 
    this->address_tag = fromBinaryToHexadecimal(address.substr(0,64-(which_byte_choose+which_row_choose)));

}

uint64_t
DogrudanOnbellek::CacheData::fromBinaryToUint64(const std::string& binaryString){
    // Using std::bitset to convert the binary string to uint64_t
    return bitset<64>(binaryString).to_ullong();
}

string
DogrudanOnbellek::CacheData::fromBinaryToHexadecimal(const std::string& binaryString){
    // Convert binary string to uint64_t
    bitset<64> bitset(binaryString);
    uint64_t decimalValue = bitset.to_ullong();

    // Convert decimal value to hexadecimal string
    stringstream hexStream;
    hexStream << std::hex << decimalValue;
    return hexStream.str();
}

string
DogrudanOnbellek::CacheData::fromHexaDecimalToBinary(const std::string& hexString){
    // create hexstream
    istringstream hexStream(hexString);

    uint64_t hexValue;
    //convert int value
    hexStream >> std::hex >> hexValue;
    // turn into binary
    bitset<64> binaryValue(hexValue);
    //return as string
    return binaryValue.to_string();
}

string
DogrudanOnbellek :: CacheData:: toHexadecimal(unsigned long int num){
    stringstream ss;
    ss << hex << num;
    return ss.str();
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

} // namespace gem5
