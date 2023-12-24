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

#include "kumelionbellek.hh"

#include "base/compiler.hh"
#include "base/random.hh"
#include "debug/KumeliOnbellek.hh"
#include "sim/system.hh"

#include <iostream>  // just testing purpose
using namespace std;

namespace gem5
{

KumeliOnbellek::KumeliOnbellek(const KumeliOnbellekParams &params) :
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

    this->cikarpolitika = params.cikarpolitika; // get data extraction policy

    this->path_number = params.yol;   // gets path number

    // add cache maps into vector
    for(int i=0; i<this->path_number; i++){
        map<uint64_t,CacheData*> cache_table;
        this->cache_tables.push_back(cache_table);
    }


}

Port &
KumeliOnbellek::getPort(const std::string &if_name, PortID idx)
{
    // This is the name from the Python SimObject declaration in KumeliOnbellek.py
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
KumeliOnbellek::CPUSidePort::sendPacket(PacketPtr pkt)
{
    // Note: This flow control is very simple since the cache is blocking.

    panic_if(blockedPacket != nullptr, "Should never try to send if blocked!");

    // If we can't send the packet across the port, store it for later.
    DPRINTF(KumeliOnbellek, "Sending %s to CPU\n", pkt->print());
    if (!sendTimingResp(pkt)) {  
        DPRINTF(KumeliOnbellek, "failed!\n");
        blockedPacket = pkt;
    }
}

AddrRangeList
KumeliOnbellek::CPUSidePort::getAddrRanges() const
{
    return owner->getAddrRanges();
}

void
KumeliOnbellek::CPUSidePort::trySendRetry()
{
    if (needRetry && blockedPacket == nullptr) {
        // Only send a retry if the port is now completely free
        needRetry = false;
        DPRINTF(KumeliOnbellek, "Sending retry req.\n");
        sendRetryReq();
    }
}

void
KumeliOnbellek::CPUSidePort::recvFunctional(PacketPtr pkt)
{
    // Just forward to the cache.
    return owner->handleFunctional(pkt);
}

bool
KumeliOnbellek::CPUSidePort::recvTimingReq(PacketPtr pkt)
{
    DPRINTF(KumeliOnbellek, "Got request %s\n", pkt->print());

    if (blockedPacket || needRetry) {
        // The cache may not be able to send a reply if this is blocked
        DPRINTF(KumeliOnbellek, "Request blocked\n");
        needRetry = true;
        return false;
    }
    // Just forward to the cache.
    if (!owner->handleRequest(pkt, id)) {
        DPRINTF(KumeliOnbellek, "Request failed\n");
        // stalling
        needRetry = true;
        return false;
    } else {
        DPRINTF(KumeliOnbellek, "Request succeeded\n");
        return true;
    }
}

void
KumeliOnbellek::CPUSidePort::recvRespRetry()
{
    // We should have a blocked packet if this function is called.
    assert(blockedPacket != nullptr);

    // Grab the blocked packet.
    PacketPtr pkt = blockedPacket;
    blockedPacket = nullptr;

    DPRINTF(KumeliOnbellek, "Retrying response pkt %s\n", pkt->print());
    // Try to resend it. It's possible that it fails again.
    sendPacket(pkt);

    // We may now be able to accept new packets
    trySendRetry();
}

void
KumeliOnbellek::MemSidePort::sendPacket(PacketPtr pkt)
{
    // Note: This flow control is very simple since the cache is blocking.

    panic_if(blockedPacket != nullptr, "Should never try to send if blocked!");

    // If we can't send the packet across the port, store it for later.
    if (!sendTimingReq(pkt)) {  
        blockedPacket = pkt;  
    }
}

bool
KumeliOnbellek::MemSidePort::recvTimingResp(PacketPtr pkt)
{
    // Just forward to the cache.
    return owner->handleResponse(pkt);
}

void
KumeliOnbellek::MemSidePort::recvReqRetry()
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
KumeliOnbellek::MemSidePort::recvRangeChange()
{
    owner->sendRangeChange();
}

bool
KumeliOnbellek::handleRequest(PacketPtr pkt, int port_id)
{
    if (blocked) {
        // There is currently an outstanding request so we can't respond. Stall
        return false;
    }

    DPRINTF(KumeliOnbellek, "Got request for addr %#x\n", pkt->getAddr());

    // Here just for debugging purposes
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    Addr addr = pkt->getAddr();
    CacheData *cache_data = new CacheData(addr,this->blockSize,this->path_number,this->capacity * this->blockSize,0);
    DPRINTF(KumeliOnbellek,"Addres hexa %s\n",cache_data->toHexadecimal(addr));
    DPRINTF(KumeliOnbellek, "Which row : %llu\n",cache_data->row_index);
    DPRINTF(KumeliOnbellek,"Addres tag %s\n",cache_data->address_tag);
    DPRINTF(KumeliOnbellek,"Block size : %#x\n",this->blockSize);
    DPRINTF(KumeliOnbellek,"Size access : %#x\n",this->capacity * this->blockSize);
    DPRINTF(KumeliOnbellek,"Policy %s\n",this->yazpolitika);
    DPRINTF(KumeliOnbellek,"Vector size equal to yol sayisi : %d\n",this->cache_tables.size());
    if(pkt->isWrite() == 1){
        DPRINTF(KumeliOnbellek,"Yazma isteği\n");
    }
    else if(pkt->isRead()){
        DPRINTF(KumeliOnbellek,"Okuma isteği\n");
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
KumeliOnbellek::handleResponse(PacketPtr pkt)
{
    assert(blocked);
    DPRINTF(KumeliOnbellek, "Got response for addr %#x\n", pkt->getAddr());
    
    // For now assume that inserts are off of the critical path and don't count
    // for any added latency.

    if(originalPacket != nullptr && (originalPacket->isRead() || (originalPacket->isWrite() && this->yazpolitika == "YAZVEAYIR"))){

        insert(pkt);

        stats.missLatency.sample(curTick() - missTime);

        // If we had to upgrade the request packet to a full cache line, now we
        // can use that packet to construct the response.
        if (originalPacket != nullptr) {
            DPRINTF(KumeliOnbellek, "Copying data from new packet to old\n");
            DPRINTF(KumeliOnbellek,"Address for old packet %#x\n",originalPacket->getAddr());
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

void KumeliOnbellek::sendResponse(PacketPtr pkt)
{

    assert(blocked);
    if(pkt != nullptr)
        DPRINTF(KumeliOnbellek, "Sending resp for addr %#x\n", pkt->getAddr());

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
KumeliOnbellek::handleFunctional(PacketPtr pkt)
{
    if (accessFunctional(pkt)) {
        pkt->makeResponse();
    } else {
        memPort.sendFunctional(pkt);
    }
}


void
KumeliOnbellek::accessTiming(PacketPtr pkt)
{

    // here change will not be implement since it is not different from direct mapped cache logic for accesstiming methdo

    bool hit = accessFunctional(pkt);

    DPRINTF(KumeliOnbellek, "%s for packet: %s\n", hit ? "Hit" : "Miss",
            pkt->print());

    if (hit) {
        // Respond to the CPU side
        stats.bulmaSayisi++; // update stats
        DDUMP(KumeliOnbellek, pkt->getConstPtr<uint8_t>(), pkt->getSize());
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
            DPRINTF(KumeliOnbellek, "forwarding already aligned packet\n");
            memPort.sendPacket(pkt);
        } else {
            if(pkt->isWrite())
                DPRINTF(KumeliOnbellek,"YAZMA MISS\n");
            else
                DPRINTF(KumeliOnbellek,"OKUMA MISS\n");

            DPRINTF(KumeliOnbellek, "Upgrading packet to block size\n");
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

            DPRINTF(KumeliOnbellek,"Original packet addr %#x\n",originalPacket->getAddr());
            DPRINTF(KumeliOnbellek,"Original packet write %d and read %d\n",originalPacket->isWrite(),originalPacket->isRead());
            DPRINTF(KumeliOnbellek,"New packet addr %#x\n",new_pkt->getAddr());

            /*
                Here and handleResponseFunctions are important for implementing yazpolitika PAY ATTENTION Crucial  !!!!!!!!!!!!!!!!!!!!!!!            
            */
            // ıf writing policy yazveayır simply send new packet otherwise direcly write the data into the memory
            if(originalPacket->isRead() || (originalPacket->isWrite() && this->yazpolitika == "YAZVEAYIR")){
                DPRINTF(KumeliOnbellek, "forwarding packet\n");
                memPort.sendPacket(new_pkt);
            }
            else{
                DPRINTF(KumeliOnbellek, "Not forward write directly to memory\n");
                // Write back the data.
                memPort.sendPacket(pkt);  // important to send pkt not new_pkt crucial!!!!!!!!!!!!!!!!!!
            }


        }
        
    }
}
 

bool
KumeliOnbellek::accessFunctional(PacketPtr pkt)
{
    // get packet address
    Addr addr = pkt->getAddr();
    // produce row_index and address tag and not create data becasue we do not insert
    CacheData *cache_data = new CacheData(addr,this->blockSize,this->path_number,this->capacity * this->blockSize,0);
    // Because we have set assosiative cache we need to search all tables
    for(size_t i=0; i<this->cache_tables.size(); i++){
        // search for given address via row index in cache data
        auto iterator = cache_tables[i].find(cache_data->row_index);

        if (iterator != cache_tables[i].end() && iterator->second->address_tag == cache_data->address_tag) {

            // very important to save last process time pay attention to this
            iterator->second->last_process_time = chrono::high_resolution_clock::now();
        
            if (pkt->isWrite()) {
                // Write the data into the block in the cache
                DPRINTF(KumeliOnbellek,"Cache data was changed in cache table no : %d\n",i);
                pkt->writeDataToBlock(iterator->second->data, blockSize);
            } else if (pkt->isRead()) {
                // Read the data out of the cache block into the packet
                DPRINTF(KumeliOnbellek,"Cache data was read in cache table no : %d\n",i);
                pkt->setDataFromBlock(iterator->second->data, blockSize);
            } else {
                panic("Unknown packet type!");
            }

            delete cache_data; // we can delete beacuse we do not need any more
            return true;
         }

    }

    delete cache_data; // we can delete beacuse we do not need any more
    return false;

}

void
KumeliOnbellek::insert(PacketPtr pkt)
{

    // The packet should be aligned.
    assert(pkt->getAddr() ==  pkt->getBlockAddr(blockSize));
    // get packet address
    Addr addr = pkt->getAddr();
    // produce row_index and address tag and create data becasue we will insert important
    CacheData *cache_data = new CacheData(addr,this->blockSize,this->path_number,this->capacity * this->blockSize,1);
    // The address should not be in the cache if there their tag should be different                                // very important section
    // HERE IMPORTANT DATA SHOULD NOT BE IN OL CACHE TABLES
    for(size_t i=0; i<this->cache_tables.size(); i++){
        assert(this->cache_tables[i].find(cache_data->row_index) == this->cache_tables[i].end() || this->cache_tables[i].find(cache_data->row_index)->second->address_tag != cache_data->address_tag );
    }
    // The pkt should be a response
    assert(pkt->isResponse());
    
    DDUMP(KumeliOnbellek, pkt->getConstPtr<uint8_t>(), blockSize);

    // try to find a cache table that given row index empty if all given cache tables row index full then implement cikarpolitika
    map<uint64_t,CacheData*> *cache_table_pointer = nullptr;
    bool isFound = 0;

    for(size_t i=0; i<this->cache_tables.size() && isFound == 0; i++){

        auto iterator = this->cache_tables[i].find(cache_data->row_index);

        if(iterator == this->cache_tables[i].end()){
            isFound = 1;
            DPRINTF(KumeliOnbellek,"Empty cache table found whose num %d\n",i);
            cache_table_pointer = &(this->cache_tables[i]);
        }

    }

    // if given row index is full in all tables then implement data extraction policy
    if(isFound == 0){

        DPRINTF(KumeliOnbellek,"ALL GIVEN INDEXES ARE FULL and POLICY %s\n",this->cikarpolitika);

        // define removed data
        CacheData *removedCache_data = nullptr;

        if(this->cikarpolitika == "EUZK"){

            // loop through all cache tables and find the EUZK table at given row index

            double maxEUZK = std::numeric_limits<double>::min();

            int record_index = 0;

            for(size_t i=0; i<this->cache_tables.size(); i++){

                // get start value from given row index
                chrono::high_resolution_clock::time_point start = this->cache_tables[i][cache_data->row_index]->last_process_time;

                // Stop the clock to calculate euzk policy
                chrono::high_resolution_clock::time_point end = std::chrono::high_resolution_clock::now();

                // Calculate the duration in seconds
                chrono::duration<double> duration_seconds = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);

                // Get the duration in seconds as a double value
                double duration_seconds_value = duration_seconds.count();

                // find max unused cache table at given row
                if(maxEUZK < duration_seconds_value){
                    maxEUZK = duration_seconds_value;
                    cache_table_pointer = &(this->cache_tables[i]);
                    record_index = i;
                }

            }

            // get removed cache data
            removedCache_data = this->cache_tables[record_index][cache_data->row_index];

            // delete the entry
            this->cache_tables[record_index].erase(cache_data->row_index);

            DPRINTF(KumeliOnbellek,"EN UZUN ZAMANDIR KULLANILMAYAN POLICY Data extracted from this table with policy EUZK %d\n",record_index);

        }
        else if(this->cikarpolitika == "RASTGELE"){

            // Create a random number generator engine
            random_device rd;
            mt19937 gen(rd());

            uniform_int_distribution<int> distribution(0, this->cache_tables.size()-1);

            // get random table index to extract the data
            int random_table_index = distribution(gen);

            DPRINTF(KumeliOnbellek,"RANDOM VALUE num %d\n",random_table_index);

            // get the table pointer and delete entry
            cache_table_pointer = &(this->cache_tables[random_table_index]);

            // get removed data
            removedCache_data = this->cache_tables[random_table_index][cache_data->row_index];

            // delete the entry
            this->cache_tables[random_table_index].erase(cache_data->row_index);

            DPRINTF(KumeliOnbellek,"RASTGELE EXTRACTION POLICY Data extracted from randomly table num %d\n",random_table_index);

        }

        DPRINTF(KumeliOnbellek, "Removing addr %#x\n", removedCache_data->address);
        DPRINTF(KumeliOnbellek, "Removing\n");
        DPRINTF(KumeliOnbellek,"Removed Addres hexa %#x\n",removedCache_data->toHexadecimal(removedCache_data->address));
        DPRINTF(KumeliOnbellek, "Removed Which row : %llu\n",removedCache_data->row_index);
        DPRINTF(KumeliOnbellek,"Removed Addres tag %s\n",removedCache_data->address_tag);


        // Write back the data.
        // Create a new request-packet pair
        RequestPtr req = std::make_shared<Request>(
            removedCache_data->address, blockSize, 0, 0);

        PacketPtr new_pkt = new Packet(req, MemCmd::WritebackDirty, blockSize);
        new_pkt->dataDynamic(removedCache_data->data); // This will be deleted later

        DPRINTF(KumeliOnbellek, "Writing packet back %s\n", pkt->print());
        // Send the write to memory
        memPort.sendPacket(new_pkt);

    }


    // Insert the data and address into the cache store
    DPRINTF(KumeliOnbellek, "Inserting %s\n", pkt->print());
    DPRINTF(KumeliOnbellek,"Inserted Addres hexa %s\n",cache_data->toHexadecimal(addr));
    DPRINTF(KumeliOnbellek, "Inserted Which row : %llu\n",cache_data->row_index);
    DPRINTF(KumeliOnbellek,"Inserted Addres tag %s\n",cache_data->address_tag);


    (*cache_table_pointer)[cache_data->row_index] = cache_data; // insert the data

    // Write the data into the cache
    pkt->writeDataToBlock(cache_data->data, blockSize);  // also important
            
}

AddrRangeList
KumeliOnbellek::getAddrRanges() const
{
    DPRINTF(KumeliOnbellek, "Sending new ranges\n");
    // Just use the same ranges as whatever is on the memory side.
    return memPort.getAddrRanges();
}

void
KumeliOnbellek::sendRangeChange() const
{
    for (auto& port : cpuPorts) {
        port.sendRangeChange();
    }
}

KumeliOnbellek::KumeliOnbellekStats::KumeliOnbellekStats(statistics::Group *parent)
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
KumeliOnbellek::CacheData::CacheData(Addr addr,uint64_t block_size,uint64_t path_number,uint64_t cache_size,bool allocate_data){

    this->last_process_time = std::chrono::high_resolution_clock::now();  // when it is created assign its time

    if(allocate_data == 1)
        this->data = new uint8_t[block_size];  // create data depends on flag allocate

    this->address = addr;  // stores the address

    string address = toHexadecimal(addr); // get addres as string hexadecimal
    //prune the 0x section
    //address = address.substr(2);
    // store the how many bit need to be allocated for byte choosing
    uint64_t which_byte_choose = (uint64_t) log2(block_size);
    // store the total_row number information
    uint64_t number_of_rows = (uint64_t)((cache_size / path_number) /  (double) block_size);  // here important because we determine the row number
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
KumeliOnbellek::CacheData::fromBinaryToUint64(const std::string& binaryString){
    // Using std::bitset to convert the binary string to uint64_t
    return bitset<64>(binaryString).to_ullong();
}

string
KumeliOnbellek::CacheData::fromBinaryToHexadecimal(const std::string& binaryString){
    // Convert binary string to uint64_t
    bitset<64> bitset(binaryString);
    uint64_t decimalValue = bitset.to_ullong();

    // Convert decimal value to hexadecimal string
    stringstream hexStream;
    hexStream << std::hex << decimalValue;
    return hexStream.str();
}

string
KumeliOnbellek::CacheData::fromHexaDecimalToBinary(const std::string& hexString){
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
KumeliOnbellek :: CacheData:: toHexadecimal(unsigned long int num){
    stringstream ss;
    ss << hex << num;
    return ss.str();
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

} // namespace gem5
