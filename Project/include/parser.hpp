#pragma once
#include <fstream>
#include <iostream>
#include "json.hpp"
#include <map>
#include "boost/algorithm/hex.hpp"
#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <stdint.h>
#include "isis.hpp"
#include "utils.hpp"
#include <stdexcept>

using json = nlohmann::json;
void parse(std::map<std::string,std::string>& lsdb, std::string file_json) {

      std::vector<std::string> keys;
      std::ifstream f(file_json);
      json raw = json::parse(f);
      json data = raw["isis-database-information"][0]["isis-database"][1]["isis-database-entry"];


      for (const auto& item : data) {
             if (item.find("lsp-id") != item.end()) {
                  for (const auto& item2 : item["lsp-id"]) {
                             keys.push_back(std::string(item2["data"]));
                  }
                  }
             }

      std::cout << "Found LSPs: " << keys.size() << std::endl;
      if (!keys.size()) {  
            throw std::runtime_error(std::string("no LSPs found in json provided"));
      } 

      for ( int i=0; i<int(keys.size()); ++i )   {
                  unsigned short eth_length{0},pdu_length{0},tlv_length{0},remaining_lifetime{0};
                  uint32_t sequence_number{0};
                  boost::asio::streambuf checksum_pdu;
                  std::ostream os_checksum(&checksum_pdu);
                  boost::asio::streambuf tlvs;
                  std::ostream os_tlvs(&tlvs);
                  boost::asio::streambuf packet;
                  std::ostream os(&packet);


                  eth_header eth;
                  isis_header isis;
                  isis_lsp_header lsp_header;
                  isis.pdu_type(l2_lsp);
                  isis.length_indicator(27);
                  remaining_lifetime = std::stoi(std::string(data[i]["remaining-lifetime"][0]["data"]));
                  std::string lsp_id = std::string(data[i]["lsp-id"][0]["data"]);
                  std::cout << "LSP-ID " << lsp_id << std::endl;
                  boost::erase_all(lsp_id,".");
                  boost::erase_all(lsp_id,"-");
                  sequence_number = htonl(std::stol((std::string(data[i]["sequence-number"][0]["data"]).erase(0,2)),0,16));
                  unsigned char sn_temp[4]{0};
                  std::memcpy(sn_temp, &sequence_number, 4);
                  lsp_header.remaining_lifetime(htons(remaining_lifetime));
                  lsp_header.sequence_num(sn_temp);
                  unsigned char lsp_id_temp[16]{0},lsp_id_packed[8]{0};
                  std::memcpy(lsp_id_temp, lsp_id.c_str(), lsp_id.size());
                  for (int j=0; j<16; ++j) {
                              lsp_id_temp[j]-=0x30;
                  }
                  for (int j=0, k=0; j<8 && k<16; ++j, k+=2) {
                         lsp_id_packed[j]=16*lsp_id_temp[k]  + lsp_id_temp[k+1];
                  }
                  lsp_header.lsp_id(lsp_id_packed);
                  eth_length+= (sizeof(isis) + sizeof(lsp_header) + 3);
                  pdu_length+= (sizeof(isis) + sizeof(lsp_header));
                  os_checksum << isis << lsp_header; /* checksum and length here is 0 */
                  /* TLVs  */
                  /* hostname tlv */
                  if ( !data[i]["isis-tlv"][0]["hostname-tlv"][0]["hostname"][0]["data"].is_null())  {
                            tlv_137 hostname;
                            std::string hostname_str = std::string(data[i]["isis-tlv"][0]["hostname-tlv"][0]["hostname"][0]["data"]);
                            boost::erase_all(hostname_str,".");
                            boost::erase_all(hostname_str,"-");
                            std::unique_ptr<unsigned char[]> hostname_temp_ptr(new unsigned char[hostname_str.size()]{});
                            unsigned char* hostname_temp = hostname_temp_ptr.get();
                            std::cout << "hostname: " << hostname_str << std::endl;
                            std::memcpy(hostname_temp, hostname_str.c_str(), hostname_str.size());
                            hostname.tlv_length(hostname_str.size());
                            hostname.tlv_hostname(hostname_temp,hostname_str.size());
                            /*eth_length += sizeof(hostname);
                            pdu_length += sizeof(hostname);  hostname is special as not fixed, only caped by 255 bytes */
                            eth_length += hostname_str.size()+2;
                            pdu_length += hostname_str.size()+2;
                            tlv_length += hostname_str.size()+2;
                            //os_checksum << std::string(reinterpret_cast<char const*>(hostname.data()),hostname.tlv_length()+2);
                            //os_tlvs << std::string(reinterpret_cast<char const*>(hostname.data()),hostname.tlv_length()+2);
                            os_checksum << hostname;
                            os_tlvs << hostname;
                  } else {  std::cout << "hostname no found " << std::endl; break; } 
                  

                  eth.length(eth_length);
                  lsp_header.pdu_length(htons(pdu_length));
                  /* calculating checksum */
                  std::string checksum_str(boost::asio::buffers_begin(checksum_pdu.data()),
                boost::asio::buffers_begin(checksum_pdu.data()) + checksum_pdu.size());
                  std::unique_ptr<unsigned char[]> checksum_temp_ptr(new unsigned char[checksum_str.size()]{});
                  unsigned char* checksum_temp = checksum_temp_ptr.get();

                  std::memcpy(checksum_temp, checksum_str.c_str(), checksum_str.size());
                  unsigned short checksum = htons(fletcher_checksum(checksum_temp+12,checksum_str.size()-12,12));
                  lsp_header.checksum(htons(checksum));


                  /* constructing final packet */
                  std::string tlvs_str(boost::asio::buffers_begin(tlvs.data()),
                boost::asio::buffers_begin(tlvs.data()) + tlvs.size());
                  os << eth << isis << lsp_header << tlvs_str;
                  std::string packet_str(boost::asio::buffers_begin(packet.data()),
                boost::asio::buffers_begin(packet.data()) + packet.size());

                  /* saving packet to db */
                  lsdb.insert(std::pair<std::string,std::string>(keys[i],packet_str)); 
                  }
} 
