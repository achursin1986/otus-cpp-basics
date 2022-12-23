#pragma once
#include <stdint.h>

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>

#include "boost/algorithm/hex.hpp"
#include "isis.hpp"
#include "json.hpp"
#include "utils.hpp"

using json = nlohmann::json;
void parse(std::map<std::string, std::string>& lsdb, std::string file_json) {
	std::vector<std::string> keys;
	std::ifstream f(file_json);
	json raw = json::parse(f);
	json data = raw["isis-database-information"][0]["isis-database"][1]
		       ["isis-database-entry"];

	for (const auto& item : data) {
		if (item.find("lsp-id") != item.end()) {
			for (const auto& item2 : item["lsp-id"]) {
				keys.push_back(std::string(item2["data"]));
			}
		}
	}

	std::cout << "Found LSPs: " << keys.size() << std::endl;
	if (!keys.size()) {
		throw std::runtime_error(
		    std::string("no LSPs found in json provided"));
	}

	for (int i = 0; i < int(keys.size()); ++i) {
		unsigned short eth_length{0}, pdu_length{0},
		    remaining_lifetime{0};
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
		remaining_lifetime = std::stoi(
		    std::string(data[i]["remaining-lifetime"][0]["data"]));
		std::string lsp_id = std::string(data[i]["lsp-id"][0]["data"]);
		std::cout << "LSP-ID " << lsp_id << std::endl;
		boost::erase_all(lsp_id, ".");
		boost::erase_all(lsp_id, "-");
		sequence_number = htonl(std::stol(
		    (std::string(data[i]["sequence-number"][0]["data"])
			 .erase(0, 2)),
		    0, 16));
		unsigned char sn_temp[4]{0};
		std::memcpy(sn_temp, &sequence_number, 4);
		lsp_header.remaining_lifetime(htons(remaining_lifetime));
		lsp_header.sequence_num(sn_temp);
		unsigned char lsp_id_temp[16]{0}, lsp_id_packed[8]{0};
		std::memcpy(lsp_id_temp, lsp_id.c_str(), lsp_id.size());
		for (int j = 0; j < 16; ++j) {
			lsp_id_temp[j] -= 0x30;
		}
		for (int j = 0, k = 0; j < 8 && k < 16; ++j, k += 2) {
			lsp_id_packed[j] =
			    16 * lsp_id_temp[k] + lsp_id_temp[k + 1];
		}
		lsp_header.lsp_id(lsp_id_packed);
		eth_length += (sizeof(isis) + sizeof(lsp_header) + 3);
		pdu_length += (sizeof(isis) + sizeof(lsp_header));
		os_checksum << isis
			    << lsp_header; /* checksum and length here is 0 */
		/* TLVs  */
		/* hostname tlv */
		if (!data[i]["isis-tlv"][0]["hostname-tlv"][0]["hostname"][0]
			 ["data"]
			     .is_null()) {
			tlv_137 hostname;
			std::string hostname_str =
			    std::string(data[i]["isis-tlv"][0]["hostname-tlv"]
					    [0]["hostname"][0]["data"]);
			boost::erase_all(hostname_str, ".");
			boost::erase_all(hostname_str, "-");
			std::unique_ptr<unsigned char[]> hostname_temp_ptr(
			    new unsigned char[hostname_str.size()]{});
			unsigned char* hostname_temp = hostname_temp_ptr.get();
			std::cout << "hostname: " << hostname_str << std::endl;
			std::memcpy(hostname_temp, hostname_str.c_str(),
				    hostname_str.size());
			hostname.tlv_length(hostname_str.size());
			hostname.tlv_hostname(hostname_temp,
					      hostname_str.size());
			/*eth_length += sizeof(hostname);
			pdu_length += sizeof(hostname);  hostname is special as
			not fixed, only caped by 255 bytes */
			eth_length += hostname_str.size() + 2;
			pdu_length += hostname_str.size() + 2;
			os_checksum << hostname;
			os_tlvs << hostname;
		} else {
			std::cout << "hostname not found " << std::endl;
			break;
		}

		/* buffer size tlv */
		if (!data[i]["isis-tlv"][0]["lsp-buffer-size-tlv"][0]
			 ["lsp-buffer-size"][0]["data"]
			     .is_null()) {
			tlv_14 buffer_size;
			std::string buffer_size_str = std::string(
			    data[i]["isis-tlv"][0]["lsp-buffer-size-tlv"][0]
				["lsp-buffer-size"][0]["data"]);
			buffer_size.set_size(htons(std::stol(buffer_size_str)));
			eth_length += 4;
			pdu_length += 4;
			os_checksum << buffer_size;
			os_tlvs << buffer_size;
		}

		/* protocols supported tlv */
		if (!data[i]["isis-tlv"][0]["protocols-tlv"][0]["protocol"][0]
			 ["data"]
			     .is_null()) {
			tlv_129_ext protocols_supported;
			unsigned int index{0}, length{0};
			for (const auto& item :
			     data[i]["isis-tlv"][0]["protocols-tlv"][0]
				 ["protocol"]) {
				std::string protocols =
				    std::string(item["data"]);
#ifdef DEBUG
				std::cout << protocols << std::endl;
#endif
				if (protocols.compare("Speaks: IP") == 0) {
					length++;
					protocols_supported.nlpid(0xcc, index);
					index++;
				} else if (protocols.compare("Speaks: IPV6") ==
					   0) {
					length++;
					protocols_supported.nlpid(0x8e, index);
					index++;
				} else if (protocols.compare("Speaks: CLNP") ==
					   0) {
					length++;
					protocols_supported.nlpid(0x81, index);
					index++;
				}
			}
			protocols_supported.tlv_length(length);
			eth_length += length + 2;
			pdu_length += length + 2;
			os_checksum << protocols_supported;
			os_tlvs << protocols_supported;
		}

		/* ip address tlv 132 */

		if (!data[i]["isis-tlv"][0]["ipaddress-tlv"][0]["address"][0]
			 ["data"]
			     .is_null()) {
			tlv_132 ip;
			std::string ip_str =
			    data[i]["isis-tlv"][0]["ipaddress-tlv"][0]
				["address"][0]["data"];
			unsigned char ip_array[4]{};
			size_t ip_pos = 0;
			std::string ip_delimiter = ".";
			std::string ip_part_1{}, ip_part_2{}, ip_part_3{},
			    ip_part_4{};
			ip_pos = ip_str.find(ip_delimiter);
			ip_part_1 = ip_str.substr(0, ip_pos);
			ip_str.erase(0, ip_pos + ip_delimiter.length());
			ip_pos = ip_str.find(ip_delimiter);
			ip_part_2 = ip_str.substr(0, ip_pos);
			ip_str.erase(0, ip_pos + ip_delimiter.length());
			ip_pos = ip_str.find(ip_delimiter);
			ip_part_3 = ip_str.substr(0, ip_pos);
			ip_str.erase(0, ip_pos + ip_delimiter.length());
			ip_part_4 = ip_str;
			ip_array[0] = static_cast<unsigned char>(
			    std::stoi(ip_part_1, 0, 10));
			ip_array[1] = static_cast<unsigned char>(
			    std::stoi(ip_part_2, 0, 10));
			ip_array[2] = static_cast<unsigned char>(
			    std::stoi(ip_part_3, 0, 10));
			ip_array[3] = static_cast<unsigned char>(
			    std::stoi(ip_part_4, 0, 10));

			ip.ip_address(ip_array);
			eth_length += 6;
			pdu_length += 6;
			os_checksum << ip;
			os_tlvs << ip;
		}

		/* area address tlv 1 */

		if (!data[i]["isis-tlv"][0]["area-address-tlv"][0]["address"][0]
			 ["data"]
			     .is_null()) {
			tlv_1 area;
			std::string area_str =
			    data[i]["isis-tlv"][0]["area-address-tlv"][0]
				["address"][0]["data"];

			unsigned char area_array[4]{};
			area_array[0] = 0x3;
			size_t area_pos = 0;
			std::string area_delimiter = ".";
			std::string area_part_1{}, area_part_2{};
			area_pos = area_str.find(area_delimiter);
			area_part_1 = area_str.substr(0, area_pos);
			area_part_2 = area_str.erase(
			    0, area_pos + area_delimiter.length());
			area_array[1] = static_cast<unsigned char>(
			    std::stoi(area_part_1, 0, 16));
			area_array[2] = static_cast<unsigned char>(
			    std::stoi(area_part_2, 0, 16) >> 8);
			area_array[3] = static_cast<unsigned char>(
			    std::stoi(area_part_2, 0, 16) & 0xFF);
			area.area(area_array);
			eth_length += 6;
			pdu_length += 6;
			os_checksum << area;
			os_tlvs << area;
		}

		/* traffic engineering router id tlv 134 */

		if (!data[i]["isis-tlv"][0]["router-id-tlv"][0]["router-id"][0]
			 ["data"]
			     .is_null()) {
			tlv_134 te_id;
			std::string te_id_str =
			    data[i]["isis-tlv"][0]["router-id-tlv"][0]
				["router-id"][0]["data"];
			unsigned char te_id_array[4]{};
			size_t te_id_pos = 0;
			std::string te_id_delimiter = ".";
			std::string te_id_part_1{}, te_id_part_2{},
			    te_id_part_3{}, te_id_part_4{};
			te_id_pos = te_id_str.find(te_id_delimiter);
			te_id_part_1 = te_id_str.substr(0, te_id_pos);
			te_id_str.erase(0,
					te_id_pos + te_id_delimiter.length());
			te_id_pos = te_id_str.find(te_id_delimiter);
			te_id_part_2 = te_id_str.substr(0, te_id_pos);
			te_id_str.erase(0,
					te_id_pos + te_id_delimiter.length());
			te_id_pos = te_id_str.find(te_id_delimiter);
			te_id_part_3 = te_id_str.substr(0, te_id_pos);
			te_id_str.erase(0,
					te_id_pos + te_id_delimiter.length());
			te_id_part_4 = te_id_str;
			te_id_array[0] = static_cast<unsigned char>(
			    std::stoi(te_id_part_1, 0, 10));
			te_id_array[1] = static_cast<unsigned char>(
			    std::stoi(te_id_part_2, 0, 10));
			te_id_array[2] = static_cast<unsigned char>(
			    std::stoi(te_id_part_3, 0, 10));
			te_id_array[3] = static_cast<unsigned char>(
			    std::stoi(te_id_part_4, 0, 10));

			te_id.ip_address(te_id_array);
			eth_length += 6;
			pdu_length += 6;
			os_checksum << te_id;
			os_tlvs << te_id;
		}
		/* ipv6 interface address tlv 232 */
		if (!data[i]["isis-tlv"][0]["ipv6address-tlv"][0]["address"][0]
			 ["data"]
			     .is_null()) {
			tlv_232 ipv6_addr;
			std::string ipv6_addr_str =
			    data[i]["isis-tlv"][0]["ipv6address-tlv"][0]
				["address"][0]["data"];

			// unsigned char ipv6_addr_array[16]{};
			IPv6Address ipv6_addr_array;
			ipv6_addr_array.fromString(ipv6_addr_str.c_str());
			ipv6_addr.ip_address(ipv6_addr_array.getAddr());
			eth_length += 18;
			pdu_length += 18;
			os_checksum << ipv6_addr;
			os_tlvs << ipv6_addr;
		}
		/* extended IS reachability  tlv 22 x n neighbors*/

		/* iterating over tlvs 22 */
		for (const auto& item : data[i]["isis-tlv"][0].items()) {
			std::string key_str = std::string(item.key());
			if (key_str.find("ext-reachability-tlv") !=
			    std::string::npos) {
				tlv_22 ext_reach;
				unsigned int length{}, sub_length{};
				boost::erase_all(key_str,
						 "ext-reachability-tlv");
				std::string rkey_str =
				    "reachability-tlv" + key_str;
				/* get reachability tlv processed */
				std::string neighbor_id = std::string(
				    data[i]["isis-tlv"][0][rkey_str][0]
					["address-prefix"][0]["data"]);
				boost::erase_all(neighbor_id, ".");
				unsigned char neighbor_id_temp[14]{0},
				    neighbor_id_packed[7]{0};
				std::memcpy(neighbor_id_temp,
					    neighbor_id.c_str(),
					    neighbor_id.size());
				for (int j = 0; j < 14; ++j) {
					neighbor_id_temp[j] -= 0x30;
				}
				for (int j = 0, k = 0; j < 7 && k < 14;
				     ++j, k += 2) {
					neighbor_id_packed[j] =
					    16 * neighbor_id_temp[k] +
					    neighbor_id_temp[k + 1];
				}
				ext_reach.neighbor_sysid(neighbor_id_packed);
				std::string metric_str =
				    std::string(data[i]["isis-tlv"][0][rkey_str]
						    [0]["metric"][0]["data"]);
				unsigned int metric = std::stol(metric_str);
				unsigned char metric_array[3]{};
				metric_array[2] = (metric >> 0) & 0xFF;
				metric_array[1] = (metric >> 8) & 0xFF;
				metric_array[0] = (metric >> 16) & 0xFF;
				ext_reach.metric(metric_array);
				std::string subclv_length_str = std::string(
				    data[i]["isis-tlv"][0][rkey_str][0]
					["subtlv-length"][0]["data"]);
				/*ext_reach.subclv_length(
				    static_cast<unsigned char>(
					std::stoi(subclv_length_str, 0, 16)));*/
				length += 13;
				eth_length += 13;
				pdu_length += 13;

				/* subTLVs */
				subtlv22_c6 ip_interface_addr;
				subtlv22_c8 neighbor_ip_addr;
				subtlv22_c4 local_remote_ifindex;
				for (const auto& subitem :
				     data[i]["isis-tlv"][0][rkey_str][0]
					 ["isis-reachability-subtlv"]
					     .items()) {
					if (!data[i]["isis-tlv"][0][rkey_str][0]
						 ["isis-reachability-subtlv"]
						 [std::stoi(subitem.key())]
						 ["address"][0]["data"]
						     .is_null()) {
						std::string
						    ip_interface_addr_str = data
							[i]["isis-tlv"][0]
							[rkey_str][0]
							["isis-reachability-"
							 "subtlv"][std::stoi(
							    subitem.key())]
							["address"][0]["data"];
						unsigned char
						    ip_interface_addr_array
							[4]{};
						size_t ip_interface_addr_pos =
						    0;
						std::string
						    ip_interface_addr_delimiter =
							".";
						std::string
						    ip_interface_addr_part_1{},
						    ip_interface_addr_part_2{},
						    ip_interface_addr_part_3{},
						    ip_interface_addr_part_4{};
						ip_interface_addr_pos =
						    ip_interface_addr_str.find(
							ip_interface_addr_delimiter);
						ip_interface_addr_part_1 =
						    ip_interface_addr_str.substr(
							0,
							ip_interface_addr_pos);
						ip_interface_addr_str.erase(
						    0,
						    ip_interface_addr_pos +
							ip_interface_addr_delimiter
							    .length());
						ip_interface_addr_pos =
						    ip_interface_addr_str.find(
							ip_interface_addr_delimiter);
						ip_interface_addr_part_2 =
						    ip_interface_addr_str.substr(
							0,
							ip_interface_addr_pos);
						ip_interface_addr_str.erase(
						    0,
						    ip_interface_addr_pos +
							ip_interface_addr_delimiter
							    .length());
						ip_interface_addr_pos =
						    ip_interface_addr_str.find(
							ip_interface_addr_delimiter);
						ip_interface_addr_part_3 =
						    ip_interface_addr_str.substr(
							0,
							ip_interface_addr_pos);
						ip_interface_addr_str.erase(
						    0,
						    ip_interface_addr_pos +
							ip_interface_addr_delimiter
							    .length());
						ip_interface_addr_part_4 =
						    ip_interface_addr_str;
						ip_interface_addr_array[0] =
						    static_cast<
							unsigned char>(std::stoi(
							ip_interface_addr_part_1,
							0, 16));
						ip_interface_addr_array[1] =
						    static_cast<
							unsigned char>(std::stoi(
							ip_interface_addr_part_2,
							0, 16));
						ip_interface_addr_array[2] =
						    static_cast<
							unsigned char>(std::stoi(
							ip_interface_addr_part_3,
							0, 16));
						ip_interface_addr_array[3] =
						    static_cast<
							unsigned char>(std::stoi(
							ip_interface_addr_part_4,
							0, 16));
						ip_interface_addr.ip_address(
						    ip_interface_addr_array);
						length += 6;
						sub_length += 6;
						eth_length += 6;
						pdu_length += 6;
					}
					if (!data[i]["isis-tlv"][0][rkey_str][0]
						 ["isis-reachability-subtlv"]
						 [std::stoi(subitem.key())]
						 ["neighbor-prefix"][0]["data"]
						     .is_null()) {
						std::string
						    neighbor_ip_addr_str = data
							[i]["isis-tlv"][0]
							[rkey_str][0]
							["isis-reachability-"
							 "subtlv"][std::stoi(
							    subitem.key())]
							["neighbor-prefix"][0]
							["data"];
						unsigned char
						    neighbor_ip_addr_array[4]{};
						size_t neighbor_ip_addr_pos = 0;
						std::string
						    neighbor_ip_addr_delimiter =
							".";
						std::string
						    neighbor_ip_addr_part_1{},
						    neighbor_ip_addr_part_2{},
						    neighbor_ip_addr_part_3{},
						    neighbor_ip_addr_part_4{};
						neighbor_ip_addr_pos =
						    neighbor_ip_addr_str.find(
							neighbor_ip_addr_delimiter);
						neighbor_ip_addr_part_1 =
						    neighbor_ip_addr_str.substr(
							0,
							neighbor_ip_addr_pos);
						neighbor_ip_addr_str.erase(
						    0,
						    neighbor_ip_addr_pos +
							neighbor_ip_addr_delimiter
							    .length());
						neighbor_ip_addr_pos =
						    neighbor_ip_addr_str.find(
							neighbor_ip_addr_delimiter);
						neighbor_ip_addr_part_2 =
						    neighbor_ip_addr_str.substr(
							0,
							neighbor_ip_addr_pos);
						neighbor_ip_addr_str.erase(
						    0,
						    neighbor_ip_addr_pos +
							neighbor_ip_addr_delimiter
							    .length());
						neighbor_ip_addr_pos =
						    neighbor_ip_addr_str.find(
							neighbor_ip_addr_delimiter);
						neighbor_ip_addr_part_3 =
						    neighbor_ip_addr_str.substr(
							0,
							neighbor_ip_addr_pos);
						neighbor_ip_addr_str.erase(
						    0,
						    neighbor_ip_addr_pos +
							neighbor_ip_addr_delimiter
							    .length());
						neighbor_ip_addr_part_4 =
						    neighbor_ip_addr_str;
						neighbor_ip_addr_array[0] =
						    static_cast<
							unsigned char>(std::stoi(
							neighbor_ip_addr_part_1,
							0, 16));
						neighbor_ip_addr_array[1] =
						    static_cast<
							unsigned char>(std::stoi(
							neighbor_ip_addr_part_2,
							0, 16));
						neighbor_ip_addr_array[2] =
						    static_cast<
							unsigned char>(std::stoi(
							neighbor_ip_addr_part_3,
							0, 16));
						neighbor_ip_addr_array[3] =
						    static_cast<
							unsigned char>(std::stoi(
							neighbor_ip_addr_part_4,
							0, 16));
						neighbor_ip_addr.ip_address(
						    neighbor_ip_addr_array);
						length += 6;
						sub_length += 6;
						eth_length += 6;
						pdu_length += 6;
					}
					if (!data[i]["isis-tlv"][0][rkey_str][0]
						 ["isis-reachability-subtlv"]
						 [std::stoi(subitem.key())]
						 ["local-ifindex"][0]["data"]
						     .is_null() &&
					    !data[i]["isis-tlv"][0][rkey_str][0]
						 ["isis-reachability-subtlv"]
						 [std::stoi(subitem.key())]
						 ["remote-ifindex"][0]["data"]
						     .is_null()) {
						std::string local_ifindex_str =
						    std::string(
							data[i]["isis-tlv"][0]
							    [rkey_str][0]
							    ["isis-"
							     "reachability-"
							     "subtlv"]
							    [std::stoi(
								subitem.key())]
							    ["local-ifindex"][0]
							    ["data"]);
						std::string remote_ifindex_str =
						    std::string(
							data[i]["isis-tlv"][0]
							    [rkey_str][0]
							    ["isis-"
							     "reachability-"
							     "subtlv"]
							    [std::stoi(
								subitem.key())]
							    ["remote-ifindex"]
							    [0]["data"]);
						unsigned int local_ifindex =
						    std::stol(
							local_ifindex_str);
						unsigned int remote_ifindex =
						    std::stol(
							remote_ifindex_str);
						unsigned char
						    local_ifindex_array[4]{},
						    remote_ifindex_array[4]{};
						local_ifindex_array[3] =
						    (local_ifindex >> 0) & 0xFF;
						local_ifindex_array[2] =
						    (local_ifindex >> 8) & 0xFF;
						local_ifindex_array[1] =
						    (local_ifindex >> 16) &
						    0xFF;
						local_ifindex_array[0] =
						    (local_ifindex >> 24) &
						    0xFF;

						remote_ifindex_array[3] =
						    (remote_ifindex >> 0) &
						    0xFF;
						remote_ifindex_array[2] =
						    (remote_ifindex >> 8) &
						    0xFF;
						remote_ifindex_array[1] =
						    (remote_ifindex >> 16) &
						    0xFF;
						remote_ifindex_array[0] =
						    (remote_ifindex >> 24) &
						    0xFF;
						local_remote_ifindex
						    .link_local_id(
							local_ifindex_array);
						local_remote_ifindex
						    .link_remote_id(
							remote_ifindex_array);

						length += 10;
						sub_length += 10;
						eth_length += 10;
						pdu_length += 10;
					}
				}
				ext_reach.subclv_length(sub_length);
				ext_reach.tlv_length(length - 2);
				os_checksum << ext_reach << ip_interface_addr
					    << neighbor_ip_addr
					    << local_remote_ifindex;
				os_tlvs << ext_reach << ip_interface_addr
					<< neighbor_ip_addr
					<< local_remote_ifindex;
				// TE
				/*if (!data[i]["isis-tlv"][0][rkey_str][0]
					 ["isis-reachability-subtlv"][4]
					 ["max-bandwidth"][0]["data"]
					     .is_null()) {
					os_checksum << max_bandwidth
						    << max_reserve_bandwidth
					    << unreserved_bandwidth
					    << admin_groups;
					os_tlvs << max_bandwidth
						<< max_reserve_bandwidth
					    << unreserved_bandwidth
					    << admin_groups;  */
			}

			// SR
		}

		/* Ext IP reachability tlv 135 */
		if (!data[i]["isis-tlv"][0]["ip-prefix-tlv"][0]
			 ["address-prefix"][0]["data"]
			     .is_null()) {
			tlv_135 ext_ip_reach;
			unsigned int length = 2;
			eth_length += 2;
			pdu_length += 2;
			boost::asio::streambuf tlv135_temp;
			std::ostream tlv135_stream(&tlv135_temp);

			for (const auto& subitem :
			     data[i]["isis-tlv"][0]["ip-prefix-tlv"].items()) {
				if (!data[i]["isis-tlv"][0]["ip-prefix-tlv"]
					 [std::stoi(subitem.key())]
					 ["address-prefix"][0]["data"]
					     .is_null()) {
					tlv135_ipreach ipreach;
					length += 9;
					eth_length += 9;
					pdu_length += 9;
					std::string ip_metric_str = std::string(
					    data[i]["isis-tlv"][0]
						["ip-prefix-tlv"]
						[std::stoi(subitem.key())]
						["metric"][0]["data"]);
					unsigned int ip_metric =
					    std::stol(ip_metric_str);
					unsigned char ip_metric_array[4]{};
					ip_metric_array[3] =
					    (ip_metric >> 0) & 0xFF;
					ip_metric_array[2] =
					    (ip_metric >> 8) & 0xFF;
					ip_metric_array[1] =
					    (ip_metric >> 16) & 0xFF;
					ip_metric_array[0] =
					    (ip_metric >> 24) & 0xFF;
					ipreach.metric(ip_metric_array);
					std::string ip_prefix_delimiter = "/",
						    ip_addr_delimiter = ".";
					size_t ip_prefix_pos = 0;
					std::string ip_prefix_withlength =
					    std::string(
						data[i]["isis-tlv"][0]
						    ["ip-prefix-tlv"]
						    [std::stoi(subitem.key())]
						    ["address-prefix"][0]
						    ["data"]);
					ip_prefix_pos =
					    ip_prefix_withlength.find(
						ip_prefix_delimiter);
					std::string ip_prefix_str =
					    ip_prefix_withlength.substr(
						0, ip_prefix_pos);
					std::string ip_prefixl_str =
					    ip_prefix_withlength.substr(
						ip_prefix_pos + 1,
						ip_prefix_withlength.length());

					std::string ip_prefix_part_1{},
					    ip_prefix_part_2{},
					    ip_prefix_part_3{},
					    ip_prefix_part_4{};

					ip_prefix_pos = ip_prefix_str.find(
					    ip_addr_delimiter);
					ip_prefix_part_1 = ip_prefix_str.substr(
					    0, ip_prefix_pos);
					ip_prefix_str.erase(
					    0, ip_prefix_pos +
						   ip_addr_delimiter.length());
					ip_prefix_pos = ip_prefix_str.find(
					    ip_addr_delimiter);
					ip_prefix_part_2 = ip_prefix_str.substr(
					    0, ip_prefix_pos);
					ip_prefix_str.erase(
					    0, ip_prefix_pos +
						   ip_addr_delimiter.length());
					ip_prefix_pos = ip_prefix_str.find(
					    ip_addr_delimiter);
					ip_prefix_part_3 = ip_prefix_str.substr(
					    0, ip_prefix_pos);
					ip_prefix_str.erase(
					    0, ip_prefix_pos +
						   ip_addr_delimiter.length());
					ip_prefix_part_4 = ip_prefix_str;
                                        unsigned char ip_prefix_array[4]{};
					ip_prefix_array[0] =
					    static_cast<unsigned char>(
						std::stoi(ip_prefix_part_1, 0,
							  10));
					ip_prefix_array[1] =
					    static_cast<unsigned char>(
						std::stoi(ip_prefix_part_2, 0,
							  10));
					ip_prefix_array[2] =
					    static_cast<unsigned char>(
						std::stoi(ip_prefix_part_3, 0,
							  10));
					ip_prefix_array[3] =
					    static_cast<unsigned char>(
						std::stoi(ip_prefix_part_4, 0,
							  10));
					ipreach.ipv4_prefix(ip_prefix_array);

					unsigned char flags{};
                                        flags = static_cast<unsigned char>(std::stoi(ip_prefixl_str));

					if (std::string(
						data[i]["isis-tlv"][0]
						    ["ip-prefix-tlv"]
						    [std::stoi(subitem.key())]
						    ["prefix-status"][0]
						    ["data"]) == "down") {
						flags |= 1 << 7;
					}
					ipreach.flags(flags);

					tlv135_stream << ipreach;
				}
			}

			std::string tlv135_temp_str(
			    boost::asio::buffers_begin(tlv135_temp.data()),
			    boost::asio::buffers_begin(tlv135_temp.data()) +
				tlv135_temp.size());
			ext_ip_reach.tlv_length(length - 2);
			os_checksum << ext_ip_reach << tlv135_temp_str;
			os_tlvs << ext_ip_reach << tlv135_temp_str;
		}

		// more TLVs go here

		eth.length(eth_length);
		lsp_header.pdu_length(htons(pdu_length));
		/* calculating checksum */
		std::string checksum_str(
		    boost::asio::buffers_begin(checksum_pdu.data()),
		    boost::asio::buffers_begin(checksum_pdu.data()) +
			checksum_pdu.size());
		std::unique_ptr<unsigned char[]> checksum_temp_ptr(
		    new unsigned char[checksum_str.size()]{});
		unsigned char* checksum_temp = checksum_temp_ptr.get();

		std::memcpy(checksum_temp, checksum_str.c_str(),
			    checksum_str.size());
		unsigned short checksum = htons(fletcher_checksum(
		    checksum_temp + 12, checksum_str.size() - 12, 12));
		lsp_header.checksum(htons(checksum));

		/* constructing final packet */
		std::string tlvs_str(
		    boost::asio::buffers_begin(tlvs.data()),
		    boost::asio::buffers_begin(tlvs.data()) + tlvs.size());
		os << eth << isis << lsp_header << tlvs_str;
		std::string packet_str(
		    boost::asio::buffers_begin(packet.data()),
		    boost::asio::buffers_begin(packet.data()) + packet.size());

		/* saving packet to db */
		lsdb.insert(
		    std::pair<std::string, std::string>(keys[i], packet_str));
	}
}
