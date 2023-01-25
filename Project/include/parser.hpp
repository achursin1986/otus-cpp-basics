#pragma once
#include <stdint.h>

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <vector>

#include "boost/algorithm/hex.hpp"
#include "isis.hpp"
#include "json.hpp"
#include "utils.hpp"

using json = nlohmann::json;
void parse(std::map<std::string, std::string>& lsdb, std::string file_json) {
	std::vector<std::string> keys;
	std::ifstream f(file_json);
	std::cout << "Loading JSON ..." << std::endl;
	json raw = json::parse(f);
	json data = raw["isis-database-information"][0]["isis-database"][1]["isis-database-entry"];
	std::cout << "done" << std::endl;
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

	for (int i = 0; i < int(keys.size()); ++i) {
		unsigned short eth_length{0}, pdu_length{0}, remaining_lifetime{0};
		uint32_t sequence_number{0};
		unsigned int our_mt_length{};
		unsigned char topology_neighbor_id[7]{0};
		std::string our_mt_str;
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
		boost::erase_all(lsp_id, ".");
		boost::erase_all(lsp_id, "-");
		sequence_number = htonl(std::stol((std::string(data[i]["sequence-number"][0]["data"]).erase(0, 2)), 0, 16));
		unsigned char sn_temp[4]{0};
		std::memcpy(sn_temp, &sequence_number, 4);
		lsp_header.remaining_lifetime(htons(remaining_lifetime));
		lsp_header.sequence_num(sn_temp);
		unsigned char lsp_id_packed[8]{0};
		/*unsigned char lsp_id_temp[16]{0}, lsp_id_packed[8]{0};
		std::memcpy(lsp_id_temp, lsp_id.c_str(), lsp_id.size());
		for (int j = 0; j < 16; ++j) {
			lsp_id_temp[j] -= 0x30;
		}*/
		for (int j = 0, k = 0; j < 8 && k < 16; ++j, k += 2) {
			lsp_id_packed[j] = static_cast<unsigned char>(std::stoi(lsp_id.substr(k, 2), 0, 16));
		}
		lsp_header.lsp_id(lsp_id_packed);
		if (i == 15) {
			std::memcpy(topology_neighbor_id, lsp_id_packed, 7);
		}
		eth_length += (sizeof(isis) + sizeof(lsp_header) + 3);
		pdu_length += (sizeof(isis) + sizeof(lsp_header));
		os_checksum << isis << lsp_header; /* checksum and length here is 0 */
		/* TLVs  */
		/* hostname tlv */
		if (!data[i]["isis-tlv"][0]["hostname-tlv"][0]["hostname"][0]["data"].is_null()) {
			tlv_137 hostname;
			std::string hostname_str = std::string(data[i]["isis-tlv"][0]["hostname-tlv"][0]["hostname"][0]["data"]);
			boost::erase_all(hostname_str, ".");
			// boost::erase_all(hostname_str, "-");
			std::unique_ptr<unsigned char[]> hostname_temp_ptr(new unsigned char[hostname_str.size()]{});
			unsigned char* hostname_temp = hostname_temp_ptr.get();
			std::cout << "hostname: " << hostname_str << std::endl;
			std::memcpy(hostname_temp, hostname_str.c_str(), hostname_str.size());
			hostname.tlv_length(hostname_str.size());
			hostname.tlv_hostname(hostname_temp, hostname_str.size());
			/*eth_length += sizeof(hostname);
			pdu_length += sizeof(hostname);  hostname is special as
			not fixed, only caped by 255 bytes */
			eth_length += hostname_str.size() + 2;
			pdu_length += hostname_str.size() + 2;
			os_checksum << hostname;
			os_tlvs << hostname;
		}

		/* buffer size tlv */
		if (!data[i]["isis-tlv"][0]["lsp-buffer-size-tlv"][0]["lsp-buffer-size"][0]["data"].is_null()) {
			tlv_14 buffer_size;
			std::string buffer_size_str =
			    std::string(data[i]["isis-tlv"][0]["lsp-buffer-size-tlv"][0]["lsp-buffer-size"][0]["data"]);
			buffer_size.set_size(htons(std::stol(buffer_size_str)));
			eth_length += 4;
			pdu_length += 4;
			os_checksum << buffer_size;
			os_tlvs << buffer_size;
		}

		/* protocols supported tlv */
		if (!data[i]["isis-tlv"][0]["protocols-tlv"][0]["protocol"][0]["data"].is_null()) {
			tlv_129_ext protocols_supported;
			unsigned int index{0}, length{0};
			for (const auto& item : data[i]["isis-tlv"][0]["protocols-tlv"][0]["protocol"]) {
				std::string protocols = std::string(item["data"]);
#ifdef DEBUG
				std::cout << protocols << std::endl;
#endif
				if (protocols.compare("Speaks: IP") == 0) {
					length++;
					protocols_supported.nlpid(0xcc, index);
					index++;
				} else if (protocols.compare("Speaks: IPV6") == 0) {
					length++;
					protocols_supported.nlpid(0x8e, index);
					index++;
				} else if (protocols.compare("Speaks: CLNP") == 0) {
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

		if (!data[i]["isis-tlv"][0]["ipaddress-tlv"][0]["address"][0]["data"].is_null()) {
			tlv_132 ip;
			std::string ip_str = data[i]["isis-tlv"][0]["ipaddress-tlv"][0]["address"][0]["data"];
			unsigned char ip_array[4]{};
			size_t ip_pos = 0;
			std::string ip_delimiter = ".";
			std::string ip_part_1{}, ip_part_2{}, ip_part_3{}, ip_part_4{};
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
			ip_array[0] = static_cast<unsigned char>(std::stoi(ip_part_1, 0, 10));
			ip_array[1] = static_cast<unsigned char>(std::stoi(ip_part_2, 0, 10));
			ip_array[2] = static_cast<unsigned char>(std::stoi(ip_part_3, 0, 10));
			ip_array[3] = static_cast<unsigned char>(std::stoi(ip_part_4, 0, 10));

			ip.ip_address(ip_array);
			eth_length += 6;
			pdu_length += 6;
			os_checksum << ip;
			os_tlvs << ip;
		}

		/* area address tlv 1 */

		if (!data[i]["isis-tlv"][0]["area-address-tlv"][0]["address"][0]["data"].is_null()) {
			// tlv_1 area;
			tlv_1_ext area;
			std::string area_str = data[i]["isis-tlv"][0]["area-address-tlv"][0]["address"][0]["data"];
			boost::erase_all(area_str, ".");
			area.area(area_to_bytes(area_str).get(), area_str.size() / 2);
			area.area_length(area_str.size() / 2);
			area.tlv_length(1 + area_str.size() / 2);
			eth_length += 3 + area_str.size() / 2;
			pdu_length += 3 + area_str.size() / 2;
			os_checksum << area;
			os_tlvs << area;
		}

		/* traffic engineering router id tlv 134 */

		if (!data[i]["isis-tlv"][0]["router-id-tlv"][0]["router-id"][0]["data"].is_null()) {
			tlv_134 te_id;
			std::string te_id_str = data[i]["isis-tlv"][0]["router-id-tlv"][0]["router-id"][0]["data"];
			unsigned char te_id_array[4]{};
			size_t te_id_pos = 0;
			std::string te_id_delimiter = ".";
			std::string te_id_part_1{}, te_id_part_2{}, te_id_part_3{}, te_id_part_4{};
			te_id_pos = te_id_str.find(te_id_delimiter);
			te_id_part_1 = te_id_str.substr(0, te_id_pos);
			te_id_str.erase(0, te_id_pos + te_id_delimiter.length());
			te_id_pos = te_id_str.find(te_id_delimiter);
			te_id_part_2 = te_id_str.substr(0, te_id_pos);
			te_id_str.erase(0, te_id_pos + te_id_delimiter.length());
			te_id_pos = te_id_str.find(te_id_delimiter);
			te_id_part_3 = te_id_str.substr(0, te_id_pos);
			te_id_str.erase(0, te_id_pos + te_id_delimiter.length());
			te_id_part_4 = te_id_str;
			te_id_array[0] = static_cast<unsigned char>(std::stoi(te_id_part_1, 0, 10));
			te_id_array[1] = static_cast<unsigned char>(std::stoi(te_id_part_2, 0, 10));
			te_id_array[2] = static_cast<unsigned char>(std::stoi(te_id_part_3, 0, 10));
			te_id_array[3] = static_cast<unsigned char>(std::stoi(te_id_part_4, 0, 10));

			te_id.ip_address(te_id_array);
			eth_length += 6;
			pdu_length += 6;
			os_checksum << te_id;
			os_tlvs << te_id;
		}
		/* ipv6 interface address tlv 232 */
		if (!data[i]["isis-tlv"][0]["ipv6address-tlv"][0]["address"][0]["data"].is_null()) {
			tlv_232 ipv6_addr;
			std::string ipv6_addr_str = data[i]["isis-tlv"][0]["ipv6address-tlv"][0]["address"][0]["data"];

			IPv6Address ipv6_addr_array;
			ipv6_addr_array.fromString(ipv6_addr_str.c_str());
			ipv6_addr.ip_address(ipv6_addr_array.getAddr());
			eth_length += 18;
			pdu_length += 18;
			os_checksum << ipv6_addr;
			os_tlvs << ipv6_addr;
		}
		/* extended IS reachability  tlv 22 (MT tlv 222) x n neighbors*/
		/* iterating over tlvs 22 */
		// bug in searching neighbors, inside reachability tlv
		for (const auto& item : data[i]["isis-tlv"][0].items()) {
			std::string key_str = std::string(item.key());
			if (key_str.find("reachability-tlv") != std::string::npos && key_str.find("ipv6") == std::string::npos) {
				for (const auto& subindex : data[i]["isis-tlv"][0][key_str].items()) {
					int sub_key_str = std::stoi(subindex.key());
					tlv_22 ext_reach;
					tlv_222 mt_ext_reach;
					unsigned int length{}, sub_length{};

					bool mt222 = false;

					if (!data[i]["isis-tlv"][0][key_str][sub_key_str]["isis-topology-id"][0]["data"].is_null()) {
						std::string topology_id_str = std::string(
						    data[i]["isis-tlv"][0][key_str][sub_key_str]["isis-topology-id"][0]["data"]);
						if (topology_id_str.compare("IPV4 Unicast") == 0) {
							mt_ext_reach.topology_id(0);
						}
						if (topology_id_str.compare("IPV6 Unicast") == 0) {
							mt_ext_reach.topology_id(2);
						}
						if (topology_id_str.compare("IPV4 Multicast") == 0) {
							mt_ext_reach.topology_id(3);
						}
						if (topology_id_str.compare("IPV6 Multicast") == 0) {
							mt_ext_reach.topology_id(4);
						}

						mt222 = true;
					}

					/* get reachability tlv processed */

					if (!data[i]["isis-tlv"][0][key_str][sub_key_str]["address-prefix"][0]["data"].is_null()) {
						std::string neighbor_id =
						    std::string(data[i]["isis-tlv"][0][key_str][sub_key_str]["address-prefix"][0]["data"]);
						boost::erase_all(neighbor_id, ".");
						boost::erase_all(neighbor_id, "-");
						unsigned char neighbor_id_packed[7]{0};
						for (int j = 0, k = 0; j < 7 && k < 14; ++j, k += 2) {
							neighbor_id_packed[j] =
							    static_cast<unsigned char>(std::stoi(neighbor_id.substr(k, 2), 0, 16));
						}
						ext_reach.neighbor_sysid(neighbor_id_packed);
						if (mt222) {
							mt_ext_reach.neighbor_sysid(neighbor_id_packed);
						}
						std::string metric_str =
						    std::string(data[i]["isis-tlv"][0][key_str][sub_key_str]["metric"][0]["data"]);
						unsigned int metric = std::stol(metric_str);
						unsigned char metric_array[3]{};
						metric_array[2] = (metric >> 0) & 0xFF;
						metric_array[1] = (metric >> 8) & 0xFF;
						metric_array[0] = (metric >> 16) & 0xFF;
						ext_reach.metric(metric_array);
						if (mt222) {
							mt_ext_reach.metric(metric_array);
						}
					}

					if (mt222) {
						length += 15;
						eth_length += 15;
						pdu_length += 15;

					} else {
						length += 13;
						eth_length += 13;
						pdu_length += 13;
					}

					/* subTLVs */

					subtlv22_c6 ip_interface_addr;
					subtlv22_c8 neighbor_ip_addr;
					subtlv22_c4 local_remote_ifindex;
					bool ifindex_found = false;
                                        bool ip_interface_found = false;
                                        bool neighbor_ip_found = false;
					for (const auto& subitem :
					     data[i]["isis-tlv"][0][key_str][sub_key_str]["isis-reachability-subtlv"].items()) {
						if (!data[i]["isis-tlv"][0][key_str][sub_key_str]["isis-reachability-"
												  "subtlv"][std::stoi(subitem.key())]
							 ["address"][0]["data"]
							     .is_null()) {
							std::string ip_interface_addr_str =
							    data[i]["isis-tlv"][0][key_str][sub_key_str]
								["isis-"
								 "reachability-"
								 "subtlv"][std::stoi(subitem.key())]["address"][0]["data"];
							unsigned char ip_interface_addr_array[4]{};
							size_t ip_interface_addr_pos = 0;
							std::string ip_interface_addr_delimiter = ".";
							std::string ip_interface_addr_part_1{}, ip_interface_addr_part_2{},
							    ip_interface_addr_part_3{}, ip_interface_addr_part_4{};
							ip_interface_addr_pos = ip_interface_addr_str.find(ip_interface_addr_delimiter);
							ip_interface_addr_part_1 = ip_interface_addr_str.substr(0, ip_interface_addr_pos);
							ip_interface_addr_str.erase(
							    0, ip_interface_addr_pos + ip_interface_addr_delimiter.length());
							ip_interface_addr_pos = ip_interface_addr_str.find(ip_interface_addr_delimiter);
							ip_interface_addr_part_2 = ip_interface_addr_str.substr(0, ip_interface_addr_pos);
							ip_interface_addr_str.erase(
							    0, ip_interface_addr_pos + ip_interface_addr_delimiter.length());
							ip_interface_addr_pos = ip_interface_addr_str.find(ip_interface_addr_delimiter);
							ip_interface_addr_part_3 = ip_interface_addr_str.substr(0, ip_interface_addr_pos);
							ip_interface_addr_str.erase(
							    0, ip_interface_addr_pos + ip_interface_addr_delimiter.length());
							ip_interface_addr_part_4 = ip_interface_addr_str;
							ip_interface_addr_array[0] =
							    static_cast<unsigned char>(std::stoi(ip_interface_addr_part_1, 0, 10));
							ip_interface_addr_array[1] =
							    static_cast<unsigned char>(std::stoi(ip_interface_addr_part_2, 0, 10));
							ip_interface_addr_array[2] =
							    static_cast<unsigned char>(std::stoi(ip_interface_addr_part_3, 0, 10));
							ip_interface_addr_array[3] =
							    static_cast<unsigned char>(std::stoi(ip_interface_addr_part_4, 0, 10));
							ip_interface_addr.ip_address(ip_interface_addr_array);
							length += 6;
							sub_length += 6;
							eth_length += 6;
							pdu_length += 6;
                                                        ip_interface_found = true;
						}
						if (!data[i]["isis-tlv"][0][key_str][sub_key_str]["isis-reachability-"
												  "subtlv"][std::stoi(subitem.key())]
							 ["neighbor-prefix"][0]["data"]
							     .is_null()) {
							std::string neighbor_ip_addr_str = data[i]["isis-tlv"][0][key_str][sub_key_str]
											       ["isis-"
												"reachability-"
												"subtlv"][std::stoi(subitem.key())]
											       ["neighbor-"
												"prefix"][0]["data"];
							unsigned char neighbor_ip_addr_array[4]{};
							size_t neighbor_ip_addr_pos = 0;
							std::string neighbor_ip_addr_delimiter = ".";
							std::string neighbor_ip_addr_part_1{}, neighbor_ip_addr_part_2{},
							    neighbor_ip_addr_part_3{}, neighbor_ip_addr_part_4{};
							neighbor_ip_addr_pos = neighbor_ip_addr_str.find(neighbor_ip_addr_delimiter);
							neighbor_ip_addr_part_1 = neighbor_ip_addr_str.substr(0, neighbor_ip_addr_pos);
							neighbor_ip_addr_str.erase(
							    0, neighbor_ip_addr_pos + neighbor_ip_addr_delimiter.length());
							neighbor_ip_addr_pos = neighbor_ip_addr_str.find(neighbor_ip_addr_delimiter);
							neighbor_ip_addr_part_2 = neighbor_ip_addr_str.substr(0, neighbor_ip_addr_pos);
							neighbor_ip_addr_str.erase(
							    0, neighbor_ip_addr_pos + neighbor_ip_addr_delimiter.length());
							neighbor_ip_addr_pos = neighbor_ip_addr_str.find(neighbor_ip_addr_delimiter);
							neighbor_ip_addr_part_3 = neighbor_ip_addr_str.substr(0, neighbor_ip_addr_pos);
							neighbor_ip_addr_str.erase(
							    0, neighbor_ip_addr_pos + neighbor_ip_addr_delimiter.length());
							neighbor_ip_addr_part_4 = neighbor_ip_addr_str;
							neighbor_ip_addr_array[0] =
							    static_cast<unsigned char>(std::stoi(neighbor_ip_addr_part_1, 0, 10));
							neighbor_ip_addr_array[1] =
							    static_cast<unsigned char>(std::stoi(neighbor_ip_addr_part_2, 0, 10));
							neighbor_ip_addr_array[2] =
							    static_cast<unsigned char>(std::stoi(neighbor_ip_addr_part_3, 0, 10));
							neighbor_ip_addr_array[3] =
							    static_cast<unsigned char>(std::stoi(neighbor_ip_addr_part_4, 0, 10));
							neighbor_ip_addr.ip_address(neighbor_ip_addr_array);
							length += 6;
							sub_length += 6;
							eth_length += 6;
							pdu_length += 6;
                                                        neighbor_ip_found = true;
						}
						if (!data[i]["isis-tlv"][0][key_str][sub_key_str]["isis-reachability-"
												  "subtlv"][std::stoi(subitem.key())]
							 ["local-ifindex"][0]["data"]
							     .is_null() &&
						    !data[i]["isis-tlv"][0][key_str][sub_key_str]["isis-reachability-"
												  "subtlv"][std::stoi(subitem.key())]
							 ["remote-ifindex"][0]["data"]
							     .is_null()) {
							std::string local_ifindex_str =
							    std::string(data[i]["isis-tlv"][0][key_str][sub_key_str]["isis-"
														     "reachabil"
														     "ity-"
														     "subtlv"]
									    [std::stoi(subitem.key())]["local-"
												       "ifindex"][0]["data"]);
							std::string remote_ifindex_str =
							    std::string(data[i]["isis-tlv"][0][key_str][sub_key_str]["isis-"
														     "reachabil"
														     "ity-"
														     "subtlv"]
									    [std::stoi(subitem.key())]["remote-"
												       "ifindex"][0]["data"]);
							unsigned int local_ifindex = std::stol(local_ifindex_str);
							unsigned int remote_ifindex = std::stol(remote_ifindex_str);
							unsigned char local_ifindex_array[4]{}, remote_ifindex_array[4]{};
							local_ifindex_array[3] = (local_ifindex >> 0) & 0xFF;
							local_ifindex_array[2] = (local_ifindex >> 8) & 0xFF;
							local_ifindex_array[1] = (local_ifindex >> 16) & 0xFF;
							local_ifindex_array[0] = (local_ifindex >> 24) & 0xFF;

							remote_ifindex_array[3] = (remote_ifindex >> 0) & 0xFF;
							remote_ifindex_array[2] = (remote_ifindex >> 8) & 0xFF;
							remote_ifindex_array[1] = (remote_ifindex >> 16) & 0xFF;
							remote_ifindex_array[0] = (remote_ifindex >> 24) & 0xFF;
							local_remote_ifindex.link_local_id(local_ifindex_array);
							local_remote_ifindex.link_remote_id(remote_ifindex_array);

							length += 10;
							sub_length += 10;
							eth_length += 10;
							pdu_length += 10;
							ifindex_found = true;
						}
					}
					if (mt222) {
						mt_ext_reach.subclv_length(sub_length);
						mt_ext_reach.tlv_length(length - 2);
						os_checksum << mt_ext_reach;
						os_tlvs << mt_ext_reach;
						if (sub_length) {
                                                        // need to update to match tlv 22 below
							os_checksum << ip_interface_addr << neighbor_ip_addr;
							os_tlvs << ip_interface_addr << neighbor_ip_addr;

							if (ifindex_found) {
								os_checksum << local_remote_ifindex;
								os_tlvs << local_remote_ifindex;
							}
						}
					} else {
						ext_reach.subclv_length(sub_length);
						ext_reach.tlv_length(length - 2);
						os_checksum << ext_reach;
						os_tlvs << ext_reach;
						if (sub_length) {
                                                        if (ip_interface_found) {
                                                                os_checksum << ip_interface_addr;
                                                                os_tlvs << ip_interface_addr;
                                                        }
                                                        if (neighbor_ip_found) {
                                                                os_checksum << neighbor_ip_addr;
                                                                os_tlvs << neighbor_ip_addr;
                                                        }
							if (ifindex_found) {
								os_checksum << local_remote_ifindex;
								os_tlvs << local_remote_ifindex;
							}
						}
					}
					// TE
				}  // new for
			}

			// SR
		}

		// mock peer
		if (i == 15) {
			/*tlv_222 peer_mt_ext_reach;
			  unsigned int peer_length{}, peer_sub_length{};
			  peer_mt_ext_reach.neighbor_sysid(SOURCE_ID);
			  peer_mt_ext_reach.topology_id(0);
			  peer_mt_ext_reach.metric(FAKE_METRIC);
			  peer_length += 15;
			  eth_length += 15;
			  pdu_length += 15;*/

			tlv_22 peer_ext_reach;
			unsigned int peer_length{}, peer_sub_length{};
			peer_ext_reach.neighbor_sysid(SOURCE_ID);
			peer_ext_reach.metric(FAKE_METRIC);
			peer_length += 13;
			eth_length += 13;
			pdu_length += 13;

			subtlv22_c6 peer_ip_interface_addr;
			subtlv22_c8 peer_neighbor_ip_addr;
			subtlv22_c4 peer_local_remote_ifindex;
			peer_ip_interface_addr.ip_address(FAKE_IP_ADDRESS3);
			peer_length += 6;
			peer_sub_length += 6;
			eth_length += 6;
			pdu_length += 6;
			peer_neighbor_ip_addr.ip_address(FAKE_IP_ADDRESS2);
			peer_length += 6;
			peer_sub_length += 6;
			eth_length += 6;
			pdu_length += 6;
			peer_local_remote_ifindex.link_local_id(FAKE_IF_INDEX);
			peer_local_remote_ifindex.link_remote_id(FAKE_IF_INDEX);
			peer_length += 10;
			peer_sub_length += 10;
			eth_length += 10;
			pdu_length += 10;

			/*peer_mt_ext_reach.subclv_length(peer_sub_length);
			peer_mt_ext_reach.tlv_length(peer_length - 2);*/
			peer_ext_reach.subclv_length(peer_sub_length);
			peer_ext_reach.tlv_length(peer_length - 2);

			/*os_checksum << peer_mt_ext_reach;
			os_tlvs << peer_mt_ext_reach;*/
			os_checksum << peer_ext_reach;
			os_tlvs << peer_ext_reach;
			os_checksum << peer_ip_interface_addr << peer_neighbor_ip_addr << peer_local_remote_ifindex;
			os_tlvs << peer_ip_interface_addr << peer_neighbor_ip_addr << peer_local_remote_ifindex;
		}

		/* Ext IP reachability tlv 135 (MT tlv 235) */
		for (const auto& item : data[i]["isis-tlv"][0].items()) {
			std::string key_str = std::string(item.key());
			if (key_str.find("ip-prefix-tlv") != std::string::npos) {
				if (!data[i]["isis-tlv"][0][key_str][0]["address-prefix"][0]["data"].is_null()) {
					tlv_135 ext_ip_reach;
					tlv_235 mt_ext_ip_reach;
					bool mt235 = false;
					if (!data[i]["isis-tlv"][0][key_str][0]["isis-topology-id"][0]["data"].is_null()) {
						std::string topology_id_str =
						    std::string(data[i]["isis-tlv"][0][key_str][0]["isis-topology-id"][0]["data"]);
						if (topology_id_str.compare("IPV4 Unicast") == 0) {
							mt_ext_ip_reach.topology_id(0);
						}
						if (topology_id_str.compare("IPV6 Unicast") == 0) {
							mt_ext_ip_reach.topology_id(2);
						}
						if (topology_id_str.compare("IPV4 Multicast") == 0) {
							mt_ext_ip_reach.topology_id(3);
						}
						if (topology_id_str.compare("IPV6 Multicast") == 0) {
							mt_ext_ip_reach.topology_id(4);
						}

						mt235 = true;
					}
					unsigned int length = 2;
					if (mt235) {
						eth_length += 4;
						pdu_length += 4;
						length += 2;

					} else {
						eth_length += 2;
						pdu_length += 2;
					}
					boost::asio::streambuf tlv135_temp;
					std::ostream tlv135_stream(&tlv135_temp);
					for (const auto& subitem : data[i]["isis-tlv"][0][key_str].items()) {
						if (!data[i]["isis-tlv"][0][key_str][std::stoi(subitem.key())]["address-prefix"][0]["data"]
							 .is_null()) {
							/*handling new Junos tlv 135 json representaion, tlv 135,
							    not 235 yet */
							if (length > 240) {
								std::string tlv135_intermediate_str(
								    boost::asio::buffers_begin(tlv135_temp.data()),
								    boost::asio::buffers_begin(tlv135_temp.data()) + tlv135_temp.size());
								tlv135_temp.consume(tlv135_intermediate_str.length());
								tlv_135 ext_ip_reach_intermediate;
								ext_ip_reach_intermediate.tlv_length(length - 2);
								os_checksum << ext_ip_reach_intermediate << tlv135_intermediate_str;
								os_tlvs << ext_ip_reach_intermediate << tlv135_intermediate_str;
								eth_length += 2;
								pdu_length += 2;
								length = 2;
							}
							tlv135_ipreach ipreach;
							length += 9;
							eth_length += 9;
							pdu_length += 9;

							std::string ip_metric_str = std::string(
							    data[i]["isis-tlv"][0][key_str][std::stoi(subitem.key())]["metric"][0]["data"]);
							std::unique_ptr<unsigned char[]> ip_metric_array = metric_to_bytes(ip_metric_str);
							ipreach.metric(ip_metric_array.get());

							std::string ip_prefix = std::string(
							    data[i]["isis-tlv"][0][key_str][std::stoi(subitem.key())]["address-"
														      "prefix"][0]["data"]);
							std::unique_ptr<unsigned char[]> ip_prefix_array = prefix_to_bytes(ip_prefix);
							ipreach.ipv4_prefix(ip_prefix_array.get());

							unsigned char flags = prefix_length_to_bytes(ip_prefix);
							if (std::string(data[i]["isis-tlv"][0][key_str][std::stoi(subitem.key())]["prefix-"
																  "status"]
									    [0]["data"]) == "down") {
								flags |= 1 << 7;
							}
                                                        /* adjusting length as per prefix length */
                                                        unsigned int diff = 4 - ((unsigned int)(flags & 0x3F)) / 8;
                                                        if ( ((unsigned int)(flags & 0x3F) % 8 != 0) ) {
                                                              diff--; 
                                                        } 
                                                        length -= diff;
                                                        eth_length -= diff;
                                                        pdu_length -= diff;
 
							ipreach.flags(flags);

							tlv135_stream << ipreach;
						}
					}
					// possible bug in 00
					std::string tlv135_temp_str(boost::asio::buffers_begin(tlv135_temp.data()),
								    boost::asio::buffers_begin(tlv135_temp.data()) + tlv135_temp.size());

					if (mt235) {
						mt_ext_ip_reach.tlv_length(length - 2);
						os_checksum << mt_ext_ip_reach << tlv135_temp_str;
						os_tlvs << mt_ext_ip_reach << tlv135_temp_str;

					} else {
						ext_ip_reach.tlv_length(length - 2);
						os_checksum << ext_ip_reach << tlv135_temp_str;
						os_tlvs << ext_ip_reach << tlv135_temp_str;
					}
				}
			}
		}
		// mock peer
		if (i == 15) {
			tlv_135 peer_ext_ip_reach;

			unsigned int peer_length = 2;
			eth_length += 2;
			pdu_length += 2;

			tlv135_ipreach peer_ipreach;
			peer_length += 9;
			eth_length += 9;
			pdu_length += 9;

			peer_ipreach.ipv4_prefix(FAKE_IP_ADDRESS2);
			peer_ipreach.flags(0x1F);
			peer_ipreach.metric(FAKE_IP_METRIC);
			peer_ext_ip_reach.tlv_length(peer_length - 2);
			os_checksum << peer_ext_ip_reach << peer_ipreach;
			os_tlvs << peer_ext_ip_reach << peer_ipreach;
		}

		/* router capability tlv 242 */
		if (!data[i]["isis-tlv"][0]["rtr-capability-tlv"][0]["router-id"][0]["data"].is_null()) {
			tlv_242 rtr_capability;
			eth_length += 7;
			pdu_length += 7;

			std::string rtr_id_str = std::string(data[i]["isis-tlv"][0]["rtr-capability-tlv"][0]["router-id"][0]["data"]);
			std::unique_ptr<unsigned char[]> rtr_id = prefix_to_bytes(rtr_id_str);
			rtr_capability.router_id(rtr_id.get());
			std::string rtr_flags_str =
			    std::string(data[i]["isis-tlv"][0]["rtr-capability-tlv"][0]["rtr-cap-flags"][0]["data"]);
			rtr_flags_str.erase(0, 2);
			rtr_capability.flags(static_cast<unsigned char>(std::stoi(rtr_flags_str, 0, 16)));
			os_checksum << rtr_capability;
			os_tlvs << rtr_capability;
		}
		if (!data[i]["isis-prefix"][0]["isis-topology-id"][0]["data"].is_null()) {
			std::cout << "Multi-topology:" << std::endl;
			std::vector<unsigned int> status(4, 0);
			for (const auto& subitem : data[i]["isis-prefix"].items()) {
				if (!data[i]["isis-prefix"][std::stoi(subitem.key())]["isis-topology-id"][0]["data"].is_null()) {
					std::string topology_string =
					    data[i]["isis-prefix"][std::stoi(subitem.key())]["isis-topology-id"][0]["data"];
					if (!status[0] && topology_string.compare("IPV4 Unicast") == 0) {
						status[0] = 1;
					}
					if (!status[1] && topology_string.compare("IPV6 Unicast") == 0) {
						status[1] = 1;
					}
					if (!status[2] && topology_string.compare("IPV4 Multicast") == 0) {
						status[2] = 1;
					}
					if (!status[3] && topology_string.compare("IPV6 Multicast") == 0) {
						status[3] = 1;
					}
				}
			}
			unsigned int mt_length{};
			boost::asio::streambuf mt_temp;
			std::ostream mt_stream(&mt_temp);
			if (status[0]) {
				std::cout << "IPv4 unicast" << std::endl;
				mt_length++;
				tlv_229_topology ipv4_unicast;
				ipv4_unicast.topology(0);
				mt_stream << ipv4_unicast;
			};
			if (status[1]) {
				std::cout << "IPv6 unicast" << std::endl;
				mt_length++;
				tlv_229_topology ipv6_unicast;
				ipv6_unicast.topology(2);
				mt_stream << ipv6_unicast;
			};
			if (status[2]) {
				std::cout << "IPv4 multicast" << std::endl;
				mt_length++;
				tlv_229_topology ipv4_multicast;
				ipv4_multicast.topology(3);
				mt_stream << ipv4_multicast;
			};
			if (status[3]) {
				std::cout << "IPv6 multicast" << std::endl;
				mt_length++;
				tlv_229_topology ipv6_multicast;
				ipv6_multicast.topology(4);
				mt_stream << ipv6_multicast;
			};
			std::string mt_str(boost::asio::buffers_begin(mt_temp.data()),
					   boost::asio::buffers_begin(mt_temp.data()) + mt_temp.size());
			tlv_229 multitopology;
			multitopology.tlv_length(2 * mt_length);
			os_checksum << multitopology << mt_str;
			os_tlvs << multitopology << mt_str;
			our_mt_str = mt_str;
			our_mt_length = mt_length;
			eth_length += 2 * mt_length + 2;
			pdu_length += 2 * mt_length + 2;
		}
		// more TLVs go here

		// adding mock peer

		/*if (i == 0) {

			tlv_222 peer_mt_ext_reach;
			unsigned int peer_length{}, peer_sub_length{};
			peer_mt_ext_reach.neighbor_sysid(SOURCE_ID);
			peer_mt_ext_reach.topology_id(0);
			peer_mt_ext_reach.metric(FAKE_METRIC);
			peer_length += 15;
			eth_length += 15;
			pdu_length += 15;

			tlv_22 peer_ext_reach;
			unsigned int peer_length{}, peer_sub_length{};
			peer_ext_reach.neighbor_sysid(SOURCE_ID);
			peer_ext_reach.metric(FAKE_METRIC);
			peer_length += 13;
			eth_length += 13;
			pdu_length += 13;


			subtlv22_c6 peer_ip_interface_addr;
			subtlv22_c8 peer_neighbor_ip_addr;
			subtlv22_c4 peer_local_remote_ifindex;
			peer_ip_interface_addr.ip_address(FAKE_IP_ADDRESS3);
			peer_length += 6;
			peer_sub_length += 6;
			eth_length += 6;
			pdu_length += 6;
			peer_neighbor_ip_addr.ip_address(FAKE_IP_ADDRESS2);
			peer_length += 6;
			peer_sub_length += 6;
			eth_length += 6;
			pdu_length += 6;
			peer_local_remote_ifindex.link_local_id(FAKE_IF_INDEX);
			peer_local_remote_ifindex.link_remote_id(FAKE_IF_INDEX);
			peer_length += 10;
			peer_sub_length += 10;
			eth_length += 10;
			pdu_length += 10;
			*/
		/*peer_mt_ext_reach.subclv_length(peer_sub_length);
		peer_mt_ext_reach.tlv_length(peer_length - 2);*/
		/*peer_ext_reach.subclv_length(peer_sub_length);
		peer_ext_reach.tlv_length(peer_length - 2);*/

		/*os_checksum << peer_mt_ext_reach;
		os_tlvs << peer_mt_ext_reach;*/
		/*os_checksum << peer_ext_reach;
		os_tlvs << peer_ext_reach;
		os_checksum << peer_ip_interface_addr
			    << peer_neighbor_ip_addr
			    << peer_local_remote_ifindex;
		os_tlvs << peer_ip_interface_addr
			<< peer_neighbor_ip_addr
			<< peer_local_remote_ifindex;

		tlv_135 peer_ext_ip_reach;

		peer_length = 2;
		eth_length += 2;
		pdu_length += 2;

		tlv135_ipreach peer_ipreach;
		peer_length += 9;
		eth_length += 9;
		pdu_length += 9;

		peer_ipreach.ipv4_prefix(FAKE_IP_ADDRESS2);
		peer_ipreach.flags(0x1F);
		peer_ipreach.metric(FAKE_IP_METRIC);
		peer_ext_ip_reach.tlv_length(peer_length - 2);
		os_checksum << peer_ext_ip_reach << peer_ipreach;
		os_tlvs << peer_ext_ip_reach << peer_ipreach;

	}  */
		// end of mock peer

		eth.length(eth_length);
		lsp_header.pdu_length(htons(pdu_length));
		/* calculating checksum */
		std::string checksum_str(boost::asio::buffers_begin(checksum_pdu.data()),
					 boost::asio::buffers_begin(checksum_pdu.data()) + checksum_pdu.size());
		std::unique_ptr<unsigned char[]> checksum_temp_ptr(new unsigned char[checksum_str.size()]{});
		unsigned char* checksum_temp = checksum_temp_ptr.get();

		std::memcpy(checksum_temp, checksum_str.c_str(), checksum_str.size());
		unsigned short checksum = htons(fletcher_checksum(checksum_temp + 12, checksum_str.size() - 12, 12));
		lsp_header.checksum(htons(checksum));

		/* constructing final packet */
		std::string tlvs_str(boost::asio::buffers_begin(tlvs.data()), boost::asio::buffers_begin(tlvs.data()) + tlvs.size());
		os << eth << isis << lsp_header << tlvs_str;
		std::string packet_str(boost::asio::buffers_begin(packet.data()),
				       boost::asio::buffers_begin(packet.data()) + packet.size());

		/* saving packet to db */
		lsdb.insert(std::pair<std::string, std::string>(keys[i], packet_str));

		/* create and save own LSP */
		if (i == 15) {
			unsigned int our_eth_length{}, our_pdu_length{};

			boost::asio::streambuf our_checksum_pdu;
			std::ostream our_os_checksum(&our_checksum_pdu);
			boost::asio::streambuf our_tlvs;
			std::ostream our_os_tlvs(&our_tlvs);
			boost::asio::streambuf our_packet;
			std::ostream our_os(&our_packet);

			eth_header our_eth;
			isis_header our_isis;
			isis_lsp_header our_lsp_header;
			our_isis.pdu_type(l2_lsp);
			our_isis.length_indicator(27);
			our_lsp_header.remaining_lifetime(htons(1100));
			our_lsp_header.sequence_num(OUR_LSP_SEQ);
			our_lsp_header.lsp_id(OUR_LSP_ID);
			our_eth_length += (sizeof(our_isis) + sizeof(our_lsp_header) + 3);
			our_pdu_length += (sizeof(our_isis) + sizeof(our_lsp_header));
			our_os_checksum << our_isis << our_lsp_header;
			/* TLVs */
			tlv_137 our_hostname;
			our_hostname.tlv_length(11);
			our_hostname.tlv_hostname(OUR_HOSTNAME, 11);
			our_eth_length += 13;
			our_pdu_length += 13;
			our_os_checksum << our_hostname;
			our_os_tlvs << our_hostname;

			tlv_14 our_buffer_size;
			our_buffer_size.set_size(htons(1492));
			our_eth_length += 4;
			our_pdu_length += 4;
			our_os_checksum << our_buffer_size;
			our_os_tlvs << our_buffer_size;

			tlv_129_ext our_protocols_supported;
			our_protocols_supported.nlpid(0xcc, 0);
			our_protocols_supported.nlpid(0x8e, 1);
			// our_protocols_supported.nlpid(0x81, 2);
			our_protocols_supported.tlv_length(2);
			our_eth_length += 4;
			our_pdu_length += 4;
			our_os_checksum << our_protocols_supported;
			our_os_tlvs << our_protocols_supported;

			tlv_1 our_area;
			our_eth_length += 6;
			our_pdu_length += 6;
			our_os_checksum << our_area;
			our_os_tlvs << our_area;

			tlv_134 our_ip_interface;
			our_eth_length += 6;
			our_pdu_length += 6;
			our_os_checksum << our_ip_interface;
			our_os_tlvs << our_ip_interface;

			// tlv 22(222),135(235)

			/*tlv_222 our_mt_ext_reach;
			unsigned int our_length{}, our_sub_length{};
			our_mt_ext_reach.topology_id(0);
			our_mt_ext_reach.neighbor_sysid(topology_neighbor_id);
			our_mt_ext_reach.metric(FAKE_METRIC);
			our_length += 15;
			our_eth_length += 15;
			our_pdu_length += 15;*/

			tlv_22 our_ext_reach;
			unsigned int our_length{}, our_sub_length{};
			our_ext_reach.neighbor_sysid(topology_neighbor_id);
			our_ext_reach.metric(FAKE_METRIC);
			our_length += 13;
			our_eth_length += 13;
			our_pdu_length += 13;

			subtlv22_c6 our_ip_interface_addr;
			subtlv22_c8 our_neighbor_ip_addr;
			subtlv22_c4 our_local_remote_ifindex;
			our_ip_interface_addr.ip_address(FAKE_IP_ADDRESS2);
			our_length += 6;
			our_sub_length += 6;
			our_eth_length += 6;
			our_pdu_length += 6;
			our_neighbor_ip_addr.ip_address(FAKE_IP_ADDRESS3);
			our_length += 6;
			our_sub_length += 6;
			our_eth_length += 6;
			our_pdu_length += 6;
			our_local_remote_ifindex.link_local_id(FAKE_IF_INDEX);
			our_local_remote_ifindex.link_remote_id(FAKE_IF_INDEX);
			our_length += 10;
			our_sub_length += 10;
			our_eth_length += 10;
			our_pdu_length += 10;
			/*our_mt_ext_reach.tlv_length(our_length - 2);
			our_mt_ext_reach.subclv_length(our_sub_length);*/
			our_ext_reach.tlv_length(our_length - 2);
			our_ext_reach.subclv_length(our_sub_length);
			/*our_os_checksum << our_mt_ext_reach;
			our_os_tlvs << our_mt_ext_reach;*/
			our_os_checksum << our_ext_reach;
			our_os_tlvs << our_ext_reach;

			our_os_checksum << our_ip_interface_addr << our_neighbor_ip_addr << our_local_remote_ifindex;
			our_os_tlvs << our_ip_interface_addr << our_neighbor_ip_addr << our_local_remote_ifindex;

			tlv_22 our_ext_reach2;
			unsigned int our_length2{}, our_sub_length2{};
			our_ext_reach2.neighbor_sysid(DUT_SYS_ID);
			our_ext_reach2.metric(FAKE_METRIC);
			our_length2 += 13;
			our_eth_length += 13;
			our_pdu_length += 13;
			/*tlv_222 our_mt_ext_reach2;
			unsigned int our_length2{}, our_sub_length2{};
			our_mt_ext_reach2.topology_id(0);
			our_mt_ext_reach2.neighbor_sysid(DUT_SYS_ID);
			our_mt_ext_reach2.metric(FAKE_METRIC);
			our_length2 += 15;
			our_eth_length += 15;
			our_pdu_length += 15;*/

			subtlv22_c6 our_ip_interface_addr2;
			subtlv22_c8 our_neighbor_ip_addr2;
			subtlv22_c4 our_local_remote_ifindex2;
			our_ip_interface_addr2.ip_address(OUR_IP_ADDRESS);
			our_length2 += 6;
			our_sub_length2 += 6;
			our_eth_length += 6;
			our_pdu_length += 6;
			our_neighbor_ip_addr2.ip_address(DUT_IP_ADDRESS);
			our_length2 += 6;
			our_sub_length2 += 6;
			our_eth_length += 6;
			our_pdu_length += 6;
			our_local_remote_ifindex2.link_local_id(FAKE_IF_INDEX2);
			our_local_remote_ifindex2.link_remote_id(FAKE_IF_INDEX2);
			our_length2 += 10;
			our_sub_length2 += 10;
			our_eth_length += 10;
			our_pdu_length += 10;
			/*our_mt_ext_reach2.tlv_length(our_length2 - 2);
			our_mt_ext_reach2.subclv_length(our_sub_length2);*/
			our_ext_reach2.tlv_length(our_length2 - 2);
			our_ext_reach2.subclv_length(our_sub_length2);
			/*our_os_checksum << our_mt_ext_reach2;
			our_os_tlvs << our_mt_ext_reach2;*/
			our_os_checksum << our_ext_reach2;
			our_os_tlvs << our_ext_reach2;

			our_os_checksum << our_ip_interface_addr2 << our_neighbor_ip_addr2 << our_local_remote_ifindex2;
			our_os_tlvs << our_ip_interface_addr2 << our_neighbor_ip_addr2 << our_local_remote_ifindex2;

			tlv_135 our_ext_ip_reach;

			our_length = 2;
			our_eth_length += 2;
			our_pdu_length += 2;

			tlv135_ipreach our_ipreach1, our_ipreach2, our_ipreach3;
			our_length += 27;
			our_eth_length += 27;
			our_pdu_length += 27;

			our_ipreach1.ipv4_prefix(DUT_IP_ADDRESS);
			our_ipreach2.ipv4_prefix(FAKE_IP_ADDRESS2);
			our_ipreach3.ipv4_prefix(OUR_IP_ADDRESS);
			our_ipreach1.flags(0x1F);
			our_ipreach2.flags(0x1F);
			our_ipreach3.flags(0x20);
			our_ipreach1.metric(FAKE_IP_METRIC);
			our_ipreach2.metric(FAKE_IP_METRIC);
			our_ipreach3.metric(FAKE_IP_METRIC);
			our_ext_ip_reach.tlv_length(our_length - 2);
			our_os_checksum << our_ext_ip_reach << our_ipreach1 << our_ipreach2 << our_ipreach3;
			our_os_tlvs << our_ext_ip_reach << our_ipreach1 << our_ipreach2 << our_ipreach3;

			tlv_242 our_rtr_capability;
			our_eth_length += 7;
			our_pdu_length += 7;
			our_rtr_capability.router_id(OUR_IP_ADDRESS);
			our_rtr_capability.flags(0);

			our_os_checksum << our_rtr_capability;
			our_os_tlvs << our_rtr_capability;

			tlv_229 our_multitopology;
			our_multitopology.tlv_length(2 * our_mt_length);
			our_os_checksum << our_multitopology << our_mt_str;
			our_os_tlvs << our_multitopology << our_mt_str;
			our_eth_length += 2 * our_mt_length + 2;
			our_pdu_length += 2 * our_mt_length + 2;

			our_eth.length(our_eth_length);
			our_lsp_header.pdu_length(htons(our_pdu_length));
			std::string our_checksum_str(boost::asio::buffers_begin(our_checksum_pdu.data()),
						     boost::asio::buffers_begin(our_checksum_pdu.data()) + our_checksum_pdu.size());
			std::unique_ptr<unsigned char[]> our_checksum_temp_ptr(new unsigned char[our_checksum_str.size()]{});
			unsigned char* our_checksum_temp = our_checksum_temp_ptr.get();

			std::memcpy(our_checksum_temp, our_checksum_str.c_str(), our_checksum_str.size());
			unsigned short our_checksum = htons(fletcher_checksum(our_checksum_temp + 12, our_checksum_str.size() - 12, 12));
			our_lsp_header.checksum(htons(our_checksum));

			std::string our_tlvs_str(boost::asio::buffers_begin(our_tlvs.data()),
						 boost::asio::buffers_begin(our_tlvs.data()) + our_tlvs.size());
			our_os << our_eth << our_isis << our_lsp_header << our_tlvs_str;

			std::string our_packet_str(boost::asio::buffers_begin(our_packet.data()),
						   boost::asio::buffers_begin(our_packet.data()) + our_packet.size());

			lsdb.insert(std::pair<std::string, std::string>("0001.0000.0001.00-00", our_packet_str));
		}
	}
	f.close();
}
