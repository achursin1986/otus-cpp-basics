#include <unistd.h>
#include <malloc.h>

#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <array>

#include "fsm.hpp"
#include "get_version.h"
#include "io.hpp"
#include "parser.hpp"
#include "tinyfsm.hpp"


namespace bpo = boost::program_options;


std::mutex mtx;
std::condition_variable cv;
bool Flood = false;
std::string json_file{}, ifname{};

int main(int argc, char* argv[]) {
        try {
           bpo::options_description desc("options");

                desc.add_options()
                    ("help", "show help")
                    ("ifname", bpo::value<std::string>(&ifname)->required(), "interface name, required")
                    ("json-file", bpo::value<std::string>(&json_file)->required(), "json input file, required")
                    ("ipaddress", bpo::value<std::string>(), "mocker ip address, mask /31")
                    ("dut_ipaddress", bpo::value<std::string>(), "dut ip address, mask /31")
                    ("mock_ipaddress1", bpo::value<std::string>(), "used to mock adj, mask /31")
                    ("mock_ipaddress2", bpo::value<std::string>(), "used to mock adj, mask /31")
                    ("sysid", bpo::value<std::string>(), "sysid, for example 0001.0001.0001")
                    ("dut_sysid", bpo::value<std::string>(), "dut sysid, for example 0001.0001.0001")
                    ("hostname", bpo::value<std::string>(), "hostname mocker shows in isis, 11 symbols max")
                    ("version", "show version") 
                ;
              

               bpo::variables_map vm;
               bpo::store(bpo::parse_command_line(argc, argv, desc), vm);

                if (vm.count("help")) {
                        std::cout << desc << std::endl;
                        return 1;
                }

                 if (vm.count("version")) {

                        std::cout << "version: " << "0."<< version() << "."<< patch_version() << std::endl;
                        return 1;
                }

                bpo::notify(vm);
               
                if (vm.count("ipaddress") && vm.count("dut_ipaddress")) {
                        setParam<address>(OUR_IP_ADDRESS, vm["ipaddress"].as<std::string>());                    
                        setParam<address>(DUT_IP_ADDRESS, vm["dut_ipaddress"].as<std::string>()); 
                }

                if (vm.count("mock_ipaddress1") && vm.count("mock_ipaddress2")) {
                        setParam<address>(FAKE_IP_ADDRESS2, vm["mock_ipaddress1"].as<std::string>());
                        setParam<address>(FAKE_IP_ADDRESS3, vm["mock_ipaddress2"].as<std::string>());
                }

                if (vm.count("sysid") && vm.count("dut_sysid")) {
                        setParam<sysid>(SYS_ID, vm["sysid"].as<std::string>());
                        setParam<sysid>(SOURCE_ID, vm["sysid"].as<std::string>());
                        setParam<sysid>(OUR_LSP_ID, vm["sysid"].as<std::string>());
                        setParam<sysid>(DUT_SYS_ID, vm["dut_sysid"].as<std::string>());
                }

                if (vm.count("hostname")) {
                        setParam<hostname>(OUR_HOSTNAME, vm["hostname"].as<std::string>());
                }
                

        } catch (std::exception& e) {
                std::cerr << "Exception: " <<  e.what() << std::endl;
                std::cerr << "Use --help to get options list" << std::endl;
                return 1;
        }



	std::cout << R"(
  ___ ____ ___ ____        __  __  ___   ____ _  _______ ____  
 |_ _/ ___|_ _/ ___|      |  \/  |/ _ \ / ___| |/ / ____|  _ \
  | |\___ \| |\___ \ _____| |\/| | | | | |   | ' /|  _| | |_) |
  | | ___) | | ___) |_____| |  | | |_| | |___| . \| |___|  _ < 
 |___|____/___|____/      |_|  |_|\___/ \____|_|\_\_____|_| \_\)"
		  << std::endl;
        std::cout << " version: " << "0."<< version() << "." << patch_version() << std::endl;
	std::unordered_map<std::string, std::string> LSDB;

	try {
		parse(LSDB, json_file);
                malloc_trim(0);
		boost::asio::io_context io_context;
		IO s(io_context, &ifname[0]);
		fsm_list::start();

		boost::asio::io_context timer;
		boost::asio::deadline_timer hold_timer(timer);
		hold_timer.expires_from_now(boost::posix_time::seconds(30));
		hold_timer.async_wait([&](boost::system::error_code ec) {
			if (!ec) {
				TIMEOUT to;
				send_event(to);
			}
		});
		std::thread timer_th([&] {
			while (1) {
				if (timer.stopped()) {
					timer.reset();
				};
				timer.run();
			}
		});

		std::thread flooder_th([&] {
			while (1) {
                                        std::unique_lock<std::mutex> lock(mtx);
                                        cv.wait( lock, []() { return Flood; } );
					std::cout << std::endl
						  << "flooding LSPs to DUT"
						  << std::endl;

					for (auto const& [key, value] : LSDB) {
						boost::asio::streambuf sbuf;
						std::iostream os(&sbuf);
						sbuf.prepare(value.size());
						os << value;
						s.do_send(&sbuf);
                                                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                                                incrSequenceNum(LSDB,key,value);
					}
					std::cout << "sleeping" << std::endl;
                                        Flood = false;
			}
		});
                /* flood dispatch */
                std::thread dispatcher_th([&] {
                                 bool Previous = false;
                                 unsigned int count{}; 
                                 while(1) {
                                    if (ISIS_ADJ::is_in_state<Up>() && !Previous) { 
                                          std::lock_guard<std::mutex> lock(mtx); 
                                          Flood = true; 
                                          cv.notify_one();
                                          count = 0;
                                   }
                                   if (ISIS_ADJ::is_in_state<Up>() && Previous) { 
                                          count++;
                                          if (count > 190 ) {
                                                  std::lock_guard<std::mutex> lock(mtx);
                                                  Flood = true;
                                                  cv.notify_one(); 
                                                  count = 0; 
                                          }
                                   }
                                   
                                   Previous = ISIS_ADJ::is_in_state<Up>();
                                   std::this_thread::sleep_for(std::chrono::seconds(5));
                                   
                            }              
               });

		/* main loop */
		while (1) {
			s.do_receive();
			io_context.run();
			hold_timer.expires_from_now(
			    boost::posix_time::seconds(30));
			hold_timer.async_wait(
			    [&](boost::system::error_code ec) {
				    if (!ec) {
					    TIMEOUT to;
					    send_event(to);  
				    }
			    });
			ISIS_PKT packet;
			std::size_t bytes_copied = buffer_copy(
			    packet.data_.prepare(s.get_data()->size()),
			    s.get_data()->data());
			packet.data_.commit(bytes_copied);
			s.get_data()->consume(bytes_copied);
			packet.endpoint = &s;
			send_event(packet);
			io_context.reset();
		}
		timer_th.join();
		flooder_th.join();
                dispatcher_th.join();

	} catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
	}

	return 0;
}
