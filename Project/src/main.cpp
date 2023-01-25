#include <unistd.h>
#include <malloc.h>

#include <boost/asio.hpp>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <mutex>
#include <condition_variable>

#include "fsm.hpp"
#include "get_version.h"
#include "io.hpp"
#include "parser.hpp"
#include "tinyfsm.hpp"


std::mutex mtx;
std::condition_variable cv;
bool Flood = false;

int main(int argc, char* argv[]) {
	if (argc < 3) {
		std::cerr << "Usage: isis-mocker [interface] [json database file]\n";
		return EXIT_FAILURE;
	}

	std::cout << R"(
  ___ ____ ___ ____        __  __  ___   ____ _  _______ ____  
 |_ _/ ___|_ _/ ___|      |  \/  |/ _ \ / ___| |/ / ____|  _ \
  | |\___ \| |\___ \ _____| |\/| | | | | |   | ' /|  _| | |_) |
  | | ___) | | ___) |_____| |  | | |_| | |___| . \| |___|  _ < 
 |___|____/___|____/      |_|  |_|\___/ \____|_|\_\_____|_| \_\)"
		  << std::endl;
	std::cout << " version: "
		  << "0.0." << version() << std::endl;

	std::map<std::string, std::string> LSDB;

	try {
		parse(LSDB, std::string(argv[2]));
                malloc_trim(0);
		boost::asio::io_context io_context;
		IO s(io_context, argv[1]);
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
						std::string new_value = value;
						std::string seq_num_str =
						    value.substr(37, 4);

						unsigned int seq_num = static_cast<unsigned int>(static_cast<unsigned char>(seq_num_str[0])) << 24 | 
                                                                       static_cast<unsigned int>(static_cast<unsigned char>(seq_num_str[1])) << 16 |
                                                                       static_cast<unsigned int>(static_cast<unsigned char>(seq_num_str[2])) << 8  |
                                                                       static_cast<unsigned int>(static_cast<unsigned char>(seq_num_str[3]));
						seq_num++;
						new_value[40] =
						    seq_num & 0x000000ff;
						new_value[39] =
						    (seq_num & 0x0000ff00) >> 8;
						new_value[38] =
						    (seq_num & 0x00ff0000) >>
						    16;
						new_value[37] =
						    (seq_num & 0xff000000) >>
						    24;
						std::unique_ptr<unsigned char[]>
						checksum_temp_ptr(
						    new unsigned char
							[new_value.size() -
							 17]{});
						unsigned char* checksum_temp =
						    checksum_temp_ptr.get();
						new_value[41] = 0;
						new_value[42] = 0;
						std::memcpy(
						    checksum_temp,
						    new_value.c_str() + 17,
						    new_value.size() - 17);

						unsigned short checksum =
						    htons(fletcher_checksum(
							checksum_temp + 12,
							new_value.size() - 29,
							12));
						new_value[41] =
						    static_cast<unsigned char>(
							checksum >> 8);
						new_value[42] =
						    static_cast<unsigned char>(
							checksum & 0xFF);
						LSDB[key] = new_value;
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
		std::cerr << "Exception: " << e.what() << "\n";
	}

	return 0;
}
