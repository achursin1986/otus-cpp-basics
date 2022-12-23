#include <boost/asio.hpp>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

#include "fsm.hpp"
#include "io.hpp"
#include "parser.hpp"
#include "tinyfsm.hpp"

int main(int argc, char* argv[]) {
	if (argc < 3) {
		std::cerr << "Usage: repl [interface] [json database file]\n";
		return EXIT_FAILURE;
	}

	std::cout << "ISIS database replicator" << std::endl;

	std::map<std::string, std::string> LSDB;

	try {
		parse(LSDB, std::string(argv[2]));
		boost::asio::io_context io_context;
		IO s(io_context, argv[1]);
		fsm_list::start();

		boost::asio::io_context timer;
		boost::asio::deadline_timer hold_timer(timer);
		hold_timer.expires_from_now(boost::posix_time::seconds(30));
		hold_timer.async_wait([&](boost::system::error_code ec) {
			if (!ec) {
				TIMEOUT to; send_event(to);
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

		/* flood loop depending on SM state */
		std::thread flooder_th([&] {
			while (1) {
				if (ISIS_ADJ::is_in_state<Up>()) {
					std::cout << "flooding LSPs >> DUT"
						  << std::endl;
					for (auto const& [key, value] : LSDB) {
						boost::asio::streambuf sbuf;
						std::iostream os(&sbuf);
						sbuf.prepare(value.size());
						os << value;
						s.do_send(&sbuf);
						std::string new_value = value;
						std::string seq_num_str =
						    value.substr(37, 4);
						unsigned int seq_num =
						    (unsigned int)(seq_num_str
								       [3]) +
						    (unsigned int)(16 *
								   seq_num_str
								       [2]) +
						    (unsigned int)(256 *
								   seq_num_str
								       [1]) +
						    (unsigned int)(4096 *
								   seq_num_str
								       [0]);
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
						/* quick a dirty, maybe use
						 * c_str */
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

					std::this_thread::sleep_for(
					    std::chrono::seconds(120));
				}
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
					    TIMEOUT to; send_event(to);
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

	} catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << "\n";
	}

	return 0;
}
