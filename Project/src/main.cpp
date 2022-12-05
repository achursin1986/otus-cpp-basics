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
				TIMEOUT to, send_event(to);
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
					    TIMEOUT to, send_event(to);
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
