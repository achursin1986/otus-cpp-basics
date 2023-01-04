#pragma once
#include <boost/asio.hpp>
#include <iostream>
#include <istream>
#include <ostream>

#include "io.hpp"
#include "isis.hpp"
#include "tinyfsm.hpp"
#include "utils.hpp"

struct PKT : tinyfsm::Event {
	boost::asio::streambuf data_;
	IO* endpoint;
};

struct TIMEOUT : tinyfsm::Event {};

struct ISIS_PKT : PKT {};

class ISIS_ADJ : public tinyfsm::Fsm<ISIS_ADJ> {
    public:
	virtual void react(ISIS_PKT&){};
	virtual void react(TIMEOUT&){};
	virtual void entry(){};
	virtual void exit(){};
};

class Down : public ISIS_ADJ {
	void entry() override {
		std::cout << "ISIS Adj is : Down" << std::endl;
	};
	void react(ISIS_PKT& e) override;
};

class Init : public ISIS_ADJ {
	void entry() override {
		std::cout << "ISIS Adj is : Init" << std::endl;
	};
	void react(ISIS_PKT& e) override;
};

class Up : public ISIS_ADJ {
	void entry() override { std::cout << "ISIS Adj is : Up" << std::endl; };
	void react(ISIS_PKT& e) override;
	void react(TIMEOUT& e) override;
};

void Down::react(ISIS_PKT& e) {
        std::istream packet_r(&e.data_);
	eth_header hdr_0_r;
	isis_header hdr_1_r;
	isis_hello_header hdr_2_r;
	tlv_240 payload_0_r;
	packet_r >> hdr_0_r >> hdr_1_r >> hdr_2_r >> payload_0_r;

	/*  send hello with Init filling neighbor data */
	if ((hdr_1_r.pdu_type() == p2p_hello) &&
	    (payload_0_r.adjacency_state() == down)) {
#ifdef DEBUG
		std::cout << "Got hello packet in Down state" << std::endl;
#endif
		boost::asio::streambuf packet;
		std::ostream os(&packet);
		eth_header hdr_0;
		isis_header hdr_1;
		isis_hello_header hdr_2;
		tlv_240_ext payload_0;
		tlv_129 payload_1;
		tlv_132 payload_2;
		tlv_1 payload_3;

		payload_0.neighbor_sysid(hdr_2_r.system_id());
		payload_0.ext_neighbor_local_circuit_id(
		    payload_0_r.ext_local_circuit_id());
		hdr_1.pdu_type(p2p_hello);
		hdr_1.length_indicator(20);
		/* length accounts LLC part */
		hdr_0.length(sizeof(hdr_1) + sizeof(hdr_2) + sizeof(payload_0) +
			     sizeof(payload_1) + sizeof(payload_2) +
			     sizeof(payload_3) + 2);
		hdr_2.pdu_length(sizeof(hdr_1) + sizeof(hdr_2) +
				 sizeof(payload_0) + sizeof(payload_1) +
				 sizeof(payload_2) + sizeof(payload_3));

		os << hdr_0 << hdr_1 << hdr_2 << payload_0 << payload_1
		   << payload_2 << payload_3;

		e.endpoint->do_send(&packet);
		transit<Init>();
	}
}

void Init::react(ISIS_PKT& e) {
        std::istream packet_r(&e.data_);
	eth_header hdr_0_r;
	isis_header hdr_1_r;
	isis_hello_header hdr_2_r;
	tlv_240_ext payload_0_r;
	packet_r >> hdr_0_r >> hdr_1_r >> hdr_2_r >> payload_0_r;
	/* check if we are known by him */
	if ((hdr_1_r.pdu_type() == p2p_hello) &&
	    (payload_0_r.adjacency_state() == init) &&
	    (std::equal(SYS_ID, SYS_ID + sizeof(SYS_ID),
			payload_0_r.neighbor_sysid()))) {
#ifdef DEBUG
		std::cout << "Got hello packet in Init" << std::endl;
#endif
		boost::asio::streambuf packet;
		std::ostream os(&packet);
		eth_header hdr_0;
		isis_header hdr_1;
		isis_hello_header hdr_2;
		tlv_240_ext payload_0;
		tlv_129 payload_1;
		tlv_1 payload_2;
		tlv_132 payload_3;
		/* flip to up */
		payload_0.adjacency_state(up);
		payload_0.neighbor_sysid(hdr_2_r.system_id());
		payload_0.ext_neighbor_local_circuit_id(
		    payload_0_r.ext_local_circuit_id());
		hdr_1.pdu_type(p2p_hello);
		hdr_1.length_indicator(20);
		hdr_0.length(sizeof(hdr_1) + sizeof(hdr_2) + sizeof(payload_0) +
			     sizeof(payload_1) + sizeof(payload_2) +
			     sizeof(payload_3) + 2);
		hdr_2.pdu_length(sizeof(hdr_1) + sizeof(hdr_2) +
				 sizeof(payload_0) + sizeof(payload_1) +
				 sizeof(payload_2) + sizeof(payload_3));

		os << hdr_0 << hdr_1 << hdr_2 << payload_0 << payload_1
		   << payload_2 << payload_3;

		e.endpoint->do_send(&packet);

		transit<Up>();
	} else {
		transit<Down>();
	}
}

void Up::react(ISIS_PKT& e) {
        std::istream packet_r(&e.data_);
	eth_header hdr_0_r;
	isis_header hdr_1_r;
	isis_hello_header hdr_2_r;
	tlv_240_ext payload_0_r;
	packet_r >> hdr_0_r >> hdr_1_r >> hdr_2_r >> payload_0_r;

	/* CSNP and CSNP support from neighbor is not required for now, will be
	 * added later */

	if (hdr_1_r.pdu_type() == p2p_hello && payload_0_r.adjacency_state() == up) {
#ifdef DEBUG
		std::cout << "Got hello packet in Up" << std::endl;
#endif
		boost::asio::streambuf packet;
		std::ostream os(&packet);
		eth_header hdr_0;
		isis_header hdr_1;
		isis_hello_header hdr_2;
		tlv_240_ext payload_0;
		tlv_129 payload_1;
		tlv_1 payload_2;
		tlv_132 payload_3;
		/* flip to up */
		payload_0.adjacency_state(up);
		payload_0.neighbor_sysid(hdr_2_r.system_id());
		payload_0.ext_neighbor_local_circuit_id(
		    payload_0_r.ext_local_circuit_id());
		hdr_1.pdu_type(p2p_hello);
		hdr_1.length_indicator(20);
		hdr_0.length(sizeof(hdr_1) + sizeof(hdr_2) + sizeof(payload_0) +
			     sizeof(payload_1) + sizeof(payload_2) +
			     sizeof(payload_3) + 2);
		hdr_2.pdu_length(sizeof(hdr_1) + sizeof(hdr_2) +
				 sizeof(payload_0) + sizeof(payload_1) +
				 sizeof(payload_2) + sizeof(payload_3));

		os << hdr_0 << hdr_1 << hdr_2 << payload_0 << payload_1
		   << payload_2 << payload_3;

		e.endpoint->do_send(&packet);

	} else if ((hdr_1_r.pdu_type() == l2_lsp) ||
		   (hdr_1_r.pdu_type() == l2_csnp) ||
		   (hdr_1_r.pdu_type() == l2_psnp)) {
		/* if CSNP or LSP need to send empty CSNP as we don't store data
		 * for hello  */
		boost::asio::streambuf packet;
		std::ostream os(&packet);
		eth_header hdr_0;
		isis_header hdr_1;
		isis_csnp_header hdr_2;
		tlv_9 payload_0;
		hdr_1.pdu_type(l2_csnp);
		hdr_1.length_indicator(20);
		payload_0.tlv_length(0);
		hdr_0.length(sizeof(hdr_1) + sizeof(hdr_2) + sizeof(payload_0) +
			     2);
		os << hdr_0 << hdr_1 << hdr_2 << payload_0;
		e.endpoint->do_send(&packet);

	} else {
		std::cout << "Peer is not Up. Going Down." << std::endl;
		transit<Down>();
	}
}

void Up::react(TIMEOUT& e) {
        std::cout << std::endl;
	std::cout << "Hold-time expired. Going Down." << std::endl;
	transit<Down>();
        (void)e;
}

using fsm_list = tinyfsm::FsmList<ISIS_ADJ>;

/* dispatch event to "ISIS_ADJ" */
template <typename E>
void send_event(E& event) {
	fsm_list::template dispatch<E>(event);
}

FSM_INITIAL_STATE(ISIS_ADJ, Down)
