#include <algorithm>
#include <iomanip>
#include <iostream>
#include <tuple>
#include <cassert>
#include <thread>
#include "nfc_api.h"


namespace sniffc {


struct hexstr {
	const std::uint8_t* data;
	std::size_t size;

	template <std::size_t N>
	hexstr(const std::uint8_t (&a)[N]): data(a), size(N) {}
	hexstr(const std::uint8_t& b): data(&b), size(1) {}
};

std::ostream& operator<<(std::ostream& os, const hexstr& hs) {
	os << std::hex;
	for (std::size_t i = 0; i < hs.size; ++i) {
		os << std::setfill('0') << std::setw(2) << static_cast<unsigned>(hs.data[i]);
	}
	os << std::dec;
	return os;
}

struct print_target_info {
	void operator()(const nfc::iso14443a_target_info& target) const {
		std::cout << "iso14443a:"
		    << " abt_atqa=" << hexstr(target.abt_atqa)
		    << " bt_sak=" << hexstr(target.bt_sak)
		    << " uid_len=" << target.uid_len
		    << " abt_uid=" << hexstr(target.abt_uid)
		    << " ats_len=" << target.ats_len
		    << " abt_ats=" << hexstr(target.abt_ats)
		    << std::endl;
	}

	void operator()(const nfc::iso14443b_target_info& target) const {
		std::cout << "iso14443b:"
		    << " abt_pupi=" << hexstr(target.abt_pupi)
		    << " abt_application_data=" << hexstr(target.abt_application_data)
		    << " abt_protocol_info=" << hexstr(target.abt_protocol_info)
		    << " ui8_card_identifier=" << hexstr(target.ui8_card_identifier)
		    << std::endl;
	}

	template <typename TargetInfo>
	void operator()(const TargetInfo& ) const {
		std::cout << "Can't print target" << std::endl;
	}
};

void print_supported_baud_rates(const nfc::device_t& device, const nfc::modulation_type modulation) {
	std::cout << "    modulation type: " << nfc::to_string(modulation) << std::endl;
	std::cout << "         baud rates: " << device.supported_baud_rates(modulation) << std::endl;
}

void print_supported_modulations(const nfc::device_t& device, const nfc::mode_type mode) {
	std::cout << "---------------------------------------------" << std::endl;
	std::cout << "          mode type: " << nfc::to_string(mode) << std::endl;
	std::cout << "---------------------------------------------" << std::endl;

	const auto* list = device.supported_modulation(mode);
	for (std::size_t i = 0; static_cast<int>(list[i]); ++i) {
		print_supported_baud_rates(device, list[i]);
	}
}

void print_info(const nfc::device_t& device) {
	std::cout << "default device name: " << device.name() << std::endl;
	std::cout << "  connection string: " << device.connection_string() << std::endl;
	std::cout << "        device info: " << device.info() << std::endl;

	print_supported_modulations(device, nfc::mode_type::INITIATOR);
	print_supported_modulations(device, nfc::mode_type::TARGET);
}

void read_tag(nfc::device_t& device) {
	nfc::session<nfc::mode_type::INITIATOR> session(device);
	std::cout << "Session created" << std::endl;

	const auto channels = std::vector<nfc::channel_type>{
		{ nfc::modulation_type::ISO14443A, nfc::baud_rate::KBPS_424 },
		{ nfc::modulation_type::ISO14443A, nfc::baud_rate::KBPS_212 },
		{ nfc::modulation_type::ISO14443A, nfc::baud_rate::KBPS_106 },
		{ nfc::modulation_type::FELICA, nfc::baud_rate::KBPS_424 },
		{ nfc::modulation_type::FELICA, nfc::baud_rate::KBPS_212 },
		{ nfc::modulation_type::ISO14443B, nfc::baud_rate::KBPS_106 },
//      { nfc::modulation_type::ISO14443BI, nfc::baud_rate::KBPS_106 },
//      { nfc::modulation_type::ISO14443B2SR, nfc::baud_rate::KBPS_106 },
//      { nfc::modulation_type::ISO14443B2CT, nfc::baud_rate::KBPS_106 },
		{ nfc::modulation_type::JEWEL, nfc::baud_rate::KBPS_106 },
//      { nfc::modulation_type::DEP, nfc::baud_rate::KBPS_424 },
//      { nfc::modulation_type::DEP, nfc::baud_rate::KBPS_212 },
//      { nfc::modulation_type::DEP, nfc::baud_rate::KBPS_106 },
	};

	std::cout << "Polling targets..." << std::endl;
	const auto maybe_session_info = session.start(channels, /*attempts number*/20, /*period in 150 ms*/1);
	if (!maybe_session_info.has_value()) {
		std::cout << "No targets found" << std::endl;
		return;
	}

	const auto& session_info = *maybe_session_info;
	std::cout << "Target found on " << to_string(session_info.channel.type) << "/" << to_string(session_info.channel.rate) << std::endl;
	nfc::visit(session_info, print_target_info());
//		target.nm.nmt;
//		print_nfc_target(&nt, verbose);

	std::cout << "Waiting for card removing..." << std::endl;
	while (session.is_target_present()) {
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
	}
	std::cout << "Tag was removed" << std::endl;
}

void clone_tag(nfc::device_t&) {
	std::cout << "CLONNING IS NOT IMPLEMENTED" << std::endl;
}


} // namespace sniffc


int main(int argc, const char* argv[]) {
	enum class command_type {
		HELP,
		INFO,
		READ,
		CLONE
	};

	struct command_item {
		command_type     type;
		std::string_view name;
		std::string_view shortcut;
		std::string_view info;
	};

	const command_item command_list[] = {
		{command_type::HELP , "--help", "-h", "Print help"},
		{command_type::INFO , "--info", "-i", "Print NFC device info"},
		{command_type::READ , "--read", "-r", "Read tag"},
		{command_type::CLONE, "--clone", "", "Clone tag"},
	};

	const auto print_help = [&command_list]{
		std::cout << "sniffc [command]" << std::endl;
		std::cout << "commands:" << std::endl;
		for (const auto& item : command_list)
		{
			auto command_str = std::string(item.shortcut);
			if (! item.shortcut.empty())
			{
				command_str += ", ";
			}
			command_str += item.name;

			constexpr std::size_t command_section_len = 16ul;
			std::cout << "  " << command_str
			    << std::string(command_section_len + 1 - std::min(command_section_len, command_str.size()) , ' ')
			    << item.info << std::endl;
		}
	};

	const auto command = [&]{
		if (argc >= 2) {
			for (const auto& item : command_list) {
				if (item.shortcut == argv[1] || item.name == argv[1]) {
					return item.type;
				}
			}
		}
		return command_type::HELP;
	}();

	if (command == command_type::HELP) {
		print_help();
		return 0;
	}

	try {
		nfc::context_t context;
		auto device = context.open_device();

		switch (command) {
			case command_type::HELP:
				assert(false); // Help is handled above
				break;
			case command_type::INFO:
				sniffc::print_info(device);
				break;
			case command_type::READ:
				sniffc::read_tag(device);
				break;
			case command_type::CLONE:
				sniffc::clone_tag(device);
				break;
		}
	}
	catch (const std::exception& e) {
		std::cout << "Error occurred: " << e.what() << std::endl;
		return 1;
	}

	return 0;
}