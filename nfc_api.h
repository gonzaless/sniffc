#pragma once


#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <stdexcept>
#include <tuple>
#include <type_traits>
#include <vector>
#include <nfc/nfc.h>


namespace nfc {


enum class mode_type {
	TARGET          = ::N_TARGET,
	INITIATOR       = ::N_INITIATOR,
};

constexpr std::string_view to_string(const mode_type value) {
	switch (value) {
		case mode_type::TARGET: return "TARGET";
		case mode_type::INITIATOR: return "INITIATOR";
	}
	return "Unknown mode type";
}


enum class baud_rate {
	UNDEFINED       = ::NBR_UNDEFINED,
	KBPS_106        = ::NBR_106,
	KBPS_212        = ::NBR_212,
	KBPS_424        = ::NBR_424,
	KBPS_847        = ::NBR_847,
};

constexpr bool operator<(const baud_rate lhs, const baud_rate rhs) {
	return static_cast<std::underlying_type_t<baud_rate>>(lhs) < static_cast<std::underlying_type_t<baud_rate>>(rhs);
}

constexpr bool is_valid(const baud_rate v) {
	return v == baud_rate::KBPS_106
	    || v == baud_rate::KBPS_212
	    || v == baud_rate::KBPS_424
	    || v == baud_rate::KBPS_847;
}

constexpr std::string_view to_string(const baud_rate value) {
	switch (value) {
		case baud_rate::UNDEFINED: return "UNDEFINED";
		case baud_rate::KBPS_106: return "KBPS_106";
		case baud_rate::KBPS_212: return "KBPS_212";
		case baud_rate::KBPS_424: return "KBPS_424";
		case baud_rate::KBPS_847: return "KBPS_847";
	}
	return "Unknown baud rate";
}


enum class modulation_type {
	ISO14443A       = ::NMT_ISO14443A,
	JEWEL           = ::NMT_JEWEL,
	ISO14443B       = ::NMT_ISO14443B,
	ISO14443BI      = ::NMT_ISO14443BI,     // pre-ISO14443B aka ISO/IEC 14443 B' or Type B'
	ISO14443B2SR    = ::NMT_ISO14443B2SR,   // ISO14443-2B ST SRx
	ISO14443B2CT    = ::NMT_ISO14443B2CT,   // ISO14443-2B ASK CTx
	FELICA          = ::NMT_FELICA,
	DEP             = ::NMT_DEP,
};

constexpr bool operator<(const modulation_type lhs, const modulation_type rhs) {
	return static_cast<std::underlying_type_t<modulation_type>>(lhs) < static_cast<std::underlying_type_t<modulation_type>>(rhs);
}

constexpr bool is_valid(const modulation_type v) {
	return v == modulation_type::ISO14443A
	    || v == modulation_type::JEWEL
	    || v == modulation_type::ISO14443B
	    || v == modulation_type::ISO14443BI
	    || v == modulation_type::ISO14443B2SR
	    || v == modulation_type::ISO14443B2CT
	    || v == modulation_type::FELICA
	    || v == modulation_type::DEP;
}

constexpr std::string_view to_string(const modulation_type value) {
	switch (value) {
		case modulation_type::ISO14443A: return "ISO14443A";
		case modulation_type::JEWEL: return "JEWEL";
		case modulation_type::ISO14443B: return "ISO14443B";
		case modulation_type::ISO14443BI: return "ISO14443BI";
		case modulation_type::ISO14443B2SR: return "ISO14443B2SR";
		case modulation_type::ISO14443B2CT: return "ISO14443B2CT";
		case modulation_type::FELICA: return "FELICA";
		case modulation_type::DEP: return "DEP";
	}
	return "Unknown modulation type";
}


struct channel_type {
	modulation_type type;
	baud_rate       rate;
};

constexpr bool operator<(const channel_type& lhs, const channel_type& rhs) {
	return std::tuple(lhs.type, lhs.rate) < std::tuple(rhs.type, rhs.rate);
}

constexpr bool operator==(const channel_type& lhs, const channel_type& rhs) {
	return lhs.type == rhs.type && lhs.rate == rhs.rate;
}

constexpr bool is_valid(const channel_type& channel) {
	return is_valid(channel.type) && is_valid(channel.rate);
}


struct iso14443a_target_info {
	std::uint8_t abt_atqa[2];
	std::uint8_t bt_sak;
	std::size_t  uid_len;
	std::uint8_t abt_uid[10];
	std::size_t  ats_len;
	std::uint8_t abt_ats[254]; // Maximal theoretical ATS is FSD-2, FSD=256 for FSDI=8 in RATS
} __attribute__((packed)); // TODO remove

struct iso14443b_target_info {
	std::uint8_t abt_pupi[4];             // abtPupi store PUPI contained in ATQB (Answer To reQuest of type B) (see ISO14443-3)
	std::uint8_t abt_application_data[4]; // abtApplicationData store Application Data contained in ATQB (see ISO14443-3)
	std::uint8_t abt_protocol_info[3];    // abtProtocolInfo store Protocol Info contained in ATQB (see ISO14443-3)
	std::uint8_t ui8_card_identifier;     // ui8CardIdentifier store CID (Card Identifier) attributted by PCD to the PICC
};

union target_info {
	iso14443a_target_info iso14443a;
	iso14443b_target_info iso14443b;
	::nfc_iso14443a_info iso14443a_;
	::nfc_iso14443b_info iso14443b_;
	::nfc_iso14443bi_info iso14443bi;
	::nfc_iso14443b2sr_info iso14443b2sr;
	::nfc_iso14443b2ct_info iso14443b2ct;
	::nfc_dep_info dep;
	::nfc_felica_info felica;
	::nfc_jewel_info jewel;
};

struct session_info {
	target_info target;
	channel_type channel;
};

template <typename Fn>
constexpr bool visit(const session_info& si, Fn&& fn) {
	switch (si.channel.type) {
		case modulation_type::ISO14443A:
			fn(si.target.iso14443a);
			return true;
		case modulation_type::JEWEL:
			fn(si.target.jewel);
			return true;
		case modulation_type::ISO14443B:
			fn(si.target.iso14443b);
			return true;
		case modulation_type::ISO14443BI:
			fn(si.target.iso14443bi);
			return true;
		case modulation_type::ISO14443B2SR:
			fn(si.target.iso14443b2sr);
			return true;
		case modulation_type::ISO14443B2CT:
			fn(si.target.iso14443b2ct);
			return true;
		case modulation_type::FELICA:
			fn(si.target.felica);
			return true;
		case modulation_type::DEP:
			fn(si.target.dep);
			return true;
	}
	return false;
}


namespace detail {


#define NFC_DETAIL_ERRCHECK(expr) [&]() -> int {                                                \
		const auto ret = (expr);                                                                \
		if (ret < 0) {                                                                          \
		    const auto errstr = ::nfc::detail::error_string_with_code(ret);                     \
            throw std::runtime_error(#expr " failed, error " + errstr);                         \
        }                                                                                       \
        return ret;                                                                             \
	}()

constexpr std::string_view to_string_view(const char* p) {
	return p ? std::string_view(p) : std::string_view();
}

constexpr std::string_view error_string(const int code) {
	switch (code) {
		case NFC_SUCCESS: return "Success";
		case NFC_EIO: return "Input/output error, device may not be usable anymore without re-open it";
		case NFC_EINVARG: return "Invalid argument(s)";
		case NFC_EDEVNOTSUPP: return "Operation not supported by device";
		case NFC_ENOTSUCHDEV: return "No such device";
		case NFC_EOVFLOW: return "Buffer overflow";
		case NFC_ETIMEOUT: return "Operation timed out";
		case NFC_EOPABORTED: return "Operation aborted (by user)";
		case NFC_ENOTIMPL: return "Not (yet) implemented";
		case NFC_ETGRELEASED: return "Target released";
		case NFC_ERFTRANS: return "Error while RF transmission";
		case NFC_EMFCAUTHFAIL: return "MIFARE Classic: authentication failed";
		case NFC_ESOFT: return "Software error (allocation, file/pipe creation, etc.)";
		case NFC_ECHIP: return "Device's internal chip error";
		default: return "Unknown error";
	}
}

inline std::string error_string_with_code(const int code) {
	return std::to_string(code) + ": " + std::string(error_string(code));
}


constexpr channel_type to_channel_type(const ::nfc_modulation& modulation) {
	return {static_cast<modulation_type>(modulation.nmt), static_cast<baud_rate>(modulation.nbr) };
}

constexpr ::nfc_modulation to_nfc_modulation(const channel_type& channel) {
	return {static_cast<::nfc_modulation_type>(channel.type), static_cast<::nfc_baud_rate>(channel.rate) };
}


template <typename T>
class resource {
public:
	using impl_t = T;
public:
	explicit resource(T* const handle) noexcept: impl_(handle) {}
	resource(const resource&) = delete;
	~resource() = default;

	resource& operator=(const resource&) = delete;

	impl_t* handle() const { return impl_; }

	impl_t* release_handle() {
		auto temp = impl_;
		impl_ = nullptr;
		return temp;
	}

	void reset_handle(impl_t* impl) {
		impl_ = impl;
	}

	void swap_handle(resource& that) {
		std::swap(impl_, that.impl_);
	}
private:
	impl_t* impl_ = nullptr;
};


} // namespace detail


class context_t;
class session_base;


class device_t final: private detail::resource<nfc_device> {
	friend class context_t;
	friend class session_base;
private:
	explicit device_t(impl_t* handle) noexcept:
		resource(handle)
	{
	}
public:
	device_t(device_t&& that) noexcept:
		resource(that.release_handle()) {
	}

	~device_t() {
		if (auto* p = resource::release_handle()) {
			::nfc_close(p);
		}
	}

	device_t& operator=(device_t&& that) noexcept {
		device_t(std::forward<device_t>(that)).swap_handle(*this);
		return *this;
	}

	std::string_view name() const {
		return detail::to_string_view(::nfc_device_get_name(handle()));
	}

	std::string_view connection_string() const {
		return detail::to_string_view(::nfc_device_get_connstring(handle()));
	}

	std::string info() const {
		std::string result;

		char* pbuf = nullptr;
		if (const auto ret = ::nfc_device_get_information_about(handle(), &pbuf); ret >= 0 && pbuf) {
			result.assign(pbuf, static_cast<std::size_t>(ret));
			::nfc_free(pbuf);
		} else {
			result = "Error retrieving device info, error " + detail::error_string_with_code(ret);
		}

		return result;
	}

	std::string supported_baud_rates(const modulation_type modulation) const {
		const ::nfc_baud_rate* list = nullptr;
		NFC_DETAIL_ERRCHECK(::nfc_device_get_supported_baud_rate(handle(), static_cast<::nfc_modulation_type>(modulation), &list));

		std::string result;
		for (std::size_t i = 0; list[i]; ++i) {
			if (i > 0) {
				result += ',';
			}
			result += detail::to_string_view(::str_nfc_baud_rate(list[i]));
		}
		return result;
	}

	const modulation_type* supported_modulation(const mode_type mode) const {
		const ::nfc_modulation_type* list = nullptr;
		NFC_DETAIL_ERRCHECK(::nfc_device_get_supported_modulation(handle(), static_cast<::nfc_mode>(mode), &list));
		return reinterpret_cast<const modulation_type*>(list);
	}

	std::vector<channel_type> supported_channels(const mode_type mode) const {
		std::vector<channel_type> channels;

		const ::nfc_modulation_type* modulation_types = nullptr;
		NFC_DETAIL_ERRCHECK(::nfc_device_get_supported_modulation(handle(), static_cast<::nfc_mode>(mode), &modulation_types));

		for (std::size_t i = 0; modulation_types[i]; ++i) {
			const ::nfc_baud_rate* baud_rates = nullptr;
			NFC_DETAIL_ERRCHECK(::nfc_device_get_supported_baud_rate(handle(), modulation_types[i], &baud_rates));

			for (std::size_t j = 0; baud_rates[j]; ++j) {
				channels.push_back({static_cast<modulation_type>(modulation_types[i]), static_cast<baud_rate>(baud_rates[j])});
			}
		}

		return channels;
	}

	void abort_command() {
		NFC_DETAIL_ERRCHECK(::nfc_abort_command(handle()));
	}

	void idle() {
		NFC_DETAIL_ERRCHECK(::nfc_idle(handle()));
	}
};


class context_t final: public detail::resource<nfc_context> {
public:
	context_t():
		resource([]{
			::nfc_context* p = nullptr;
			::nfc_init(&p);
			if (!p)
			{
				throw std::runtime_error("Failed to initialize libnfc");
			}
			return p;
		}())
	{
	}

	context_t(context_t&& that) noexcept:
		resource(that.release_handle()) {
	}

	~context_t() {
		if (handle()) {
			::nfc_exit(handle());
		}
	}

	context_t& operator=(context_t&& that) noexcept {
		context_t(std::forward<context_t>(that)).swap_handle(*this);
		return *this;
	}

	std::string_view version() const {
		return nfc_version();
	}

	// Empty connection string for default device
	device_t open_device(const std::string& connection_string = {}) {
		auto* pdevice = ::nfc_open(handle(), connection_string.empty() ? nullptr : connection_string.data());
		if (!pdevice) {
			throw std::runtime_error("Failed to open NFC device \"" + connection_string + "\"");
		}
		return device_t(pdevice);
	}
};


class session_base {
protected:
	explicit session_base(device_t& device): device_(device) {}
	session_base(const session_base&) = delete;
	session_base& operator=(const session_base&) = delete;
protected:
	device_t::impl_t* device_handle() const {
		return device_.handle();
	}
private:
	device_t& device_;
};


struct bit_span {
	const std::byte* data;
	std::size_t size;
};

struct mutable_bit_span {
	std::byte* data;
	std::size_t size;
};

struct byte_span {
	const std::byte* data;
	std::size_t size;
};

struct mutable_byte_span {
	std::byte* data;
	std::size_t size;
};


enum class security_option {
	OFF,
	ON,
};

template <mode_type>
class session;


template <>
class session<mode_type::INITIATOR> final: public session_base {
public:
	explicit session(device_t& device, security_option security = security_option::OFF):
		session_base(device) {
		switch (security)
		{
			case security_option::OFF:
				NFC_DETAIL_ERRCHECK(::nfc_initiator_init(device_handle()));
				break;
			case security_option::ON:
				NFC_DETAIL_ERRCHECK(::nfc_initiator_init_secure_element(device_handle()));
				break;
		}
	}

	void list_passive_targets(const nfc_modulation nm, nfc_target ant[], const size_t szTargets) {
		NFC_DETAIL_ERRCHECK(::nfc_initiator_list_passive_targets(device_handle(), nm, ant, szTargets));
	}

	using polling_period = std::chrono::duration<long long, std::ratio<1LL, 150*1000LL>>; // 150ms units

	// number of targets found
	std::size_t poll_target(const nfc_modulation* pnmTargetTypes, const std::size_t szTargetTypes, const std::uint8_t numberOfAttempts, const polling_period period, nfc_target *pnt) {
		const auto target_count = NFC_DETAIL_ERRCHECK(::nfc_initiator_poll_target(device_handle(),
			pnmTargetTypes, szTargetTypes, numberOfAttempts, static_cast<std::uint8_t>(period.count()), pnt));
		return static_cast<std::size_t>(target_count);
	}

	std::optional<session_info> start(const std::vector<channel_type>& channels, const std::uint8_t attempts_number, const std::uint8_t period) {
		const auto modulations = [&]{
			std::vector<::nfc_modulation> temp;
			temp.reserve(channels.size());
			for (const auto channel : channels) {
				temp.emplace_back(detail::to_nfc_modulation(channel));
			}
			return temp;
		}();
		::nfc_target target = {};
		const auto target_count = NFC_DETAIL_ERRCHECK(::nfc_initiator_poll_target(device_handle(),
			modulations.data(), modulations.size(), attempts_number, period, &target));
		if (target_count == 0) {
			return std::nullopt;
		}
		session_info result;
		result.channel = detail::to_channel_type(target.nm);
		static_assert(sizeof(result.target) == sizeof(target.nti));
		std::memcpy(&result.target, &target.nti, sizeof(result.target));
		return result;
	}

	void select_target(const nfc_modulation nm, const uint8_t *pbtInitData, const size_t szInitData, nfc_target* pnt) {
		NFC_DETAIL_ERRCHECK(::nfc_initiator_select_passive_target(device_handle(), nm, pbtInitData, szInitData, pnt));
	}

	void poll_target(const nfc_dep_mode ndm, const nfc_baud_rate nbr, const nfc_dep_info *pndiInitiator, nfc_target *pnt, const int timeout) {
		NFC_DETAIL_ERRCHECK(::nfc_initiator_poll_dep_target(device_handle(), ndm, nbr, pndiInitiator, pnt, timeout));
	}

	void select_target(const nfc_dep_mode ndm, const nfc_baud_rate nbr, const nfc_dep_info *pndiInitiator, nfc_target *pnt, const int timeout) {
		NFC_DETAIL_ERRCHECK(::nfc_initiator_select_dep_target(device_handle(), ndm, nbr, pndiInitiator, pnt, timeout));
	}

	void deselect_target() {
		NFC_DETAIL_ERRCHECK(::nfc_initiator_deselect_target(device_handle()));
	}

	// nullptr for the last target
	bool is_target_present(const nfc_target* pnt = nullptr) {
		return ::nfc_initiator_target_is_present(device_handle(), pnt) == NFC_SUCCESS;
	}

	void transceive_bytes(const uint8_t *pbtTx, const size_t szTx, uint8_t *pbtRx, const size_t szRx, int timeout) {
		NFC_DETAIL_ERRCHECK(::nfc_initiator_transceive_bytes(device_handle(), pbtTx, szTx, pbtRx, szRx, timeout));
	}

	void transceive_bytes_timed(const uint8_t *pbtTx, const size_t szTx, uint8_t *pbtRx, const size_t szRx, uint32_t *cycles) {
		NFC_DETAIL_ERRCHECK(::nfc_initiator_transceive_bytes_timed(device_handle(), pbtTx, szTx, pbtRx, szRx, cycles));
	}

	void transceive_bits(const uint8_t *pbtTx, const size_t szTxBits, const uint8_t *pbtTxPar, uint8_t *pbtRx, const size_t szRx, uint8_t *pbtRxPar) {
		NFC_DETAIL_ERRCHECK(::nfc_initiator_transceive_bits(device_handle(), pbtTx, szTxBits, pbtTxPar, pbtRx, szRx, pbtRxPar));
	}

	void transceive_bits_timed(const uint8_t *pbtTx, const size_t szTxBits, const uint8_t *pbtTxPar, uint8_t *pbtRx, const size_t szRx, uint8_t *pbtRxPar, uint32_t *cycles) {
		NFC_DETAIL_ERRCHECK(::nfc_initiator_transceive_bits_timed(device_handle(), pbtTx, szTxBits, pbtTxPar, pbtRx, szRx, pbtRxPar, cycles));
	}
};


template <>
class session<mode_type::TARGET> final: public session_base {
public:
	session(device_t& device, const std::chrono::milliseconds timeout):
		session_base(device) {
//		NFC_EXPORT int nfc_target_init(nfc_device *pnd, nfc_target *pnt, uint8_t *pbtRx, const size_t szRx, int timeout);
//		NFC_DETAIL_ERRCHECK(::nfc_target_init(device_handle(), , , , , static_cast<int>(timeout.count())));
	}

	void send(const byte_span bytes, const std::chrono::milliseconds timeout) {
		NFC_DETAIL_ERRCHECK(::nfc_target_send_bytes(device_handle(), reinterpret_cast<const std::uint8_t*>(bytes.data), bytes.size, static_cast<int>(timeout.count())));
	}

	void receive(const mutable_byte_span bytes, const std::chrono::milliseconds timeout) {
		NFC_DETAIL_ERRCHECK(::nfc_target_receive_bytes(device_handle(), reinterpret_cast<std::uint8_t*>(bytes.data), bytes.size, static_cast<int>(timeout.count())));
	}

	void send(const bit_span bits, const uint8_t* pbtTxParity /*TODO*/) {
		NFC_DETAIL_ERRCHECK(::nfc_target_send_bits(device_handle(), reinterpret_cast<const std::uint8_t*>(bits.data), bits.size, pbtTxParity));
	}

	void receive(const mutable_bit_span bits, uint8_t* pbtRxParity /*TODO*/) {
		NFC_DETAIL_ERRCHECK(::nfc_target_receive_bits(device_handle(), reinterpret_cast<std::uint8_t*>(bits.data), bits.size, pbtRxParity));
	}
};


} // namespace nfc
