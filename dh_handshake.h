#pragma once

#include <stdexcept>
#include <string>
#include "buffer.h"
#include "mtproto_session_type.h"
#include "http.h"

class dh_gen_fail : public std::exception {
	std::string m_error_text;
public:
	dh_gen_fail(const char* reason) : m_error_text(reason) {}

	virtual const char* what() const {
		return m_error_text.c_str();
	}
};

namespace mtproto::crypto {

	void create_auth_key(mtproto::http::HTTPSender& http_adapter, mtproto::crypto::rsa_key& key, const int dc, mtproto::session::session_details& details);
}