#include "binary_stream.h"
#include "buffer.h"
#include "sha.h"
#include "aes.h"
#include "dh.h"
#include "rsa_key.h"
#include "mtproto_objects.h"
#include "mtproto_session_type.h"
#include "message.h"
#include "details/random.h"
#include "details/brent.h"
#include "dh_handshake.h"

namespace mtproto::crypto {

	void create_auth_key(mtproto::http::HTTPSender& http_adapter, mtproto::crypto::rsa_key& key, const int dc, mtproto::session::session_details& new_session) {
		mtproto::base_objects::ReqPQ req_pq;
		std::array<char, 16> nonce;
		std::array<char, 32> new_nonce;
		mtproto::crypto::random_bytes(nonce.data(), 16);
		mtproto::crypto::random_bytes(new_nonce.data(), 32);
		memcpy(req_pq.nonce, nonce.data(), nonce.size());
		auto message = mtproto::message::UnencryptedMessage::write(req_pq);
		auto response = http_adapter.send(message);
		mtproto::message::UnencryptedMessage::skip_header(response);
		mtproto::base_objects::ResPQ res_pq;
		res_pq.read(std::move(response));

		mtproto::crypto::brent_pq pq;
		pq.pq = res_pq.pq;
		mtproto::crypto::decompose(&pq);

		uint64_t fingerprint = key.compute_fingerprint();

		mtproto::base_objects::PQInnerDataDC pq_inner_data_dc;
		pq_inner_data_dc.p = pq.p;
		pq_inner_data_dc.q = pq.q;
		pq_inner_data_dc.pq = pq.pq;
		pq_inner_data_dc.dc = 2;
		memcpy(pq_inner_data_dc.nonce, nonce.data(), 16);
		memcpy(pq_inner_data_dc.server_nonce, res_pq.server_nonce, 16);
		memcpy(pq_inner_data_dc.new_nonce, new_nonce.data(), 32);
		mtproto::data::binary_buffer encrypted = pq_inner_data_dc.write();
		mtproto::data::binary_buffer pq_inner_data_dc_hash = mtproto::crypto::sha1(encrypted);
		pq_inner_data_dc_hash.append(encrypted);
		pq_inner_data_dc_hash.add_padding(255 - pq_inner_data_dc_hash.get_size());
		pq_inner_data_dc_hash = key.encrypt(pq_inner_data_dc_hash);

		mtproto::base_objects::ReqDHParams req_dh_params;
		req_dh_params.encrypted_data = std::move(pq_inner_data_dc_hash);
		req_dh_params.fingerprint = fingerprint;
		req_dh_params.p = pq.p;
		req_dh_params.q = pq.q;
		memcpy(req_dh_params.server_nonce, res_pq.server_nonce, 16);
		memcpy(req_dh_params.nonce, nonce.data(), 16);

		message = mtproto::message::UnencryptedMessage::write(req_dh_params);
		response = http_adapter.send(message);
		mtproto::message::UnencryptedMessage::skip_header(response);

		mtproto::base_objects::ServerDHParamsOk server_dh_params_ok;
		server_dh_params_ok.read(std::move(response));

		mtproto::data::binary_buffer concatenation(new_nonce.data(), 32);
		concatenation.append(res_pq.server_nonce, 16);
		mtproto::data::binary_buffer tmp_aes_key = mtproto::crypto::sha1(concatenation);
		concatenation.set_data(res_pq.server_nonce, 16);
		concatenation.append(new_nonce.data(), 32);
		concatenation = mtproto::crypto::sha1(concatenation);
		concatenation.slice(0, 12);
		tmp_aes_key.append(concatenation);
		concatenation.set_data(res_pq.server_nonce, 16);
		concatenation.append(new_nonce.data(), 32);
		mtproto::data::binary_buffer tmp_aes_iv = mtproto::crypto::sha1(concatenation);
		tmp_aes_iv.slice(12, 20);
		concatenation.set_data(new_nonce.data(), 32);
		concatenation.append(new_nonce.data(), 32);
		concatenation = mtproto::crypto::sha1(concatenation);
		tmp_aes_iv.append(concatenation);
		tmp_aes_iv.append(new_nonce.data(), 4);

		mtproto::data::binary_buffer decrypted_answer = mtproto::crypto::ige256_decrypt(server_dh_params_ok.encrypted_answer, tmp_aes_key, tmp_aes_iv);
		decrypted_answer.slice(20, decrypted_answer.get_size());

		mtproto::base_objects::ServerDHInnerData server_dh_inner_data;
		server_dh_inner_data.read(std::move(decrypted_answer));

		mtproto::crypto::dh auth_key(server_dh_inner_data.g, server_dh_inner_data.g_a, server_dh_inner_data.dh_prime);
		mtproto::base_objects::ClientDHInnerData client_dh_inner_data;
		memcpy(client_dh_inner_data.nonce, nonce.data(), 16);
		memcpy(client_dh_inner_data.server_nonce, res_pq.server_nonce, 16);
		client_dh_inner_data.retry_id = 0;
		client_dh_inner_data.g_b = auth_key.get_g_b();
		auto serialization = client_dh_inner_data.write();
		encrypted = mtproto::crypto::sha1(serialization);
		encrypted.append(serialization);
		mtproto::crypto::pad_plaintext(encrypted);
		encrypted = mtproto::crypto::ige256_encrypt(encrypted, tmp_aes_key, tmp_aes_iv);

		mtproto::base_objects::SetClientDHParams set_client_dh_params;
		memcpy(set_client_dh_params.nonce, nonce.data(), 16);
		memcpy(set_client_dh_params.server_nonce, res_pq.server_nonce, 16);
		set_client_dh_params.encrypted_data = std::move(encrypted);

		message = mtproto::message::UnencryptedMessage::write(set_client_dh_params);
		response = http_adapter.send(message);
		mtproto::message::UnencryptedMessage::skip_header(response);

		if (mtproto::TLPacket::get_packet_id(response) == 0x3bcbf734) {
			memcpy(new_session.auth_key, auth_key.get_auth_key().get_data_pointer(), 256);
			new_session.dc = dc;
			new_session.port = 443;
			new_session.ip = http_adapter.get_ip();
			mtproto::session::compute_auth_key_id(new_session.auth_key, new_session.auth_key_id);
		}
		else {
			throw dh_gen_fail("server returned dh_gen_fail!");
		}
	}
}