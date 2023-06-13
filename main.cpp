// mtproto_client2.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
//

#include <iostream>
#include "msg_id.h"
#include "rsa_key.h"
#include "dh_handshake.h"
#include "mtproto_objects.h"
#include "message.h"
#include "tcp.h"
#include "session.h"
#include "details/random.h"

template <typename T, typename U = T>
void dump_as_python_array(const std::vector<T>& array) {
	std::cout << "[";
	for (int i = 0; i < array.size(); i++) {
		if (i != 0) {
			std::cout << ", ";
		}
		std::cout << (U)array[i];
	}
	std::cout << ']';
}

int main()
{
	std::ios_base::sync_with_stdio(false);
	mtproto::session::session_details session_details;
	mtproto::session::load_from_file("new_session.bin", session_details);
	mtproto::session::session_type session = mtproto::session::session::create(session_details);
	session->initialize();
	mtproto::base_objects::help_getConfig get_config;
	mtproto::data::binary_buffer serialized = get_config.write();
	mtproto::base_objects::InitConnection init_connection;
	init_connection.api_id = 4;
	init_connection.device_model = "IBM PC/AT";
	init_connection.system_version = "DOS 6.22";
	init_connection.app_version = "1.0";
	init_connection.system_lang_code = "en";
	init_connection.lang_pack = "";
	init_connection.lang_code = "en";
	init_connection.query = std::move(serialized);
	serialized = init_connection.write();
	mtproto::base_objects::InvokeWithLayer invoke_with_layer;
	invoke_with_layer.layer = 133;
	invoke_with_layer.query = std::move(serialized);
	while (true) {
		static int i = 1;
		std::cout << session->send_packet(invoke_with_layer) << std::endl;
		std::cout << i++ << std::endl;
	}
}

// Запуск программы: CTRL+F5 или меню "Отладка" > "Запуск без отладки"
// Отладка программы: F5 или меню "Отладка" > "Запустить отладку"

// Советы по началу работы 
//   1. В окне обозревателя решений можно добавлять файлы и управлять ими.
//   2. В окне Team Explorer можно подключиться к системе управления версиями.
//   3. В окне "Выходные данные" можно просматривать выходные данные сборки и другие сообщения.
//   4. В окне "Список ошибок" можно просматривать ошибки.
//   5. Последовательно выберите пункты меню "Проект" > "Добавить новый элемент", чтобы создать файлы кода, или "Проект" > "Добавить существующий элемент", чтобы добавить в проект существующие файлы кода.
//   6. Чтобы снова открыть этот проект позже, выберите пункты меню "Файл" > "Открыть" > "Проект" и выберите SLN-файл.
