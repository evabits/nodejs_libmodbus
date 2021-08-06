#include <modbus.h>
#include <string.h>
#include <errno.h>
#include <unistd.h> 
#include <sys/socket.h>
#include <napi.h>

#include <iostream>

// using namespace v8;
using namespace std;

// finger to the sky
#define REPORT_LEN 0xFF

// modbus_t *modbus_new_rtu(const char *device, int baud, char parity, int data_bit, int stop_bit);
// External new_rtu(String, Integer, String, Integer, Integer);
Napi::Value js_new_rtu(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (info.Length() < 5) {
		Napi::Error::New(env,"Wrong number of arguments").ThrowAsJavaScriptException();
		return env.Null();
	}
	string dev = info[0].As<Napi::String>();
	int baud = info[1].As<Napi::Number>().Int32Value();
	string par = info[2].As<Napi::String>();
	int data_bit = info[3].As<Napi::Number>().Int32Value();
	int stop_bit = info[4].As<Napi::Number>().Int32Value();
	
	char parity = par.c_str()[0];
	
	modbus_t *ctx = modbus_new_rtu(dev.c_str(), baud, parity, data_bit, stop_bit);
		
	if (ctx == NULL) {
		return env.Null();
	} else {
		return Napi::External<modbus_t>::New(env, ctx);
	}
}

// int modbus_rtu_get_serial_mode(modbus_t *ctx);
// Integer rtu_get_serial_mode(External);
Napi::Value js_rtu_get_serial_mode(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	
	int ret = modbus_rtu_get_serial_mode(ctx);
	
	return Napi::Value ::From(info.Env(), ret);
}

// int modbus_rtu_set_serial_mode(modbus_t *ctx, int mode);
// Integer rtu_set_serial_mode(External, Integer);
Napi::Value js_rtu_set_serial_mode(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	int mode = info[1].As<Napi::Number>().Int32Value();

	
	int ret = modbus_rtu_set_serial_mode(ctx, mode);
	
	Napi::Number num = Napi::Number::New(info.Env(), ret);
	return num;
}

// int modbus_rtu_get_rts(modbus_t *ctx);
Napi::Value js_rtu_get_rts(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	
	int ret = modbus_rtu_get_rts(ctx);
	
	Napi::Number num = Napi::Number::New(info.Env(), ret);
	return num;
}

// int modbus_rtu_set_rts(modbus_t *ctx, int mode)
Napi::Value js_rtu_set_rts(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	int mode = info[1].As<Napi::Number>().Int32Value();

	int ret = modbus_rtu_set_rts(ctx, mode);
	
	Napi::Number num = Napi::Number::New(info.Env(), ret);
	return num;
}

// modbus_t *modbus_new_tcp(const char *ip, int port);
// External new_tcp(String, Integer);
Napi::Value js_new_tcp(const Napi::CallbackInfo& info) {
	string ip = info[0].As<Napi::String>();
	int port = info[1].As<Napi::Number>().Int32Value();
	
	modbus_t *ctx = modbus_new_tcp(ip.c_str(), port);
	
	if (ctx == NULL) {
		return info.Env().Null();
	} else {
		return Napi::External<modbus_t>::New(info.Env(), ctx);
	}
}

// modbus_t *modbus_new_tcp_pi(const char *node, const char *service);
// External new_tcp_pi(String, String);
Napi::Value js_new_tcp_pi(const Napi::CallbackInfo& info) {
	string node = info[0].As<Napi::String>();
	string service = info[1].As<Napi::String>();
	
	modbus_t *ctx = modbus_new_tcp_pi(node.c_str(), service.c_str());
	
	if (ctx == NULL) {
		return info.Env().Null();
	} else {
		return Napi::External<modbus_t>::New(info.Env(), ctx);
	}
}

// void modbus_free(modbus_t *ctx);
// Undefined free(External);
Napi::Value js_free(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	
	modbus_free(ctx);
	
	return info.Env().Undefined();
}

// void modbus_get_byte_timeout(modbus_t *ctx, struct timeval *timeout);
// Undefined get_byte_timeout(External, Object);
Napi::Value js_get_byte_timeout(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	Napi::Object timeout_obj = info[1].As<Napi::Object>();
	

	uint32_t sec = 0;
	uint32_t usec = 0;

	modbus_get_byte_timeout(ctx, &sec, &usec);

	struct timeval timeout;
	timeout.tv_sec = sec;
	timeout.tv_usec = usec;
	
	timeout_obj.Set("tv_sec", timeout.tv_sec);
	timeout_obj.Set("tv_usec", timeout.tv_usec);
	
	return info.Env().Undefined();
}

// void modbus_set_byte_timeout(modbus_t *ctx, struct timeval *timeout);
// Undefined set_byte_timeout(External, Object);
Napi::Value js_set_byte_timeout(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	Napi::Object timeout_obj = info[1].As<Napi::Object>();
	
	struct timeval timeout;
	timeout.tv_sec = timeout_obj.Get("tv_sec").As<Napi::Number>().Uint32Value();
	timeout.tv_usec = timeout_obj.Get("tv_usec").As<Napi::Number>().Uint32Value();

	modbus_set_byte_timeout(ctx, timeout.tv_sec, timeout.tv_usec);
	
	return info.Env().Undefined();
}

// void modbus_set_debug(modbus_t *ctx, int boolean);
// Undefined set_debug(External, Integer);
Napi::Value js_set_debug(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	int boolean = info[1].As<Napi::Number>().Int32Value();
	
	modbus_set_debug(ctx, boolean);
	
	return info.Env().Undefined();
}

// int modbus_set_error_recovery(modbus_t *ctx, modbus_error_recovery_mode error_recovery);
// Integer set_error_recovery(External, Integer);
Napi::Value js_set_error_recovery(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	int error_recovery = info[1].As<Napi::Number>().Int32Value();
	
	int ret = modbus_set_error_recovery(ctx, static_cast<modbus_error_recovery_mode>(error_recovery));
	
	return Napi::Number::New(info.Env(), ret);
}

// int modbus_get_header_length(modbus_t *ctx);
// Integer get_header_length(External);
Napi::Value js_get_header_length(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	
	int ret = modbus_get_header_length(ctx);
	
	return Napi::Number::New(info.Env(), ret);
}

// void modbus_get_response_timeout(modbus_t *ctx, struct timeval *timeout);
// Undefined get_response_timeout(External, Object);
Napi::Value js_get_response_timeout(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	Napi::Object timeout_obj = info[1].As<Napi::Object>();
	
	uint32_t sec = 0;
	uint32_t usec = 0;

	modbus_get_response_timeout(ctx, &sec, &usec);

	struct timeval timeout;
	timeout.tv_sec = sec;
	timeout.tv_usec = usec;
	
	timeout_obj.Set("tv_sec", timeout.tv_sec);
	timeout_obj.Set("tv_usec", timeout.tv_usec);
	
	return info.Env().Undefined();
}

// void modbus_set_response_timeout(modbus_t *ctx, struct timeval *timeout);
// Undefined set_response_timeout(External, Object);
Napi::Value js_set_response_timeout(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	Napi::Object timeout_obj = info[1].As<Napi::Object>();
	
	struct timeval timeout;
	timeout.tv_sec = timeout_obj.Get("tv_sec").As<Napi::Number>().Uint32Value();
	timeout.tv_usec = timeout_obj.Get("tv_usec").As<Napi::Number>().Uint32Value();
	modbus_set_response_timeout(ctx, timeout.tv_sec, timeout.tv_usec);
	
	return info.Env().Undefined();
}

// int modbus_set_slave(modbus_t *ctx, int slave);
// Integer set_slave(External, Integer);
Napi::Value js_set_slave(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	int slave = info[1].As<Napi::Number>().Int32Value();
	
	int ret = modbus_set_slave(ctx, slave);
	
	return Napi::Number::New(info.Env(), ret);
}

// void modbus_set_socket(modbus_t *ctx, int socket);
// Undefined set_socket(External, Integer);
Napi::Value js_set_socket(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	int socket = info[1].As<Napi::Number>().Int32Value();
	
	modbus_set_socket(ctx, socket);
	
	return info.Env().Undefined();
}

// int modbus_get_socket(modbus_t *ctx);
// Integer get_socket(External);
Napi::Value js_get_socket(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	
	int ret = modbus_get_socket(ctx);
	
	return Napi::Number::New(info.Env(), ret);
}

// in js module
// void modbus_set_bits_from_byte(uint8_t *dest, int index, const uint8_t value);
// void modbus_set_bits_from_bytes(uint8_t *dest, int index, unsigned int nb_bits, const uint8_t *tab_byte);
// uint8_t modbus_get_byte_from_bits(const uint8_t *src, int index, unsigned int nb_bits);
// float modbus_get_float(const uint16_t *src);
// void modbus_set_float(float f, uint16_t *dest);

// int modbus_connect(modbus_t *ctx);
// Integer connect(External);
Napi::Value js_connect(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	
	int ret = modbus_connect(ctx);
	
	return Napi::Number::New(info.Env(), ret);
}

// void modbus_close(modbus_t *ctx);
// Undefined close(External);
Napi::Value js_close(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	modbus_close(ctx);

	return info.Env().Undefined();
}

// int modbus_flush(modbus_t *ctx);
// Integer flush(External);
Napi::Value js_flush(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	
	int ret = modbus_flush(ctx);
	
	return Napi::Number::New(info.Env(), ret);
}

// int modbus_read_bits(modbus_t *ctx, int addr, int nb, uint8_t *dest);
// Integer read_bits(External, Integer, Integer, Array);
Napi::Value js_read_bits(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	int addr = info[1].As<Napi::Number>().Int32Value();
	int nb = info[2].As<Napi::Number>().Int32Value();
	Napi::Array dest_arr = info[3].As<Napi::Array>();
	
	uint8_t dest[nb];
	int ret = modbus_read_bits(ctx, addr, nb, dest);
	
	for (int i = 0; i < nb; i++) dest_arr.Set(i, dest[i]);
	
	return Napi::Number::New(info.Env(), ret);
}

// int modbus_read_input_bits(modbus_t *ctx, int addr, int nb, uint8_t *dest);
// Integer read_input_bits(External, Integer, Integer, Array);
Napi::Value js_read_input_bits(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	int addr = info[1].As<Napi::Number>().Int32Value();
	int nb = info[2].As<Napi::Number>().Int32Value();
	Napi::Array dest_arr = info[3].As<Napi::Array>();
	
	uint8_t dest[nb];
	int ret = modbus_read_input_bits(ctx, addr, nb, dest);
	
	for (int i = 0; i < nb; i++) dest_arr.Set(i, dest[i]);
	
	return Napi::Number::New(info.Env(), ret);
}

// int modbus_read_registers(modbus_t *ctx, int addr, int nb, uint16_t *dest);
// Integer read_registers(External, Integer, Integer, Array);
Napi::Value js_read_registers(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	int addr = info[1].As<Napi::Number>().Int32Value();
	int nb = info[2].As<Napi::Number>().Int32Value();
	Napi::Array dest_arr = info[3].As<Napi::Array>();
	
	uint16_t dest[nb];
	int ret = modbus_read_registers(ctx, addr, nb, dest);
	
	for (int i = 0; i < nb; i++) dest_arr.Set(i,dest[i]);
	
	return Napi::Number::New(info.Env(), ret);
}


// int modbus_read_input_registers(modbus_t *ctx, int addr, int nb, uint16_t *dest);
// Integer read_input_registers(External, Integer, Integer, Array);
Napi::Value js_read_input_registers(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	int addr = info[1].As<Napi::Number>().Int32Value();
	int nb = info[2].As<Napi::Number>().Int32Value();
	Napi::Array dest_arr = info[3].As<Napi::Array>();
	
	uint16_t dest[nb];
	int ret = modbus_read_input_registers(ctx, addr, nb, dest);
	
	for (int i = 0; i < nb; i++) dest_arr.Set(i, dest[i]);
	
	return Napi::Number::New(info.Env(), ret);
}

// int modbus_report_slave_id(modbus_t *ctx, int max_dest, uint8_t *dest);
// Integer report_slave_id(External, Array, Integer);
Napi::Value js_report_slave_id(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	Napi::Array dest_obj = info[1].As<Napi::Array>();
	int max_dest = info[2].As<Napi::Number>().Int32Value();
	
	uint8_t dest[REPORT_LEN];
    memset(dest, 0, REPORT_LEN * sizeof(uint8_t));
	
	int ret = modbus_report_slave_id(ctx, max_dest, dest);
	
	if (ret > 0) dest_obj.Set(uint32_t(0), uint32_t(dest[0])); // Slave ID
	if (ret > 1) dest_obj.Set(uint32_t(1), uint32_t(dest[1])); // Run Status Indicator
	if (ret > 2) { // Additional data
		for (int i = 2; i < ret; i++) dest_obj.Set(uint32_t(i), uint32_t(dest[i]));
	}
	
	return Napi::Number::New(info.Env(), ret);
}

// int modbus_write_bit(modbus_t *ctx, int addr, int status);
// Integer write_bit(External, Integer, Integer);
Napi::Value js_write_bit(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	int addr = info[1].As<Napi::Number>().Int32Value();
	int status = info[2].As<Napi::Number>().Int32Value();
	
	int ret = modbus_write_bit(ctx, addr, status);
	
	return Napi::Number::New(info.Env(), ret);
}

// int modbus_write_register(modbus_t *ctx, int addr, int value);
// Integer write_register(External, Integer, Integer);
Napi::Value js_write_register(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	int addr = info[1].As<Napi::Number>().Int32Value();
	int value = info[2].As<Napi::Number>().Int32Value();
	
	int ret = modbus_write_register(ctx, addr, value);
	
	return Napi::Number::New(info.Env(), ret);
}

// int modbus_write_bits(modbus_t *ctx, int addr, int nb, const uint8_t *src);
// Integer write_bits(External, Integer, Integer, Array);
Napi::Value js_write_bits(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	int addr = info[1].As<Napi::Number>().Int32Value();
	int nb = info[2].As<Napi::Number>().Int32Value();
	Napi::Array src_arr = info[3].As<Napi::Array>();
	
	uint8_t src[nb];
	for (int i = 0; i < nb; i++) src[i] = src_arr.Get(i).As<Napi::Number>().Uint32Value();
	
	int ret = modbus_write_bits(ctx, addr, nb, src);
	
	return Napi::Number::New(info.Env(), ret);
}

// int modbus_write_registers(modbus_t *ctx, int addr, int nb, const uint16_t *src);
// Integer write_registers(External, Integer, Integer, Array);
Napi::Value js_write_registers(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	int addr = info[1].As<Napi::Number>().Int32Value();
	int nb = info[2].As<Napi::Number>().Int32Value();
	Napi::Array src_arr = info[3].As<Napi::Array>();
	
	uint16_t src[nb];
	for (int i = 0; i < nb; i++) src[i] = src_arr.Get(i).As<Napi::Number>().Uint32Value();
	
	int ret = modbus_write_registers(ctx, addr, nb, src);
	
	return Napi::Number::New(info.Env(), ret);
}

// int modbus_write_and_read_registers(modbus_t *ctx, int write_addr, int write_nb, const uint16_t *src, int read_addr, int read_nb, const uint16_t *dest);
// Integer write_and_read_registers(External, Integer, Integer, Array, Integer, Integer, Array);
Napi::Value js_write_and_read_registers(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	int write_addr = info[1].As<Napi::Number>().Int32Value();
	int write_nb = info[2].As<Napi::Number>().Int32Value();
	Napi::Array src_arr = info[3].As<Napi::Array>();
	int read_addr = info[4].As<Napi::Number>().Int32Value();
	int read_nb = info[5].As<Napi::Number>().Int32Value();
	Napi::Array dest_arr = info[6].As<Napi::Array>();
	
	uint16_t src[write_nb];
	for (int i = 0; i < write_nb; i++) src[i] = src_arr.Get(i).As<Napi::Number>().Uint32Value();
	
	uint16_t dest[read_nb];
	
	int ret = modbus_write_and_read_registers(ctx,
		write_addr, write_nb, src,
		read_addr, read_nb, dest);
	
	for (int i = 0; i < read_nb; i++) dest_arr.Set(uint32_t(i), uint32_t(dest[i]));
	
	return Napi::Number::New(info.Env(), ret);
}

//int modbus_send_raw_request(modbus_t *ctx, uint8_t *raw_req, int raw_req_length);
// Integer send_raw_request(External, Array, Integer);
Napi::Value js_send_raw_request(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	Napi::Array raw_req_arr = info[1].As<Napi::Array>();
	int raw_req_length = info[2].As<Napi::Number>().Int32Value();
	
	uint8_t raw_req[raw_req_length];
	for (int i = 0; i < raw_req_length; i++) raw_req[i] = raw_req_arr.Get(i).As<Napi::Number>().Uint32Value();
	
	int ret = modbus_send_raw_request(ctx, raw_req, raw_req_length);
	
	return Napi::Number::New(info.Env(), ret);
}

// int modbus_receive_confirmation(modbus_t *ctx, uint8_t *rsp);
// Integer receive_confirmation(External, Array);
Napi::Value js_receive_confirmation(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	Napi::Array rsp_arr = info[1].As<Napi::Array>();
	
	uint8_t rsp[MODBUS_TCP_MAX_ADU_LENGTH];
	memset(rsp, 0, MODBUS_TCP_MAX_ADU_LENGTH * sizeof(uint8_t));
	
	int ret = modbus_receive_confirmation(ctx, rsp);
	
	if (ret > 0) {
		for (int i = 0; i < ret; i++) rsp_arr.Set(uint32_t(i), uint32_t(rsp[i]));
	}
	
	return Napi::Number::New(info.Env(), ret);
}

// int modbus_reply_exception(modbus_t *ctx, const uint8_t *req, unsigned int exception_code);
// Integer reply_exception(External, Array, Integer);
Napi::Value js_reply_exception(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	Napi::Array req_arr = info[1].As<Napi::Array>();
	unsigned int exception_code = info[2].As<Napi::Number>().Int32Value();
	
	int req_arr_len = req_arr.Length();
	uint8_t req[req_arr_len];
	for (int i = 0; i < req_arr_len; i++) req[i] = req_arr.Get(i).As<Napi::Number>().Uint32Value();
	
	int ret = modbus_reply_exception(ctx, req, exception_code);
	
	return Napi::Number::New(info.Env(), ret);
}

// modbus_mapping_t *modbus_mapping_new(int nb_bits, int nb_input_bits, int nb_registers, int nb_input_registers);
// External mapping_new(Integer, Integer, Integer, Integer);
Napi::Value js_mapping_new(const Napi::CallbackInfo& info) {
	int nb_bits = info[0].As<Napi::Number>().Int32Value();
	int nb_input_bits = info[1].As<Napi::Number>().Int32Value();
	int nb_registers = info[2].As<Napi::Number>().Int32Value();
	int nb_input_registers = info[3].As<Napi::Number>().Int32Value();
	
	modbus_mapping_t *map = modbus_mapping_new(nb_bits, nb_input_bits, nb_registers, nb_input_registers);
	
	if (map == NULL) {
		return info.Env().Null();
	} else {
		return Napi::External<modbus_mapping_t>::New(info.Env(), map);
	}
}

// void modbus_mapping_free(modbus_mapping_t *mb_mapping);
// Undefined mapping_free(External);
Napi::Value js_mapping_free(const Napi::CallbackInfo& info) {
	modbus_mapping_t *map = static_cast<modbus_mapping_t *>(info[0].As<Napi::External<modbus_mapping_t>>().Data());
	
	modbus_mapping_free(map);
	
	return info.Env().Undefined();
}

// int modbus_receive(modbus_t *ctx, uint8_t *req);
// Integer receive(External, Array);
Napi::Value js_receive(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	Napi::Array req_arr = info[1].As<Napi::Array>();
	
	uint8_t req[MODBUS_TCP_MAX_ADU_LENGTH];
    memset(req, 0, MODBUS_TCP_MAX_ADU_LENGTH * sizeof(uint8_t));
	
	int ret = modbus_receive(ctx, req);
	
	if (ret > 0) {
		for (int i = 0; i < ret; i++) req_arr.Set(uint32_t(i), uint32_t(req[i]));
	}
	
	return Napi::Number::New(info.Env(), ret);
}

// int modbus_reply(modbus_t *ctx, const uint8_t *req, int req_length, modbus_mapping_t *mb_mapping);
// Integer reply(External, Array, Integer, External);
Napi::Value js_reply(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	Napi::Array req_arr = info[1].As<Napi::Array>();
	int req_length = info[2].As<Napi::Number>().Int32Value();
	modbus_mapping_t *mb_mapping = static_cast<modbus_mapping_t *>(info[3].As<Napi::External<modbus_mapping_t>>().Data());
	
	uint8_t req[req_length];
	for (int i = 0; i < req_length; i++) req[i] = req_arr.Get(i).As<Napi::Number>().Uint32Value();
	
	int ret = modbus_reply(ctx, req, req_length, mb_mapping);
	
	return Napi::Number::New(info.Env(), ret);
}

// const char *modbus_strerror(*int errnum);
// String strerror();
Napi::Value js_strerror(const Napi::CallbackInfo& info) {
	const char *ret = modbus_strerror(errno);
	
	return Napi::String::New(info.Env(), ret);
}

// int modbus_tcp_listen(modbus_t *ctx, int nb_connection);
// Integer tcp_listen(External, Integer);
Napi::Value js_tcp_listen(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	int nb_connection = info[1].As<Napi::Number>().Int32Value();
	
	int ret = modbus_tcp_listen(ctx, nb_connection);
	
	return Napi::Number::New(info.Env(), ret);
}

// int modbus_tcp_accept(modbus_t *ctx, int *socket);
// Integer tcp_accept(External, Integer);
Napi::Value js_tcp_accept(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	int socket = info[1].As<Napi::Number>().Int32Value();
	
	int ret = modbus_tcp_accept(ctx, &socket);
	
	return Napi::Number::New(info.Env(), ret);
}

// int modbus_tcp_pi_listen(modbus_t *ctx, int nb_connection);
// Integer tcp_pi_listen(External, Integer);
Napi::Value js_tcp_pi_listen(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	int nb_connection = info[1].As<Napi::Number>().Int32Value();
	
	int ret = modbus_tcp_pi_listen(ctx, nb_connection);
	
	return Napi::Number::New(info.Env(), ret);
}

// int modbus_tcp_pi_accept(modbus_t *ctx, int *socket);
// Integer tcp_pi_accept(External, Integer);
Napi::Value js_tcp_pi_accept(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	int socket = info[1].As<Napi::Number>().Int32Value();
	
	int ret = modbus_tcp_pi_accept(ctx, &socket);
	
	return Napi::Number::New(info.Env(), ret);
}

// convert modbus_mapping_t* to json object
// Undefined map_to_json(External, Object);
Napi::Value map_to_json(const Napi::CallbackInfo& info) {
	modbus_mapping_t *map = static_cast<modbus_mapping_t *>(info[0].As<Napi::External<modbus_mapping_t>>().Data());
	Napi::Object jso = info[1].As<Napi::Object>();
	
	jso.Set("nb_bits", uint32_t(map->nb_bits));
	jso.Set("nb_input_bits", uint32_t(map->nb_input_bits));
	jso.Set("nb_input_registers", uint32_t(map->nb_input_registers));
	jso.Set("nb_registers", uint32_t(map->nb_registers));
	
	Napi::Array tab_bits = Napi::Array::New(info.Env());
	for (int i = 0; i < map->nb_bits; i++) {
		tab_bits.Set(uint32_t(i), uint32_t(map->tab_bits[i]));
	}
	
	Napi::Array tab_input_bits = Napi::Array::New(info.Env());
	for (int i = 0; i < map->nb_input_bits; i++) {
		tab_input_bits.Set(uint32_t(i), uint32_t(map->tab_input_bits[i]));
	}
	
	Napi::Array tab_input_registers = Napi::Array::New(info.Env());
	for (int i = 0; i < map->nb_input_registers; i++) {
		tab_input_registers.Set(uint32_t(i), uint32_t(map->tab_input_registers[i]));
	}
	
	Napi::Array tab_registers = Napi::Array::New(info.Env());
	for (int i = 0; i < map->nb_registers; i++) {
		tab_registers.Set(uint32_t(i), uint32_t(map->tab_registers[i]));
	}
	
	jso.Set("tab_bits", tab_bits);
	jso.Set("tab_input_bits", tab_input_bits);
	jso.Set("tab_input_registers", tab_input_registers);
	jso.Set("tab_registers", tab_registers);
	
	return info.Env().Undefined();
}

// convert json object to modbus_mapping_t*
// Undefined json_to_map(Object, External);
Napi::Value json_to_map(const Napi::CallbackInfo& info) {
	Napi::Object jso = info[0].As<Napi::Object>();
	modbus_mapping_t *map = static_cast<modbus_mapping_t *>(info[1].As<Napi::External<modbus_mapping_t>>().Data());
	
	map->nb_bits = jso.Get("nb_bits").As<Napi::Number>().Int32Value();
	map->nb_input_bits = jso.Get("nb_input_bits").As<Napi::Number>().Int32Value();
	map->nb_input_registers = jso.Get("nb_input_registers").As<Napi::Number>().Int32Value();
	map->nb_registers = jso.Get("nb_registers").As<Napi::Number>().Int32Value();
	
	Napi::Array tab_bits = jso.Get("tab_bits").As<Napi::Array>();
	for (int i = 0; i < map->nb_bits; i++) {
		map->tab_bits[i] = tab_bits.Get(i).As<Napi::Number>().Int32Value();
	}
	
	Napi::Array tab_input_bits = jso.Get("tab_input_bits").As<Napi::Array>();
	for (int i = 0; i < map->nb_input_bits; i++) {
		map->tab_input_bits[i] = tab_input_bits.Get(i).As<Napi::Number>().Int32Value();
	}
	
	Napi::Array tab_input_registers = jso.Get("tab_input_registers").As<Napi::Array>();
	for (int i = 0; i < map->nb_input_registers; i++) {
		map->tab_input_registers[i] = tab_input_registers.Get(i).As<Napi::Number>().Int32Value();
	}
	
	Napi::Array tab_registers = jso.Get("tab_registers").As<Napi::Array>();
	for (int i = 0; i < map->nb_registers; i++) {
		map->tab_registers[i] = tab_registers.Get(i).As<Napi::Number>().Int32Value();
	}
	
	return info.Env().Undefined();
}

// struct tcp_accept_t {
//     modbus_t *ctx;
//     int socket;
//     Napi::FunctionReference cb;
//     int ret;
// };

// void tcp_accept_w(uv_work_t* req) {
//     tcp_accept_t* request = (tcp_accept_t*)req->data;
//     request->ret = modbus_tcp_accept(request->ctx, &(request->socket));
// }

// void tcp_accept_a(uv_work_t* req, int arg) {
//     tcp_accept_t* request = (tcp_accept_t*)req->data;
//     delete req;
	
//     Handle<Value> argv[1];
//     argv[0] = Integer::New(isolate, request->ret);

//     v8::Local<v8::Function> lf = v8::Local<v8::Function>::New(isolate,request->cb);
//     lf->Call(Null(isolate), 1, argv);
	
//     request->cb.Reset();
//     delete request;
// }

// // Undefined tcp_accept_async(External, Integer, Function);
// // callback function - Function(Integer);
// void tcp_accept_async(const Napi::CallbackInfo& info) {
// 	Isolate* isolate = v8::Isolate::GetCurrent();
// 	HandleScope scope(isolate);
// 	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
// 	int socket = info[1].As<Napi::Number>().Int32Value();
// 	Local<Function> cb = Local<Function>::Cast(args[2]);
	
// 	tcp_accept_t* request = new tcp_accept_t;
// 	request->ctx = ctx;
// 	request->socket = socket;
// 	request->cb.Reset(isolate, cb);
	
// 	uv_work_t* req = new uv_work_t();
// 	req->data = request;
	
// 	uv_queue_work(uv_default_loop(), req, tcp_accept_w, tcp_accept_a);
	
// 	args.GetReturnValue().SetUndefined();
// }

// struct receive_t {
//     modbus_t *ctx;
//     uint8_t *req;
//     int len;
//     Persistent<Function> cb;
// };

// void receive_w(uv_work_t* req) {
//     receive_t* request = (receive_t*)req->data;
//     request->len = modbus_receive(request->ctx, request->req);
// }

// void receive_a(uv_work_t* req, int arg) {
//     Isolate* isolate = v8::Isolate::GetCurrent();
//     HandleScope scope(isolate);
//     receive_t* request = (receive_t*)req->data;
//     delete req;
	
// 	int len = request->len;
	
// 	Local<Array> req_arr = Array::New(isolate);
// 	if (len > 0) {
// 		for (int i = 0; i < len; i++) req_arr->Set(i, Number::New(isolate, request->req[i]));
// 	}
	
// 	delete request->req;
	
//     Handle<Value> argv[2];
//     argv[0] = req_arr;
//     argv[1] = Integer::New(isolate, len);
    
//     v8::Local<v8::Function> lf = v8::Local<v8::Function>::New(isolate,request->cb);
//     lf->Call(Null(isolate), 2, argv);
	
//     request->cb.Reset();
//     delete request;
// }

// // Undefined receive_async(External, Function);
// // callback function - Function(Array, Integer);
// void receive_async(const Napi::CallbackInfo& info) {
// 	Isolate* isolate = v8::Isolate::GetCurrent();
// 	HandleScope scope(isolate);
// 	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
// 	Local<Function> cb = Local<Function>::Cast(args[1]);
	
// 	uint8_t *mbreq = new uint8_t[MODBUS_TCP_MAX_ADU_LENGTH];
// 	memset(mbreq, 0, MODBUS_TCP_MAX_ADU_LENGTH * sizeof(uint8_t));
	
// 	receive_t* request = new receive_t;
// 	request->ctx = ctx;
// 	request->req = mbreq;
// 	request->len = 0;
// 	request->cb.Reset(isolate, cb);
	
// 	uv_work_t* req = new uv_work_t();
// 	req->data = request;
	
// 	uv_queue_work(uv_default_loop(), req, receive_w, receive_a);
	
// 	args.GetReturnValue().SetUndefined();
// }

// struct connect_t {
//     modbus_t *ctx;
//     Persistent<Function> cb;
//     int ret;
// };

// void connect_w(uv_work_t* req) {
//     connect_t* request = (connect_t*)req->data;
//     request->ret = modbus_connect(request->ctx);
// }

// void connect_a(uv_work_t* req, int arg) {
//     Isolate* isolate = v8::Isolate::GetCurrent();
//     HandleScope scope(isolate);
//     connect_t* request = (connect_t*)req->data;
//     delete req;
	
//     Handle<Value> argv[1];
//     argv[0] = Integer::New(isolate, request->ret);
    
//     v8::Local<v8::Function> lf = v8::Local<v8::Function>::New(isolate,request->cb);
//     lf->Call(Null(isolate), 1, argv);
	
//     request->cb.Reset();
//     delete request;
// }

class ConnectWorker : public Napi::AsyncWorker {
    public:
        ConnectWorker(Napi::Function& callback, modbus_t * ctx)
        : AsyncWorker(callback), ctx(ctx){}

        ~ConnectWorker() {}
    // This code will be executed on the worker thread
    void Execute() override {
        // Need to simulate cpu heavy task
		modbus_connect(ctx);
    }

    void OnOK() override {
        Napi::HandleScope scope(Env());
        Callback().Call({Env().Null(), Napi::External<modbus_t>::New(Env(), ctx)});
    }

    private:
        modbus_t *ctx;
};

// Undefined connect_async(External, Function);
// callback function - Function(Integer);
Napi::Value connect_async(const Napi::CallbackInfo& info) {
	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	Napi::Function cb = info[1].As<Napi::Function>();
		
	ConnectWorker* wk = new ConnectWorker(cb, ctx);
    wk->Queue();
    return info.Env().Undefined();
}

// // закрыть из треда
// // Undefined close(External);
// void close_mt(const Napi::CallbackInfo& info) {
// 	modbus_t *ctx = static_cast<modbus_t *>(info[0].As<Napi::External<modbus_t>>().Data());
	
// 	modbus_close(ctx);
	
// 	args.GetReturnValue().SetUndefined();
// }

// // Decode HEX value to a float or double
// void hex_decode(const Napi::CallbackInfo& info) {
// 	Isolate* isolate = v8::Isolate::GetCurrent();
// 	HandleScope scope(isolate);
// 	int nArgs = args.Length();

// 	if (nArgs != 2 && nArgs != 4) {
// 		isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Need at least 2 or 4 16-bit numbers")));
// 		return;
// 	}

// 	uint16_t input[nArgs];
// 	for (int i = 0; i < nArgs; i++) {
// 		input[i] = (uint16_t) args[i]->ToInteger()->Value();
// 	}

// 	if (nArgs == 2) {
// 		uint32_t raw_value = (((uint32_t) input[0]) << 16) + input[1];
// 		float output;
// 		memcpy(&output, &raw_value, sizeof(float));
// 		args.GetReturnValue().Set(output);
// 	} else {
// 		uint64_t raw_value = (((uint64_t) input[0]) << 48) + ((uint64_t) input[1] << 32) + ((uint32_t) input[2] << 16) + input[3];
// 		double output;
// 		memcpy(&output, &raw_value, sizeof(double));

// 		args.GetReturnValue().Set(output);
// 	}
// }

Napi::Object Init(Napi::Env env, Napi::Object exports) {
	
	// constants
	exports.Set(Napi::String::New(env,"LIBMODBUS_VERSION_MAJOR"), Napi::Number::New(env, LIBMODBUS_VERSION_MAJOR));
	exports.Set(Napi::String::New(env,"LIBMODBUS_VERSION_MINOR"), Napi::Number::New(env, LIBMODBUS_VERSION_MINOR));
	exports.Set(Napi::String::New(env,"LIBMODBUS_VERSION_MICRO"), Napi::Number::New(env, LIBMODBUS_VERSION_MICRO));
	exports.Set(Napi::String::New(env,"LIBMODBUS_VERSION_STRING"), Napi::String::New(env, LIBMODBUS_VERSION_STRING));
	// //target->exports.Set(Napi::String::New(env,"LIBMODBUS_VERSION_HEX"), New<Number>(LIBMODBUS_VERSION_HEX)); bug in header
	
	exports.Set(Napi::String::New(env,"FALSE"), Napi::Number::New(env,FALSE));
	exports.Set(Napi::String::New(env,"TRUE"), Napi::Number::New(env,TRUE));

	exports.Set(Napi::String::New(env,"OFF"), Napi::Number::New(env,OFF));
	exports.Set(Napi::String::New(env,"ON"), Napi::Number::New(env,ON));

	exports.Set(Napi::String::New(env,"MODBUS_BROADCAST_ADDRESS"), Napi::Number::New(env,MODBUS_BROADCAST_ADDRESS));

	exports.Set(Napi::String::New(env,"MODBUS_MAX_READ_BITS"), Napi::Number::New(env,MODBUS_MAX_READ_BITS));
	exports.Set(Napi::String::New(env,"MODBUS_MAX_WRITE_BITS"), Napi::Number::New(env,MODBUS_MAX_WRITE_BITS));

	exports.Set(Napi::String::New(env,"MODBUS_MAX_READ_REGISTERS"), Napi::Number::New(env,MODBUS_MAX_READ_REGISTERS));
	exports.Set(Napi::String::New(env,"MODBUS_MAX_WRITE_REGISTERS"), Napi::Number::New(env,MODBUS_MAX_WRITE_REGISTERS));
	exports.Set(Napi::String::New(env,"MODBUS_MAX_WR_WRITE_REGISTERS"), Napi::Number::New(env,MODBUS_MAX_WR_WRITE_REGISTERS));

	exports.Set(Napi::String::New(env,"MODBUS_ENOBASE"), Napi::Number::New(env,MODBUS_ENOBASE));

	exports.Set(Napi::String::New(env,"MODBUS_EXCEPTION_ILLEGAL_FUNCTION"), Napi::Number::New(env,MODBUS_EXCEPTION_ILLEGAL_FUNCTION));
	exports.Set(Napi::String::New(env,"MODBUS_EXCEPTION_ILLEGAL_DATA_ADDRESS"), Napi::Number::New(env,MODBUS_EXCEPTION_ILLEGAL_DATA_ADDRESS));
	exports.Set(Napi::String::New(env,"MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE"), Napi::Number::New(env,MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE));
	exports.Set(Napi::String::New(env,"MODBUS_EXCEPTION_SLAVE_OR_SERVER_FAILURE"), Napi::Number::New(env,MODBUS_EXCEPTION_SLAVE_OR_SERVER_FAILURE));
	exports.Set(Napi::String::New(env,"MODBUS_EXCEPTION_ACKNOWLEDGE"), Napi::Number::New(env,MODBUS_EXCEPTION_ACKNOWLEDGE));
	exports.Set(Napi::String::New(env,"MODBUS_EXCEPTION_SLAVE_OR_SERVER_BUSY"), Napi::Number::New(env,MODBUS_EXCEPTION_SLAVE_OR_SERVER_BUSY));
	exports.Set(Napi::String::New(env,"MODBUS_EXCEPTION_NEGATIVE_ACKNOWLEDGE"), Napi::Number::New(env,MODBUS_EXCEPTION_NEGATIVE_ACKNOWLEDGE));
	exports.Set(Napi::String::New(env,"MODBUS_EXCEPTION_MEMORY_PARITY"), Napi::Number::New(env,MODBUS_EXCEPTION_MEMORY_PARITY));
	exports.Set(Napi::String::New(env,"MODBUS_EXCEPTION_NOT_DEFINED"), Napi::Number::New(env,MODBUS_EXCEPTION_NOT_DEFINED));
	exports.Set(Napi::String::New(env,"MODBUS_EXCEPTION_GATEWAY_PATH"), Napi::Number::New(env,MODBUS_EXCEPTION_GATEWAY_PATH));
	exports.Set(Napi::String::New(env,"MODBUS_EXCEPTION_GATEWAY_TARGET"), Napi::Number::New(env,MODBUS_EXCEPTION_GATEWAY_TARGET));
	exports.Set(Napi::String::New(env,"MODBUS_EXCEPTION_MAX"), Napi::Number::New(env,MODBUS_EXCEPTION_MAX));

	exports.Set(Napi::String::New(env,"EMBXILFUN"), Napi::Number::New(env,EMBXILFUN));
	exports.Set(Napi::String::New(env,"EMBXILADD"), Napi::Number::New(env,EMBXILADD));
	exports.Set(Napi::String::New(env,"EMBXILVAL"), Napi::Number::New(env,EMBXILVAL));
	exports.Set(Napi::String::New(env,"EMBXSFAIL"), Napi::Number::New(env,EMBXSFAIL));
	exports.Set(Napi::String::New(env,"EMBXACK"), Napi::Number::New(env,EMBXACK));
	exports.Set(Napi::String::New(env,"EMBXSBUSY"), Napi::Number::New(env,EMBXSBUSY));
	exports.Set(Napi::String::New(env,"EMBXNACK"), Napi::Number::New(env,EMBXNACK));
	exports.Set(Napi::String::New(env,"EMBXMEMPAR"), Napi::Number::New(env,EMBXMEMPAR));
	exports.Set(Napi::String::New(env,"EMBXGPATH"), Napi::Number::New(env,EMBXGPATH));
	exports.Set(Napi::String::New(env,"EMBXGTAR"), Napi::Number::New(env,EMBXGTAR));

	exports.Set(Napi::String::New(env,"EMBBADCRC"), Napi::Number::New(env,EMBBADCRC));
	exports.Set(Napi::String::New(env,"EMBBADDATA"), Napi::Number::New(env,EMBBADDATA));
	exports.Set(Napi::String::New(env,"EMBBADEXC"), Napi::Number::New(env,EMBBADEXC));
	exports.Set(Napi::String::New(env,"EMBUNKEXC"), Napi::Number::New(env,EMBUNKEXC));
	exports.Set(Napi::String::New(env,"EMBMDATA"), Napi::Number::New(env,EMBMDATA));

	exports.Set(Napi::String::New(env,"MODBUS_ERROR_RECOVERY_NONE"), Napi::Number::New(env,MODBUS_ERROR_RECOVERY_NONE));
	exports.Set(Napi::String::New(env,"MODBUS_ERROR_RECOVERY_LINK"), Napi::Number::New(env,MODBUS_ERROR_RECOVERY_LINK));
	exports.Set(Napi::String::New(env,"MODBUS_ERROR_RECOVERY_PROTOCOL"), Napi::Number::New(env,MODBUS_ERROR_RECOVERY_PROTOCOL));

	exports.Set(Napi::String::New(env,"MODBUS_RTU_MAX_ADU_LENGTH"), Napi::Number::New(env,MODBUS_RTU_MAX_ADU_LENGTH));
	exports.Set(Napi::String::New(env,"MODBUS_RTU_RS232"), Napi::Number::New(env,MODBUS_RTU_RS232));
	exports.Set(Napi::String::New(env,"MODBUS_RTU_RS485"), Napi::Number::New(env,MODBUS_RTU_RS485));

	exports.Set(Napi::String::New(env,"MODBUS_TCP_DEFAULT_PORT"), Napi::Number::New(env,MODBUS_TCP_DEFAULT_PORT));
	exports.Set(Napi::String::New(env,"MODBUS_TCP_SLAVE"), Napi::Number::New(env,MODBUS_TCP_SLAVE));
	exports.Set(Napi::String::New(env,"MODBUS_TCP_MAX_ADU_LENGTH"), Napi::Number::New(env,MODBUS_TCP_MAX_ADU_LENGTH));

	// Functions
	exports.Set(Napi::String::New(env, "new_rtu"), Napi::Function::New(env,js_new_rtu));
	exports.Set(Napi::String::New(env, "rtu_get_serial_mode"), Napi::Function::New(env,js_rtu_get_serial_mode));
	exports.Set(Napi::String::New(env, "rtu_set_serial_mode"), Napi::Function::New(env,js_rtu_set_serial_mode));
	exports.Set(Napi::String::New(env, "rtu_get_rts"), Napi::Function::New(env,js_rtu_get_rts));
	exports.Set(Napi::String::New(env, "rtu_set_rts"), Napi::Function::New(env,js_rtu_set_rts));

	exports.Set(Napi::String::New(env,"new_tcp"), Napi::Function::New(env,js_new_tcp));
	exports.Set(Napi::String::New(env,"new_tcp_pi"), Napi::Function::New(env,js_new_tcp_pi));

	exports.Set(Napi::String::New(env,"free"), Napi::Function::New(env,js_free));

	exports.Set(Napi::String::New(env,"get_byte_timeout"), Napi::Function::New(env,js_get_byte_timeout));
	exports.Set(Napi::String::New(env,"set_byte_timeout"), Napi::Function::New(env,js_set_byte_timeout));
	exports.Set(Napi::String::New(env,"set_debug"), Napi::Function::New(env,js_set_debug));
	exports.Set(Napi::String::New(env,"set_error_recovery"), Napi::Function::New(env,js_set_error_recovery));
	exports.Set(Napi::String::New(env,"get_header_length"), Napi::Function::New(env,js_get_header_length));
	exports.Set(Napi::String::New(env,"get_response_timeout"), Napi::Function::New(env,js_get_response_timeout));
	exports.Set(Napi::String::New(env,"set_response_timeout"), Napi::Function::New(env,js_set_response_timeout));
	exports.Set(Napi::String::New(env,"set_slave"), Napi::Function::New(env,js_set_slave));
	exports.Set(Napi::String::New(env,"set_socket"), Napi::Function::New(env,js_set_socket));
	exports.Set(Napi::String::New(env,"get_socket"), Napi::Function::New(env,js_get_socket));

	exports.Set(Napi::String::New(env,"connect"), Napi::Function::New(env,js_connect));
	exports.Set(Napi::String::New(env,"close"), Napi::Function::New(env,js_close));
	exports.Set(Napi::String::New(env,"flush"), Napi::Function::New(env,js_flush));

	exports.Set(Napi::String::New(env,"read_bits"), Napi::Function::New(env,js_read_bits));
	exports.Set(Napi::String::New(env,"read_input_bits"), Napi::Function::New(env,js_read_input_bits));
	exports.Set(Napi::String::New(env,"read_registers"), Napi::Function::New(env,js_read_registers));
	exports.Set(Napi::String::New(env,"read_input_registers"), Napi::Function::New(env,js_read_input_registers));
	exports.Set(Napi::String::New(env,"report_slave_id"), Napi::Function::New(env,js_report_slave_id));
	exports.Set(Napi::String::New(env,"write_bit"), Napi::Function::New(env,js_write_bit));
	exports.Set(Napi::String::New(env,"write_register"), Napi::Function::New(env,js_write_register));
	exports.Set(Napi::String::New(env,"write_bits"), Napi::Function::New(env,js_write_bits));
	exports.Set(Napi::String::New(env,"write_registers"), Napi::Function::New(env,js_write_registers));
	exports.Set(Napi::String::New(env,"write_and_read_registers"), Napi::Function::New(env,js_write_and_read_registers));
	exports.Set(Napi::String::New(env,"send_raw_request"), Napi::Function::New(env,js_send_raw_request));
	exports.Set(Napi::String::New(env,"receive_confirmation"), Napi::Function::New(env,js_receive_confirmation));
	exports.Set(Napi::String::New(env,"reply_exception"), Napi::Function::New(env,js_reply_exception));

	exports.Set(Napi::String::New(env,"mapping_new"), Napi::Function::New(env,js_mapping_new));
	exports.Set(Napi::String::New(env,"mapping_free"), Napi::Function::New(env,js_mapping_free));
	exports.Set(Napi::String::New(env,"receive"), Napi::Function::New(env,js_receive));
	exports.Set(Napi::String::New(env,"reply"), Napi::Function::New(env,js_reply));

	exports.Set(Napi::String::New(env,"strerror"), Napi::Function::New(env,js_strerror));

	exports.Set(Napi::String::New(env,"tcp_listen"), Napi::Function::New(env,js_tcp_listen));
	exports.Set(Napi::String::New(env,"tcp_accept"), Napi::Function::New(env,js_tcp_accept));
	exports.Set(Napi::String::New(env,"tcp_pi_listen"), Napi::Function::New(env,js_tcp_pi_listen));
	exports.Set(Napi::String::New(env,"tcp_pi_accept"), Napi::Function::New(env,js_tcp_pi_accept));
	
	// my functions
	exports.Set(Napi::String::New(env,"map_to_json"), Napi::Function::New(env,map_to_json));
	exports.Set(Napi::String::New(env,"json_to_map"), Napi::Function::New(env,json_to_map));

	// exports.Set(Napi::String::New(env,"tcp_accept_async"), Napi::Function::New(env,tcp_accept_async));
	// exports.Set(Napi::String::New(env,"receive_async"), Napi::Function::New(env,receive_async));
	exports.Set(Napi::String::New(env,"connect_async"), Napi::Function::New(env,connect_async));
	// exports.Set(Napi::String::New(env,"close_mt"), Napi::Function::New(env,close_mt));

	// // HEX Decoding stuff
	// exports.Set(Napi::String::New(env,"hex_decode", v8::String::kInternalizedString), Napi::Function::New(env,hex_decode));
	return exports;
}

NODE_API_MODULE(modbus_binding, Init)
