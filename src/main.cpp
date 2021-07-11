
#include <v8.h>
#include <node.h>
#include <node_version.h>
#include <uv.h>
#include <modbus.h>
#include <string.h>
#include <errno.h>
#include <unistd.h> 
#include <sys/socket.h>
#include <nan.h>

#include <iostream>

// using namespace v8;
using namespace node;
using namespace std;
using namespace Nan;
using v8::FunctionTemplate;

// finger to the sky
#define REPORT_LEN 0xFF

#if (NODE_MODULE_VERSION < 12)

#define TO_EXTERNAL(sb) \
    External::Wrap(sb)
#define FROM_EXTERNAL(sb) \
    External::Unwrap(sb)

#else

#define TO_EXTERNAL(sb) \
    Nan::New<External>(sb)
#define FROM_EXTERNAL(sb) \
    External::Cast(*sb)->Value()

#endif

// modbus_t *modbus_new_rtu(const char *device, int baud, char parity, int data_bit, int stop_bit);
// External new_rtu(String, Integer, String, Integer, Integer);
NAN_METHOD(js_new_rtu) {
	v8::Local<v8::String> device = info[0].As<v8::String>();
	int baud = Nan::To<int>(info[1]).FromJust();
	v8::Local<v8::String> parity_str = info[2].As<v8::String>();
	int data_bit = Nan::To<int>(info[3]).FromJust();
	int stop_bit = Nan::To<int>(info[4]).FromJust();
	Nan::Utf8String par(parity_str);
	Nan::Utf8String dev(device);
	
	char parity = (*par)[0];
	
	modbus_t *ctx = modbus_new_rtu(*dev, baud, parity, data_bit, stop_bit);
	
	if (ctx == NULL) {
		info.GetReturnValue().SetNull();
	} else {
		info.GetReturnValue().Set(New<v8::External>(ctx));
	}
}

// // int modbus_rtu_get_serial_mode(modbus_t *ctx);
// // Integer rtu_get_serial_mode(External);
// void js_rtu_get_serial_mode(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
	
// 	int ret = modbus_rtu_get_serial_mode(ctx);
	
// 	args.GetReturnValue().Set(ret);
// }

// // int modbus_rtu_set_serial_mode(modbus_t *ctx, int mode);
// // Integer rtu_set_serial_mode(External, Integer);
// void js_rtu_set_serial_mode(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	int mode = Local<Integer>::Cast(args[1])->Int32Value();
	
// 	int ret = modbus_rtu_set_serial_mode(ctx, mode);
	
// 	args.GetReturnValue().Set(ret);
// }

// // int modbus_rtu_get_rts(modbus_t *ctx);
// void js_rtu_get_rts(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
	
// 	int ret = modbus_rtu_get_rts(ctx);
	
// 	args.GetReturnValue().Set(ret);
// }

// // int modbus_rtu_set_rts(modbus_t *ctx, int mode)
// void js_rtu_set_rts(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	int mode = Local<Integer>::Cast(args[1])->Int32Value();
	
// 	int ret = modbus_rtu_set_rts(ctx, mode);
	
// 	args.GetReturnValue().Set(ret);
// }

// // modbus_t *modbus_new_tcp(const char *ip, int port);
// // External new_tcp(String, Integer);
// void js_new_tcp(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	String::Utf8Value ip(args[0]);
// 	int port = Local<Integer>::Cast(args[1])->Int32Value();
	
// 	modbus_t *ctx = modbus_new_tcp(*ip, port);
	
// 	if (ctx == NULL) {
// 		args.GetReturnValue().SetNull();
// 	} else {
// 		args.GetReturnValue().Set(TO_EXTERNAL(ctx));
// 	}
// }

// // modbus_t *modbus_new_tcp_pi(const char *node, const char *service);
// // External new_tcp_pi(String, String);
// void js_new_tcp_pi(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	String::Utf8Value node(args[0]);
// 	String::Utf8Value service(args[1]);
	
// 	modbus_t *ctx = modbus_new_tcp_pi(*node, *service);
	
// 	if (ctx == NULL) {
// 		args.GetReturnValue().SetNull();
// 	} else {
// 		args.GetReturnValue().Set(TO_EXTERNAL(ctx));
// 	}
// }

// // void modbus_free(modbus_t *ctx);
// // Undefined free(External);
// void js_free(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
	
// 	modbus_free(ctx);
	
// 	args.GetReturnValue().SetUndefined();
// }

// // void modbus_get_byte_timeout(modbus_t *ctx, struct timeval *timeout);
// // Undefined get_byte_timeout(External, Object);
// void js_get_byte_timeout(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	Isolate* isolate = v8::Isolate::GetCurrent();
// 	HandleScope scope(isolate);
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	Local<Object> timeout_obj = Local<Object>::Cast(args[1]);
	

// 	uint32_t sec = 0;
// 	uint32_t usec = 0;

// 	modbus_get_byte_timeout(ctx, &sec, &usec);

// 	struct timeval timeout;
// 	timeout.tv_sec = sec;
// 	timeout.tv_usec = usec;
	
// 	timeout_obj->Set(String::NewFromUtf8(isolate, "tv_sec"), Uint32::New(isolate, timeout.tv_sec));
// 	timeout_obj->Set(String::NewFromUtf8(isolate, "tv_usec"), Uint32::New(isolate, timeout.tv_usec));
	
// 	args.GetReturnValue().SetUndefined();
// }

// // void modbus_set_byte_timeout(modbus_t *ctx, struct timeval *timeout);
// // Undefined set_byte_timeout(External, Object);
// void js_set_byte_timeout(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	Isolate* isolate = v8::Isolate::GetCurrent();
// 	HandleScope scope(isolate);
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	Local<Object> timeout_obj = Local<Object>::Cast(args[1]);
	
// 	struct timeval timeout;
// 	timeout.tv_sec = timeout_obj->Get(String::NewFromUtf8(isolate, "tv_sec"))->Uint32Value();
// 	timeout.tv_usec = timeout_obj->Get(String::NewFromUtf8(isolate, "tv_usec"))->Uint32Value();

// 	modbus_set_byte_timeout(ctx, timeout.tv_sec, timeout.tv_usec);
	
// 	args.GetReturnValue().SetUndefined();
// }

// // void modbus_set_debug(modbus_t *ctx, int boolean);
// // Undefined set_debug(External, Integer);
// void js_set_debug(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	int boolean = Local<Integer>::Cast(args[1])->Int32Value();
	
// 	modbus_set_debug(ctx, boolean);
	
// 	args.GetReturnValue().SetUndefined();
// }

// // int modbus_set_error_recovery(modbus_t *ctx, modbus_error_recovery_mode error_recovery);
// // Integer set_error_recovery(External, Integer);
// void js_set_error_recovery(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	int error_recovery = Local<Integer>::Cast(args[1])->Int32Value();
	
// 	int ret = modbus_set_error_recovery(ctx, static_cast<modbus_error_recovery_mode>(error_recovery));
	
// 	args.GetReturnValue().Set(ret);
// }

// // int modbus_get_header_length(modbus_t *ctx);
// // Integer get_header_length(External);
// void js_get_header_length(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
	
// 	int ret = modbus_get_header_length(ctx);
	
// 	args.GetReturnValue().Set(ret);
// }

// // void modbus_get_response_timeout(modbus_t *ctx, struct timeval *timeout);
// // Undefined get_response_timeout(External, Object);
// void js_get_response_timeout(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	Isolate* isolate = v8::Isolate::GetCurrent();
// 	HandleScope scope(isolate);
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	Local<Object> timeout_obj = Local<Object>::Cast(args[1]);
	
// 	uint32_t sec = 0;
// 	uint32_t usec = 0;

// 	modbus_get_response_timeout(ctx, &sec, &usec);

// 	struct timeval timeout;
// 	timeout.tv_sec = sec;
// 	timeout.tv_usec = usec;
	
// 	timeout_obj->Set(String::NewFromUtf8(isolate, "tv_sec"), Uint32::New(isolate, timeout.tv_sec));
// 	timeout_obj->Set(String::NewFromUtf8(isolate, "tv_usec"), Uint32::New(isolate, timeout.tv_usec));
	
// 	args.GetReturnValue().SetUndefined();
// }

// // void modbus_set_response_timeout(modbus_t *ctx, struct timeval *timeout);
// // Undefined set_response_timeout(External, Object);
// void js_set_response_timeout(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	Isolate* isolate = v8::Isolate::GetCurrent();
// 	HandleScope scope(isolate);
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	Local<Object> timeout_obj = Local<Object>::Cast(args[1]);
	
// 	struct timeval timeout;
// 	timeout.tv_sec = timeout_obj->Get(String::NewFromUtf8(isolate, "tv_sec"))->Uint32Value();
// 	timeout.tv_usec = timeout_obj->Get(String::NewFromUtf8(isolate, "tv_usec"))->Uint32Value();
// 	modbus_set_response_timeout(ctx, timeout.tv_sec, timeout.tv_usec);
	
// 	args.GetReturnValue().SetUndefined();
// }

// // int modbus_set_slave(modbus_t *ctx, int slave);
// // Integer set_slave(External, Integer);
// void js_set_slave(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	int slave = Local<Integer>::Cast(args[1])->Int32Value();
	
// 	int ret = modbus_set_slave(ctx, slave);
	
// 	args.GetReturnValue().Set(ret);
// }

// // void modbus_set_socket(modbus_t *ctx, int socket);
// // Undefined set_socket(External, Integer);
// void js_set_socket(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	int socket = Local<Integer>::Cast(args[1])->Int32Value();
	
// 	modbus_set_socket(ctx, socket);
	
// 	args.GetReturnValue().SetUndefined();
// }

// // int modbus_get_socket(modbus_t *ctx);
// // Integer get_socket(External);
// void js_get_socket(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
	
// 	int ret = modbus_get_socket(ctx);
	
// 	args.GetReturnValue().Set(ret);
// }

// // in js module
// // void modbus_set_bits_from_byte(uint8_t *dest, int index, const uint8_t value);
// // void modbus_set_bits_from_bytes(uint8_t *dest, int index, unsigned int nb_bits, const uint8_t *tab_byte);
// // uint8_t modbus_get_byte_from_bits(const uint8_t *src, int index, unsigned int nb_bits);
// // float modbus_get_float(const uint16_t *src);
// // void modbus_set_float(float f, uint16_t *dest);

// // int modbus_connect(modbus_t *ctx);
// // Integer connect(External);
// void js_connect(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
	
// 	int ret = modbus_connect(ctx);
	
// 	args.GetReturnValue().Set(ret);
// }

// // void modbus_close(modbus_t *ctx);
// // Undefined close(External);
// void js_close(const v8::FunctionCallbackInfo<v8::Value>& args) {

// 	args.GetReturnValue().Set(ret);
// }

// // in js module
// // void modbus_set_bits_from_byte(uint8_t *dest, int index, const uint8_t value);
// // void modbus_set_bits_from_bytes(uint8_t *dest, int index, unsigned int nb_bits, const uint8_t *tab_byte);
// // uint8_t modbus_get_byte_from_bits(const uint8_t *src, int index, unsigned int nb_bits);
// // float modbus_get_float(const uint16_t *src);
// // void modbus_set_float(float f, uint16_t *dest);

// // int modbus_connect(modbus_t *ctx);
// // Integer connect(External);
// void js_connect(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
	
// 	int ret = modbus_connect(ctx);
	
// 	args.GetReturnValue().Set(ret);
// }
// 	int ret = modbus_read_registers(ctx, addr, nb, dest);
	
// 	for (int i = 0; i < nb; i++) dest_arr->Set(i, Number::New(isolate, dest[i]));
	
// 	args.GetReturnValue().Set(ret);
// }

// // int modbus_read_input_registers(modbus_t *ctx, int addr, int nb, uint16_t *dest);
// // Integer read_input_registers(External, Integer, Integer, Array);
// void js_read_input_registers(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	Isolate* isolate = v8::Isolate::GetCurrent();
// 	HandleScope scope(isolate);
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	int addr = Local<Integer>::Cast(args[1])->Int32Value();
// 	int nb = Local<Integer>::Cast(args[2])->Int32Value();
// 	Local<Array> dest_arr = Local<Array>::Cast(args[3]);
	
// 	uint16_t dest[nb];
// 	int ret = modbus_read_input_registers(ctx, addr, nb, dest);
	
// 	for (int i = 0; i < nb; i++) dest_arr->Set(i, Number::New(isolate, dest[i]));
	
// 	args.GetReturnValue().Set(ret);
// }

// // int modbus_report_slave_id(modbus_t *ctx, int max_dest, uint8_t *dest);
// // Integer report_slave_id(External, Array, Integer);
// void js_report_slave_id(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	Isolate* isolate = v8::Isolate::GetCurrent();
// 	HandleScope scope(isolate);
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	Local<Array> dest_obj = Local<Array>::Cast(args[1]);
// 	int max_dest = Local<Integer>::Cast(args[2])->Int32Value();
	
// 	uint8_t dest[REPORT_LEN];
//     memset(dest, 0, REPORT_LEN * sizeof(uint8_t));
	
// 	int ret = modbus_report_slave_id(ctx, max_dest, dest);
	
// 	if (ret > 0) dest_obj->Set(0, Integer::New(isolate, dest[0])); // Slave ID
// 	if (ret > 1) dest_obj->Set(1, Integer::New(isolate, dest[1])); // Run Status Indicator
// 	if (ret > 2) { // Additional data
// 		for (int i = 2; i < ret; i++) dest_obj->Set(i, Integer::New(isolate, dest[i]));
// 	}
	
// 	args.GetReturnValue().Set(ret);
// }

// // int modbus_write_bit(modbus_t *ctx, int addr, int status);
// // Integer write_bit(External, Integer, Integer);
// void js_write_bit(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	int addr = Local<Integer>::Cast(args[1])->Int32Value();
// 	int status = Local<Integer>::Cast(args[2])->Int32Value();
	
// 	int ret = modbus_write_bit(ctx, addr, status);
	
// 	args.GetReturnValue().Set(ret);
// }

// // int modbus_write_register(modbus_t *ctx, int addr, int value);
// // Integer write_register(External, Integer, Integer);
// void js_write_register(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	int addr = Local<Integer>::Cast(args[1])->Int32Value();
// 	int value = Local<Integer>::Cast(args[2])->Int32Value();
	
// 	int ret = modbus_write_register(ctx, addr, value);
	
// 	args.GetReturnValue().Set(ret);
// }

// // int modbus_write_bits(modbus_t *ctx, int addr, int nb, const uint8_t *src);
// // Integer write_bits(External, Integer, Integer, Array);
// void js_write_bits(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	int addr = Local<Integer>::Cast(args[1])->Int32Value();
// 	int nb = Local<Integer>::Cast(args[2])->Int32Value();
// 	Local<Array> src_arr = Local<Array>::Cast(args[3]);
	
// 	uint8_t src[nb];
// 	for (int i = 0; i < nb; i++) src[i] = src_arr->Get(i)->Uint32Value();
	
// 	int ret = modbus_write_bits(ctx, addr, nb, src);
	
// 	args.GetReturnValue().Set(ret);
// }

// // int modbus_write_registers(modbus_t *ctx, int addr, int nb, const uint16_t *src);
// // Integer write_registers(External, Integer, Integer, Array);
// void js_write_registers(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	int addr = Local<Integer>::Cast(args[1])->Int32Value();
// 	int nb = Local<Integer>::Cast(args[2])->Int32Value();
// 	Local<Array> src_arr = Local<Array>::Cast(args[3]);
	
// 	uint16_t src[nb];
// 	for (int i = 0; i < nb; i++) src[i] = src_arr->Get(i)->Uint32Value();
	
// 	int ret = modbus_write_registers(ctx, addr, nb, src);
	
// 	args.GetReturnValue().Set(ret);
// }

// // int modbus_write_and_read_registers(modbus_t *ctx, int write_addr, int write_nb, const uint16_t *src, int read_addr, int read_nb, const uint16_t *dest);
// // Integer write_and_read_registers(External, Integer, Integer, Array, Integer, Integer, Array);
// void js_write_and_read_registers(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	Isolate* isolate = v8::Isolate::GetCurrent();
// 	HandleScope scope(isolate);
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	int write_addr = Local<Integer>::Cast(args[1])->Int32Value();
// 	int write_nb = Local<Integer>::Cast(args[2])->Int32Value();
// 	Local<Array> src_arr = Local<Array>::Cast(args[3]);
// 	int read_addr = Local<Integer>::Cast(args[4])->Int32Value();
// 	int read_nb = Local<Integer>::Cast(args[5])->Int32Value();
// 	Local<Array> dest_arr = Local<Array>::Cast(args[6]);
	
// 	uint16_t src[write_nb];
// 	for (int i = 0; i < write_nb; i++) src[i] = src_arr->Get(i)->Uint32Value();
	
// 	uint16_t dest[read_nb];
	
// 	int ret = modbus_write_and_read_registers(ctx,
// 		write_addr, write_nb, src,
// 		read_addr, read_nb, dest);
	
// 	for (int i = 0; i < read_nb; i++) dest_arr->Set(i, Number::New(isolate, dest[i]));
	
// 	args.GetReturnValue().Set(ret);
// }

// //int modbus_send_raw_request(modbus_t *ctx, uint8_t *raw_req, int raw_req_length);
// // Integer send_raw_request(External, Array, Integer);
// void js_send_raw_request(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	Local<Array> raw_req_arr = Local<Array>::Cast(args[1]);
// 	int raw_req_length = Local<Integer>::Cast(args[2])->Int32Value();
	
// 	uint8_t raw_req[raw_req_length];
// 	for (int i = 0; i < raw_req_length; i++) raw_req[i] = raw_req_arr->Get(i)->Uint32Value();
	
// 	int ret = modbus_send_raw_request(ctx, raw_req, raw_req_length);
	
// 	args.GetReturnValue().Set(ret);
// }

// // int modbus_receive_confirmation(modbus_t *ctx, uint8_t *rsp);
// // Integer receive_confirmation(External, Array);
// void js_receive_confirmation(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	Isolate* isolate = v8::Isolate::GetCurrent();
// 	HandleScope scope(isolate);
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	Local<Array> rsp_arr = Local<Array>::Cast(args[1]);
	
// 	uint8_t rsp[MODBUS_TCP_MAX_ADU_LENGTH];
// 	memset(rsp, 0, MODBUS_TCP_MAX_ADU_LENGTH * sizeof(uint8_t));
	
// 	int ret = modbus_receive_confirmation(ctx, rsp);
	
// 	if (ret > 0) {
// 		for (int i = 0; i < ret; i++) rsp_arr->Set(i, Number::New(isolate, rsp[i]));
// 	}
	
// 	args.GetReturnValue().Set(ret);
// }

// // int modbus_reply_exception(modbus_t *ctx, const uint8_t *req, unsigned int exception_code);
// // Integer reply_exception(External, Array, Integer);
// void js_reply_exception(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	Local<Array> req_arr = Local<Array>::Cast(args[1]);
// 	unsigned int exception_code = Local<Integer>::Cast(args[2])->Int32Value();
	
// 	int req_arr_len = req_arr->InternalFieldCount();
// 	uint8_t req[req_arr_len];
// 	for (int i = 0; i < req_arr_len; i++) req[i] = req_arr->Get(i)->Uint32Value();
	
// 	int ret = modbus_reply_exception(ctx, req, exception_code);
	
// 	args.GetReturnValue().Set(ret);
// }

// // modbus_mapping_t *modbus_mapping_new(int nb_bits, int nb_input_bits, int nb_registers, int nb_input_registers);
// // External mapping_new(Integer, Integer, Integer, Integer);
// void js_mapping_new(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	int nb_bits = Local<Integer>::Cast(args[0])->Int32Value();
// 	int nb_input_bits = Local<Integer>::Cast(args[1])->Int32Value();
// 	int nb_registers = Local<Integer>::Cast(args[2])->Int32Value();
// 	int nb_input_registers = Local<Integer>::Cast(args[3])->Int32Value();
	
// 	modbus_mapping_t *map = modbus_mapping_new(nb_bits, nb_input_bits, nb_registers, nb_input_registers);
	
// 	if (map == NULL) {
// 		args.GetReturnValue().SetNull();
// 	} else {
// 		args.GetReturnValue().Set(TO_EXTERNAL(map));
// 	}
// }

// // void modbus_mapping_free(modbus_mapping_t *mb_mapping);
// // Undefined mapping_free(External);
// void js_mapping_free(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	modbus_mapping_t *map = static_cast<modbus_mapping_t *>(FROM_EXTERNAL(args[0]));
	
// 	modbus_mapping_free(map);
	
// 	args.GetReturnValue().SetUndefined();
// }

// // int modbus_receive(modbus_t *ctx, uint8_t *req);
// // Integer receive(External, Array);
// void js_receive(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	Isolate* isolate = v8::Isolate::GetCurrent();
// 	HandleScope scope(isolate);
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	Local<Array> req_arr = Local<Array>::Cast(args[1]);
	
// 	uint8_t req[MODBUS_TCP_MAX_ADU_LENGTH];
//     memset(req, 0, MODBUS_TCP_MAX_ADU_LENGTH * sizeof(uint8_t));
	
// 	int ret = modbus_receive(ctx, req);
	
// 	if (ret > 0) {
// 		for (int i = 0; i < ret; i++) req_arr->Set(i, Number::New(isolate, req[i]));
// 	}
	
// 	args.GetReturnValue().Set(ret);
// }

// // int modbus_reply(modbus_t *ctx, const uint8_t *req, int req_length, modbus_mapping_t *mb_mapping);
// // Integer reply(External, Array, Integer, External);
// void js_reply(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	Local<Array> req_arr = Local<Array>::Cast(args[1]);
// 	int req_length = Local<Integer>::Cast(args[2])->Int32Value();
// 	modbus_mapping_t *mb_mapping = static_cast<modbus_mapping_t *>(FROM_EXTERNAL(args[3]));
	
// 	uint8_t req[req_length];
// 	for (int i = 0; i < req_length; i++) req[i] = req_arr->Get(i)->Uint32Value();
	
// 	int ret = modbus_reply(ctx, req, req_length, mb_mapping);
	
// 	args.GetReturnValue().Set(ret);
// }

// // const char *modbus_strerror(*int errnum);
// // String strerror();
// void js_strerror(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	Isolate* isolate = v8::Isolate::GetCurrent();
// 	HandleScope scope(isolate);
// 	const char *ret = modbus_strerror(errno);
	
// 	args.GetReturnValue().Set(v8::String::NewFromUtf8(isolate, ret));
// }

// // int modbus_tcp_listen(modbus_t *ctx, int nb_connection);
// // Integer tcp_listen(External, Integer);
// void js_tcp_listen(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	int nb_connection = Local<Integer>::Cast(args[1])->Int32Value();
	
// 	int ret = modbus_tcp_listen(ctx, nb_connection);
	
// 	args.GetReturnValue().Set(ret);
// }

// // int modbus_tcp_accept(modbus_t *ctx, int *socket);
// // Integer tcp_accept(External, Integer);
// void js_tcp_accept(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	int socket = Local<Integer>::Cast(args[1])->Int32Value();
	
// 	int ret = modbus_tcp_accept(ctx, &socket);
	
// 	args.GetReturnValue().Set(ret);
// }

// // int modbus_tcp_pi_listen(modbus_t *ctx, int nb_connection);
// // Integer tcp_pi_listen(External, Integer);
// void js_tcp_pi_listen(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	int nb_connection = Local<Integer>::Cast(args[1])->Int32Value();
	
// 	int ret = modbus_tcp_pi_listen(ctx, nb_connection);
	
// 	args.GetReturnValue().Set(ret);
// }

// // int modbus_tcp_pi_accept(modbus_t *ctx, int *socket);
// // Integer tcp_pi_accept(External, Integer);
// void js_tcp_pi_accept(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	int socket = Local<Integer>::Cast(args[1])->Int32Value();
	
// 	int ret = modbus_tcp_pi_accept(ctx, &socket);
	
// 	args.GetReturnValue().Set(ret);
// }

// // convert modbus_mapping_t* to json object
// // Undefined map_to_json(External, Object);
// void map_to_json(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	Isolate* isolate = v8::Isolate::GetCurrent();
// 	HandleScope scope(isolate);
// 	modbus_mapping_t *map = static_cast<modbus_mapping_t *>(FROM_EXTERNAL(args[0]));
// 	Local<Object> jso = Local<Object>::Cast(args[1]);
	
// 	jso->Set(String::NewFromUtf8(isolate, "nb_bits"), Integer::New(isolate, map->nb_bits));
// 	jso->Set(String::NewFromUtf8(isolate, "nb_input_bits"), Integer::New(isolate, map->nb_input_bits));
// 	jso->Set(String::NewFromUtf8(isolate, "nb_input_registers"), Integer::New(isolate, map->nb_input_registers));
// 	jso->Set(String::NewFromUtf8(isolate, "nb_registers"), Integer::New(isolate, map->nb_registers));
	
// 	Local<Array> tab_bits = Array::New(isolate);
// 	for (int i = 0; i < map->nb_bits; i++) {
// 		tab_bits->Set(i, Integer::New(isolate, map->tab_bits[i]));
// 	}
	
// 	Local<Array> tab_input_bits = Array::New(isolate);
// 	for (int i = 0; i < map->nb_input_bits; i++) {
// 		tab_input_bits->Set(i, Integer::New(isolate, map->tab_input_bits[i]));
// 	}
	
// 	Local<Array> tab_input_registers = Array::New(isolate);
// 	for (int i = 0; i < map->nb_input_registers; i++) {
// 		tab_input_registers->Set(i, Integer::New(isolate, map->tab_input_registers[i]));
// 	}
	
// 	Local<Array> tab_registers = Array::New(isolate);
// 	for (int i = 0; i < map->nb_registers; i++) {
// 		tab_registers->Set(i, Integer::New(isolate, map->tab_registers[i]));
// 	}
	
// 	jso->Set(String::NewFromUtf8(isolate, "tab_bits"), tab_bits);
// 	jso->Set(String::NewFromUtf8(isolate, "tab_input_bits"), tab_input_bits);
// 	jso->Set(String::NewFromUtf8(isolate, "tab_input_registers"), tab_input_registers);
// 	jso->Set(String::NewFromUtf8(isolate, "tab_registers"), tab_registers);
	
// 	args.GetReturnValue().SetUndefined();
// }

// // convert json object to modbus_mapping_t*
// // Undefined json_to_map(Object, External);
// void json_to_map(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	Isolate* isolate = v8::Isolate::GetCurrent();
// 	HandleScope scope(isolate);
// 	Local<Object> jso = Local<Object>::Cast(args[0]);
// 	modbus_mapping_t *map = static_cast<modbus_mapping_t *>(FROM_EXTERNAL(args[1]));
	
// 	map->nb_bits = jso->Get(String::NewFromUtf8(isolate, "nb_bits"))->Int32Value();
// 	map->nb_input_bits = jso->Get(String::NewFromUtf8(isolate, "nb_input_bits"))->Int32Value();
// 	map->nb_input_registers = jso->Get(String::NewFromUtf8(isolate, "nb_input_registers"))->Int32Value();
// 	map->nb_registers = jso->Get(String::NewFromUtf8(isolate, "nb_registers"))->Int32Value();
	
// 	Local<Array> tab_bits = Local<Array>::Cast(jso->Get(String::NewFromUtf8(isolate, "tab_bits")));
// 	for (int i = 0; i < map->nb_bits; i++) {
// 		map->tab_bits[i] = tab_bits->Get(i)->Int32Value();
// 	}
	
// 	Local<Array> tab_input_bits = Local<Array>::Cast(jso->Get(String::NewFromUtf8(isolate, "tab_input_bits")));
// 	for (int i = 0; i < map->nb_input_bits; i++) {
// 		map->tab_input_bits[i] = tab_input_bits->Get(i)->Int32Value();
// 	}
	
// 	Local<Array> tab_input_registers = Local<Array>::Cast(jso->Get(String::NewFromUtf8(isolate, "tab_input_registers")));
// 	for (int i = 0; i < map->nb_input_registers; i++) {
// 		map->tab_input_registers[i] = tab_input_registers->Get(i)->Int32Value();
// 	}
	
// 	Local<Array> tab_registers = Local<Array>::Cast(jso->Get(String::NewFromUtf8(isolate, "tab_registers")));
// 	for (int i = 0; i < map->nb_registers; i++) {
// 		map->tab_registers[i] = tab_registers->Get(i)->Int32Value();
// 	}
	
// 	args.GetReturnValue().SetUndefined();
// }

// struct tcp_accept_t {
//     modbus_t *ctx;
//     int socket;
//     Persistent<Function> cb;
//     int ret;
// };

// void tcp_accept_w(uv_work_t* req) {
//     tcp_accept_t* request = (tcp_accept_t*)req->data;
//     request->ret = modbus_tcp_accept(request->ctx, &(request->socket));
// }

// void tcp_accept_a(uv_work_t* req, int arg) {
//     Isolate* isolate = v8::Isolate::GetCurrent();
//     HandleScope scope(isolate);
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
// void tcp_accept_async(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	Isolate* isolate = v8::Isolate::GetCurrent();
// 	HandleScope scope(isolate);
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	int socket = Local<Integer>::Cast(args[1])->Int32Value();
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
// void receive_async(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	Isolate* isolate = v8::Isolate::GetCurrent();
// 	HandleScope scope(isolate);
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
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

// // Undefined connect_async(External, Function);
// // callback function - Function(Integer);
// void connect_async(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	Isolate* isolate = v8::Isolate::GetCurrent();
// 	HandleScope scope(isolate);
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
// 	Local<Function> cb = Local<Function>::Cast(args[1]);
	
// 	connect_t* request = new connect_t;
// 	request->ctx = ctx;
// 	request->cb.Reset(isolate, cb);
// 	request->ret = 0;
	
// 	uv_work_t* req = new uv_work_t();
// 	req->data = request;
	
// 	uv_queue_work(uv_default_loop(), req, connect_w, connect_a);
	
// 	args.GetReturnValue().SetUndefined();
// }

// // закрыть из треда
// // Undefined close(External);
// void close_mt(const v8::FunctionCallbackInfo<v8::Value>& args) {
// 	modbus_t *ctx = static_cast<modbus_t *>(FROM_EXTERNAL(args[0]));
	
// 	modbus_close(ctx);
	
// 	args.GetReturnValue().SetUndefined();
// }

// // Decode HEX value to a float or double
// void hex_decode(const v8::FunctionCallbackInfo<v8::Value>& args) {
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

NAN_MODULE_INIT(init) {
	
	// constants
	Set(target, New<v8::String>("LIBMODBUS_VERSION_MAJOR").ToLocalChecked(), New<v8::Number>(LIBMODBUS_VERSION_MAJOR));
	// Set(target, New<String>("LIBMODBUS_VERSION_MINOR").ToLocalChecked(), New<Number>(LIBMODBUS_VERSION_MINOR));
	// Set(target, New<String>("LIBMODBUS_VERSION_MICRO").ToLocalChecked(), New<Number>(LIBMODBUS_VERSION_MICRO));
	// Set(target, New<String>("LIBMODBUS_VERSION_STRING").ToLocalChecked(), String::NewFromUtf8(isolate, LIBMODBUS_VERSION_STRING));
	// //target->Set(target, New<String>("LIBMODBUS_VERSION_HEX").ToLocalChecked(), New<Number>(LIBMODBUS_VERSION_HEX)); bug in header
	
	// Set(target, New<String>("FALSE").ToLocalChecked(), New<Number>(FALSE));
	// Set(target, New<String>("TRUE").ToLocalChecked(), New<Number>(TRUE));

	// Set(target, New<String>("OFF").ToLocalChecked(), New<Number>(OFF));
	// Set(target, New<String>("ON").ToLocalChecked(), New<Number>(ON));

	// Set(target, New<String>("MODBUS_BROADCAST_ADDRESS").ToLocalChecked(), New<Number>(MODBUS_BROADCAST_ADDRESS));

	// Set(target, New<String>("MODBUS_MAX_READ_BITS").ToLocalChecked(), New<Number>(MODBUS_MAX_READ_BITS));
	// Set(target, New<String>("MODBUS_MAX_WRITE_BITS").ToLocalChecked(), New<Number>(MODBUS_MAX_WRITE_BITS));

	// Set(target, New<String>("MODBUS_MAX_READ_REGISTERS").ToLocalChecked(), New<Number>(MODBUS_MAX_READ_REGISTERS));
	// Set(target, New<String>("MODBUS_MAX_WRITE_REGISTERS").ToLocalChecked(), New<Number>(MODBUS_MAX_WRITE_REGISTERS));
	// Set(target, New<String>("MODBUS_MAX_WR_WRITE_REGISTERS").ToLocalChecked(), New<Number>(MODBUS_MAX_WR_WRITE_REGISTERS));

	// Set(target, New<String>("MODBUS_ENOBASE").ToLocalChecked(), New<Number>(MODBUS_ENOBASE));

	// Set(target, New<String>("MODBUS_EXCEPTION_ILLEGAL_FUNCTION").ToLocalChecked(), New<Number>(MODBUS_EXCEPTION_ILLEGAL_FUNCTION));
	// Set(target, New<String>("MODBUS_EXCEPTION_ILLEGAL_DATA_ADDRESS").ToLocalChecked(), New<Number>(MODBUS_EXCEPTION_ILLEGAL_DATA_ADDRESS));
	// Set(target, New<String>("MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE").ToLocalChecked(), New<Number>(MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE));
	// Set(target, New<String>("MODBUS_EXCEPTION_SLAVE_OR_SERVER_FAILURE").ToLocalChecked(), New<Number>(MODBUS_EXCEPTION_SLAVE_OR_SERVER_FAILURE));
	// Set(target, New<String>("MODBUS_EXCEPTION_ACKNOWLEDGE").ToLocalChecked(), New<Number>(MODBUS_EXCEPTION_ACKNOWLEDGE));
	// Set(target, New<String>("MODBUS_EXCEPTION_SLAVE_OR_SERVER_BUSY").ToLocalChecked(), New<Number>(MODBUS_EXCEPTION_SLAVE_OR_SERVER_BUSY));
	// Set(target, New<String>("MODBUS_EXCEPTION_NEGATIVE_ACKNOWLEDGE").ToLocalChecked(), New<Number>(MODBUS_EXCEPTION_NEGATIVE_ACKNOWLEDGE));
	// Set(target, New<String>("MODBUS_EXCEPTION_MEMORY_PARITY").ToLocalChecked(), New<Number>(MODBUS_EXCEPTION_MEMORY_PARITY));
	// Set(target, New<String>("MODBUS_EXCEPTION_NOT_DEFINED").ToLocalChecked(), New<Number>(MODBUS_EXCEPTION_NOT_DEFINED));
	// Set(target, New<String>("MODBUS_EXCEPTION_GATEWAY_PATH").ToLocalChecked(), New<Number>(MODBUS_EXCEPTION_GATEWAY_PATH));
	// Set(target, New<String>("MODBUS_EXCEPTION_GATEWAY_TARGET").ToLocalChecked(), New<Number>(MODBUS_EXCEPTION_GATEWAY_TARGET));
	// Set(target, New<String>("MODBUS_EXCEPTION_MAX").ToLocalChecked(), New<Number>(MODBUS_EXCEPTION_MAX));

	// Set(target, New<String>("EMBXILFUN").ToLocalChecked(), New<Number>(EMBXILFUN));
	// Set(target, New<String>("EMBXILADD").ToLocalChecked(), New<Number>(EMBXILADD));
	// Set(target, New<String>("EMBXILVAL").ToLocalChecked(), New<Number>(EMBXILVAL));
	// Set(target, New<String>("EMBXSFAIL").ToLocalChecked(), New<Number>(EMBXSFAIL));
	// Set(target, New<String>("EMBXACK").ToLocalChecked(), New<Number>(EMBXACK));
	// Set(target, New<String>("EMBXSBUSY").ToLocalChecked(), New<Number>(EMBXSBUSY));
	// Set(target, New<String>("EMBXNACK").ToLocalChecked(), New<Number>(EMBXNACK));
	// Set(target, New<String>("EMBXMEMPAR").ToLocalChecked(), New<Number>(EMBXMEMPAR));
	// Set(target, New<String>("EMBXGPATH").ToLocalChecked(), New<Number>(EMBXGPATH));
	// Set(target, New<String>("EMBXGTAR").ToLocalChecked(), New<Number>(EMBXGTAR));

	// Set(target, New<String>("EMBBADCRC").ToLocalChecked(), New<Number>(EMBBADCRC));
	// Set(target, New<String>("EMBBADDATA").ToLocalChecked(), New<Number>(EMBBADDATA));
	// Set(target, New<String>("EMBBADEXC").ToLocalChecked(), New<Number>(EMBBADEXC));
	// Set(target, New<String>("EMBUNKEXC").ToLocalChecked(), New<Number>(EMBUNKEXC));
	// Set(target, New<String>("EMBMDATA").ToLocalChecked(), New<Number>(EMBMDATA));

	// Set(target, New<String>("MODBUS_ERROR_RECOVERY_NONE").ToLocalChecked(), New<Number>(MODBUS_ERROR_RECOVERY_NONE));
	// Set(target, New<String>("MODBUS_ERROR_RECOVERY_LINK").ToLocalChecked(), New<Number>(MODBUS_ERROR_RECOVERY_LINK));
	// Set(target, New<String>("MODBUS_ERROR_RECOVERY_PROTOCOL").ToLocalChecked(), New<Number>(MODBUS_ERROR_RECOVERY_PROTOCOL));

	// Set(target, New<String>("MODBUS_RTU_MAX_ADU_LENGTH").ToLocalChecked(), New<Number>(MODBUS_RTU_MAX_ADU_LENGTH));
	// Set(target, New<String>("MODBUS_RTU_RS232").ToLocalChecked(), New<Number>(MODBUS_RTU_RS232));
	// Set(target, New<String>("MODBUS_RTU_RS485").ToLocalChecked(), New<Number>(MODBUS_RTU_RS485));

	// Set(target, New<String>("MODBUS_TCP_DEFAULT_PORT").ToLocalChecked(), New<Number>(MODBUS_TCP_DEFAULT_PORT));
	// Set(target, New<String>("MODBUS_TCP_SLAVE").ToLocalChecked(), New<Number>(MODBUS_TCP_SLAVE));
	// Set(target, New<String>("MODBUS_TCP_MAX_ADU_LENGTH").ToLocalChecked(), New<Number>(MODBUS_TCP_MAX_ADU_LENGTH));

	// Functions
	Set(target, New<v8::String>("new_rtu").ToLocalChecked(), GetFunction(New<v8::FunctionTemplate>(js_new_rtu)).ToLocalChecked());
	// Set(target, New<String>("rtu_get_serial_mode").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_rtu_get_serial_mode).ToLocalChecked());
	// Set(target, New<String>("rtu_set_serial_mode").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_rtu_set_serial_mode).ToLocalChecked());
	// Set(target, New<String>("rtu_get_rts").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_rtu_get_rts).ToLocalChecked());
	// Set(target, New<String>("rtu_set_rts").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_rtu_set_rts).ToLocalChecked());

	// Set(target, New<String>("new_tcp").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_new_tcp).ToLocalChecked());
	// Set(target, New<String>("new_tcp_pi").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_new_tcp_pi).ToLocalChecked());

	// Set(target, New<String>("free").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_free).ToLocalChecked());

	// Set(target, New<String>("get_byte_timeout").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_get_byte_timeout).ToLocalChecked());
	// Set(target, New<String>("set_byte_timeout").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_set_byte_timeout).ToLocalChecked());
	// Set(target, New<String>("set_debug").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_set_debug).ToLocalChecked());
	// Set(target, New<String>("set_error_recovery").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_set_error_recovery).ToLocalChecked());
	// Set(target, New<String>("get_header_length").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_get_header_length).ToLocalChecked());
	// Set(target, New<String>("get_response_timeout").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_get_response_timeout).ToLocalChecked());
	// Set(target, New<String>("set_response_timeout").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_set_response_timeout).ToLocalChecked());
	// Set(target, New<String>("set_slave").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_set_slave).ToLocalChecked());
	// Set(target, New<String>("set_socket").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_set_socket).ToLocalChecked());
	// Set(target, New<String>("get_socket").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_get_socket).ToLocalChecked());

	// Set(target, New<String>("connect").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_connect).ToLocalChecked());
	// Set(target, New<String>("close").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_close).ToLocalChecked());
	// Set(target, New<String>("flush").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_flush).ToLocalChecked());

	// Set(target, New<String>("read_bits").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_read_bits).ToLocalChecked());
	// Set(target, New<String>("read_input_bits").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_read_input_bits).ToLocalChecked());
	// Set(target, New<String>("read_registers").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_read_registers).ToLocalChecked());
	// Set(target, New<String>("read_input_registers").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_read_input_registers).ToLocalChecked());
	// Set(target, New<String>("report_slave_id").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_report_slave_id).ToLocalChecked());
	// Set(target, New<String>("write_bit").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_write_bit).ToLocalChecked());
	// Set(target, New<String>("write_register").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_write_register).ToLocalChecked());
	// Set(target, New<String>("write_bits").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_write_bits).ToLocalChecked());
	// Set(target, New<String>("write_registers").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_write_registers).ToLocalChecked());
	// Set(target, New<String>("write_and_read_registers").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_write_and_read_registers).ToLocalChecked());
	// Set(target, New<String>("send_raw_request").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_send_raw_request).ToLocalChecked());
	// Set(target, New<String>("receive_confirmation").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_receive_confirmation).ToLocalChecked());
	// Set(target, New<String>("reply_exception").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_reply_exception).ToLocalChecked());

	// Set(target, New<String>("mapping_new").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_mapping_new).ToLocalChecked());
	// Set(target, New<String>("mapping_free").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_mapping_free).ToLocalChecked());
	// Set(target, New<String>("receive").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_receive).ToLocalChecked());
	// Set(target, New<String>("reply").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_reply).ToLocalChecked());

	// Set(target, New<String>("strerror").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_strerror).ToLocalChecked());

	// Set(target, New<String>("tcp_listen").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_tcp_listen).ToLocalChecked());
	// Set(target, New<String>("tcp_accept").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_tcp_accept).ToLocalChecked());
	// Set(target, New<String>("tcp_pi_listen").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_tcp_pi_listen).ToLocalChecked());
	// Set(target, New<String>("tcp_pi_accept").ToLocalChecked(), GetFunction(New<FunctionTemplate>(js_tcp_pi_accept).ToLocalChecked());
	
	// // my functions
	// Set(target, New<String>("map_to_json").ToLocalChecked(), GetFunction(New<FunctionTemplate>(map_to_json).ToLocalChecked());
	// Set(target, New<String>("json_to_map").ToLocalChecked(), GetFunction(New<FunctionTemplate>(json_to_map).ToLocalChecked());

	// Set(target, New<String>("tcp_accept_async").ToLocalChecked(), GetFunction(New<FunctionTemplate>(tcp_accept_async).ToLocalChecked());
	// Set(target, New<String>("receive_async").ToLocalChecked(), GetFunction(New<FunctionTemplate>(receive_async).ToLocalChecked());
	// Set(target, New<String>("connect_async").ToLocalChecked(), GetFunction(New<FunctionTemplate>(connect_async).ToLocalChecked());
	// Set(target, New<String>("close_mt").ToLocalChecked(), GetFunction(New<FunctionTemplate>(close_mt).ToLocalChecked());

	// // HEX Decoding stuff
	// Set(target, New<String>("hex_decode", v8::String::kInternalizedString).ToLocalChecked(), GetFunction(New<FunctionTemplate>(hex_decode).ToLocalChecked());
}

NODE_MODULE(modbus_binding, init)
