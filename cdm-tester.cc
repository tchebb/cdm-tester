#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "content_decryption_module.h"

using namespace std;

string the_session;

class MyFuncs : public cdm::Host_11 {
  virtual cdm::Buffer *Allocate(uint32_t capacity) { return nullptr; };

  virtual void SetTimer(int64_t delay_ms, void *context) {};

  virtual cdm::Time GetCurrentWallTime() {
    cout << "GetCurrentWallTime" << endl;
    return time(0);
  };

  virtual void OnInitialized(bool success) {
    cout << "OnInitialized, success = " << success
         << ", thread = " << this_thread::get_id() << endl;
  };

  virtual void OnResolveKeyStatusPromise(uint32_t promise_id,
                                         cdm::KeyStatus key_status) {
    cout << "Key status " << promise_id << " resolved, status = " << key_status
         << ", thread = " << this_thread::get_id() << endl;
  }

  virtual void OnResolveNewSessionPromise(uint32_t promise_id,
                                          const char *session_id,
                                          uint32_t session_id_size) {
    string id(session_id, session_id_size);
    cout << "Session " << promise_id << " resolved, id = " << id
         << ", thread = " << this_thread::get_id() << endl;
    the_session = id;
  }

  virtual void OnResolvePromise(uint32_t promise_id) {
    cout << "Promise " << promise_id
         << " resolved, thread = " << this_thread::get_id() << endl;
  }

  virtual void OnRejectPromise(uint32_t promise_id, cdm::Exception exception,
                               uint32_t system_code, const char *error_message,
                               uint32_t error_message_size) {
    string err(error_message, error_message_size);
    cout << "Promise " << promise_id << " rejected, exc = " << exception << ", "
         << system_code << ":" << err << ", thread = " << this_thread::get_id()
         << endl;
  }

  virtual void OnSessionMessage(const char *session_id,
                                uint32_t session_id_size,
                                cdm::MessageType message_type,
                                const char *message, uint32_t message_size) {
    string id(session_id, session_id_size);
    vector<uint8_t> msg;
    msg.assign(message, message + message_size);

    cout << "Message for " << id << ", type = " << message_type << ", data = ";

    ios state(nullptr);
    state.copyfmt(cout);

    cout << hex << setfill('0');
    for (auto b : msg)
      cout << setw(2) << (int)b;

    cout.copyfmt(state);
    cout << endl;
  }

  virtual void OnSessionKeysChange(const char *session_id,
                                   uint32_t session_id_size,
                                   bool has_additional_usable_key,
                                   const cdm::KeyInformation *keys_info,
                                   uint32_t keys_info_count) {};

  virtual void OnExpirationChange(const char *session_id,
                                  uint32_t session_id_size,
                                  cdm::Time new_expiry_time) {};

  virtual void OnSessionClosed(const char *session_id,
                               uint32_t session_id_size) {};

  virtual void SendPlatformChallenge(const char *service_id,
                                     uint32_t service_id_size,
                                     const char *challenge,
                                     uint32_t challenge_size) {};

  virtual void EnableOutputProtection(uint32_t desired_protection_mask) {};

  virtual void QueryOutputProtectionStatus() {};

  virtual void OnDeferredInitializationDone(cdm::StreamType stream_type,
                                            cdm::Status decoder_status) {};

  virtual cdm::FileIO *CreateFileIO(cdm::FileIOClient *client) {
    return nullptr;
  };

  virtual void RequestStorageId(uint32_t version) {};

  virtual void ReportMetrics(cdm::MetricName metric_name, uint64_t value) {};
};

void *get_host(int host_interface_version, void *user_data) {
  if (host_interface_version != 11) {
    cerr << "Wrong host interface version " << host_interface_version << endl;
    return nullptr;
  }

  return user_data;
}

int main() {
  string key_system("com.widevine.alpha");
  cout << "Main thread: " << this_thread::get_id() << endl;

  InitializeCdmModule_4();

  MyFuncs host;
  cdm::ContentDecryptionModule_11 *cdm =
      static_cast<decltype(cdm)>(CreateCdmInstance(
          11, key_system.c_str(), key_system.length(), get_host, &host));
  cout << "Created CDM: " << cdm << endl;

  cdm->Initialize(false, false, false);

  uint8_t pssh_wv[] = {
      0x00, 0x00, 0x00, 0x3e, 0x70, 0x73, 0x73, 0x68, 0x00, 0x00, 0x00, 0x00,
      0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce, 0xa3, 0xc8, 0x27, 0xdc,
      0xd5, 0x1d, 0x21, 0xed, 0x00, 0x00, 0x00, 0x1e, 0x22, 0x16, 0x73, 0x68,
      0x61, 0x6b, 0x61, 0x5f, 0x63, 0x65, 0x63, 0x32, 0x66, 0x36, 0x34, 0x61,
      0x61, 0x37, 0x38, 0x39, 0x30, 0x61, 0x31, 0x31, 0x48, 0xe3, 0xdc, 0x95,
      0x9b, 0x06
  };

  cdm->CreateSessionAndGenerateRequest(100, cdm::SessionType::kTemporary,
                                       cdm::InitDataType::kCenc, pssh_wv,
                                       sizeof(pssh_wv));

  cdm->RemoveSession(110, the_session.c_str(), the_session.length());
  cdm->CloseSession(120, the_session.c_str(), the_session.length());

  cdm->Destroy();

  DeinitializeCdmModule();
  return 0;
}
