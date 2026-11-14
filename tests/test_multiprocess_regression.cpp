// Adapter Fabric — multiprocess regression checks against this build's
// af_coordinator. Workers and control clients are fake peers on raw framed TCP
// connections, so each check controls exactly what the coordinator receives.
// This process only connects; it never listens.
//
// No check depends on a time window: a connection's close is followed by a
// barrier (half-close, then read until the coordinator closes its end, which
// it does after handling the close) or by polling the coordinator's snapshot
// for the state the close must produce, without a time limit.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "test.hpp"
#include "fixtures.hpp"
#include "adapter_fabric/authority.hpp"
#include "adapter_fabric/checksum.hpp"
#include "adapter_fabric/persistence.hpp"
#include "adapter_fabric/protocol.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <algorithm>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

using namespace adapter_fabric;
namespace fx = af_test_fixture;

namespace {

void net_init() {
  static const bool done = [] { WSADATA d; return WSAStartup(MAKEWORD(2, 2), &d) == 0; }();
  (void)done;
}

// A client connection speaking the coordinator's frame format:
// [4-byte length][payload][8-byte FNV-1a checksum of payload].
class Conn {
 public:
  Conn() = default;
  Conn(const Conn&) = delete;
  Conn& operator=(const Conn&) = delete;
  ~Conn() { close(); }

  bool connect(std::uint16_t port) {
    net_init();
    close();
    SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return false;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (::connect(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) { closesocket(s); return false; }
    s_ = s;
    return true;
  }

  bool send_frame(const std::vector<std::uint8_t>& p) {
    std::lock_guard<std::mutex> lk(write_);
    std::uint8_t hdr[4];
    const auto n = static_cast<std::uint32_t>(p.size());
    for (int i = 0; i < 4; ++i) hdr[i] = static_cast<std::uint8_t>((n >> (8 * i)) & 0xFF);
    const std::uint64_t h = fnv1a_64(1469598103934665603ULL, p.data(), p.size());
    std::uint8_t ck[8];
    for (int i = 0; i < 8; ++i) ck[i] = static_cast<std::uint8_t>((h >> (8 * i)) & 0xFF);
    return send_all(hdr, 4) && (p.empty() || send_all(p.data(), p.size())) && send_all(ck, 8);
  }
  bool send(const Message& m) { return send_frame(encode_message(m)); }

  bool recv(Message& m) {
    std::uint8_t hdr[4];
    if (!recv_all(hdr, 4)) return false;
    std::uint32_t n = 0;
    for (int i = 0; i < 4; ++i) n |= static_cast<std::uint32_t>(hdr[i]) << (8 * i);
    std::vector<std::uint8_t> p(n);
    std::uint8_t ck[8];
    if ((n > 0 && !recv_all(p.data(), n)) || !recv_all(ck, 8)) return false;
    try { m = decode_message(p); } catch (...) { return false; }
    return true;
  }

  // Half-closes the connection and returns once the coordinator has closed its
  // end, which it does only after it has finished handling the close.
  void half_close_and_drain() {
    if (s_ == INVALID_SOCKET) return;
    ::shutdown(s_, SD_SEND);
    char buf[512];
    while (::recv(s_, buf, sizeof(buf), 0) > 0) {}
    close();
  }

  // Wakes a thread blocked in recv on this connection.
  void interrupt() {
    if (s_ == INVALID_SOCKET) return;
    ::shutdown(s_, SD_BOTH);
    ::CancelIoEx(reinterpret_cast<HANDLE>(s_), nullptr);
  }

  void close() {
    if (s_ != INVALID_SOCKET) { closesocket(s_); s_ = INVALID_SOCKET; }
  }

 private:
  bool send_all(const std::uint8_t* p, std::size_t n) {
    while (n > 0) {
      const int k = ::send(s_, reinterpret_cast<const char*>(p), static_cast<int>(n), 0);
      if (k <= 0) return false;
      p += k; n -= static_cast<std::size_t>(k);
    }
    return true;
  }
  bool recv_all(std::uint8_t* p, std::size_t n) {
    while (n > 0) {
      const int k = ::recv(s_, reinterpret_cast<char*>(p), static_cast<int>(n), 0);
      if (k <= 0) return false;
      p += k; n -= static_cast<std::size_t>(k);
    }
    return true;
  }

  SOCKET s_ = INVALID_SOCKET;
  std::mutex write_;
};

// This build's af_coordinator as a child process, killed when it goes out of scope.
class CoordinatorProcess {
 public:
  explicit CoordinatorProcess(std::uint16_t port) : port_(port) {
    std::string cmd = std::string("\"") + AF_COORDINATOR_EXE + "\" --port " + std::to_string(port);
    std::vector<char> buf(cmd.begin(), cmd.end());
    buf.push_back(0);
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (CreateProcessA(nullptr, buf.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
      h_ = pi.hProcess;
      CloseHandle(pi.hThread);
    }
  }
  ~CoordinatorProcess() {
    if (h_) { TerminateProcess(h_, 0); WaitForSingleObject(h_, INFINITE); CloseHandle(h_); }
  }
  CoordinatorProcess(const CoordinatorProcess&) = delete;
  CoordinatorProcess& operator=(const CoordinatorProcess&) = delete;

  bool alive() const { return h_ != nullptr && WaitForSingleObject(h_, 0) == WAIT_TIMEOUT; }
  // Connects, retrying while the coordinator starts up; fails if it exits.
  bool connect(Conn& c) const {
    while (!c.connect(port_)) {
      if (!alive()) return false;
      Sleep(20);
    }
    return true;
  }
  void wait_exit() const { if (h_) WaitForSingleObject(h_, INFINITE); }
  std::uint16_t port() const { return port_; }

 private:
  std::uint16_t port_;
  HANDLE h_ = nullptr;
};

MsgType ack_for(MsgType t) {
  switch (t) {
    case MsgType::wk_load: return MsgType::wk_load_ack;
    case MsgType::wk_activate: return MsgType::wk_activate_ack;
    case MsgType::wk_deactivate: return MsgType::wk_deactivate_ack;
    case MsgType::wk_migrate: return MsgType::wk_migrate_ack;
    case MsgType::wk_invalidate: return MsgType::wk_invalidate_ack;
    default: return MsgType::wk_error;
  }
}

// A fake worker. serve() answers every command with success on a background
// thread and records what it received; otherwise next()/reply() answer by hand.
class FakeWorker {
 public:
  WorkerId id;
  WorkerBootId boot;
  Conn conn;

  explicit FakeWorker(WorkerId i = WorkerId::generate(), WorkerBootId b = WorkerBootId::generate()) : id(i), boot(b) {}
  ~FakeWorker() {
    conn.interrupt();
    if (server_.joinable()) server_.join();
  }

  // True when the coordinator accepted the registration.
  bool register_at(const CoordinatorProcess& c) {
    if (!c.connect(conn)) return false;
    Message reg; reg.type = MsgType::wk_register; reg.text = id.str(); reg.text2 = boot.str(); reg.text3 = "fake-worker";
    if (!conn.send(reg)) return false;
    Message ack;
    return conn.recv(ack) && ack.type == MsgType::wk_register_ack && ack.ok;
  }

  void serve() {
    server_ = std::thread([this] {
      Message m;
      while (conn.recv(m)) {
        { std::lock_guard<std::mutex> lk(seen_m_); seen_.push_back(m.type); }
        reply(m, true);
      }
    });
  }

  Message next() {
    Message m;
    if (!conn.recv(m)) throw std::runtime_error("worker connection closed");
    return m;
  }
  void reply(const Message& req, bool ok, const std::string& text = "ok") {
    Message r; r.type = ack_for(req.type); r.req_id = req.req_id; r.ok = ok; r.a = 8192; r.text = text;
    conn.send(r);
  }
  int received(MsgType t) {
    std::lock_guard<std::mutex> lk(seen_m_);
    int n = 0;
    for (auto x : seen_) if (x == t) ++n;
    return n;
  }

 private:
  std::thread server_;
  std::mutex seen_m_;
  std::vector<MsgType> seen_;
};

Message request(Conn& c, const Message& m) {
  Message out;
  if (!c.send(m) || !c.recv(out)) { out = Message{}; out.ok = false; out.text = "control connection failed"; }
  return out;
}

AdapterDescriptor register_adapter(Conn& ctl, const std::string& name) {
  Message m; m.type = MsgType::ctl_register_adapter;
  m.payload = serialize_adapter(fx::make_lora(name, fx::base(), fx::rev(), 8192));
  const Message out = request(ctl, m);
  if (!out.ok) throw std::runtime_error("adapter registration failed: " + out.text);
  return deserialize_adapter(out.payload);
}

AuthorityFence fence_for(const AdapterDescriptor& d, const FakeWorker& w, std::uint64_t epoch) {
  AuthorityFence f;
  f.adapter = d.id; f.adapter_generation = d.generation; f.base_model_revision = d.base_model_revision;
  f.epoch = CoordinatorEpoch{epoch}; f.worker = w.id; f.boot = w.boot; f.attempt = AttemptId::generate();
  f.device = DeviceId::generate();
  f.residency_generation = ResidencyGeneration{1}; f.composition_generation = CompositionGeneration{1};
  f.artifact_generation = ArtifactGeneration{1};
  return f;
}

Message fenced(MsgType t, const AuthorityFence& f) {
  Message m; m.type = t; m.text = f.adapter.str(); m.text2 = f.worker.str(); m.payload = encode_fence(f);
  return m;
}

std::optional<WorkerRecord> worker_state(Conn& ctl, const WorkerId& id) {
  Message m; m.type = MsgType::ctl_snapshot;
  const Message out = request(ctl, m);
  if (!out.ok) return std::nullopt;
  for (const auto& w : deserialize_snapshot(out.payload).workers) if (w.id == id) return w;
  return std::nullopt;
}

// Polls the coordinator until it has seen the worker's connection go away.
void wait_disconnected(Conn& ctl, const WorkerId& id) {
  for (;;) {
    auto w = worker_state(ctl, id);
    if (w && !w->connected) return;
    Sleep(10);
  }
}

std::string capacity(Conn& ctl) {
  Message m; m.type = MsgType::ctl_capacity;
  return request(ctl, m).text + " ";
}

// Flushes the previous case's result line, so it is not lost if a later case
// hangs and the process is ended from outside.
void begin_case() { std::cout << std::flush; }

}  // namespace

AF_TEST_CASE(regression_malformed_registration_does_not_kill_coordinator) {
  begin_case();
  CoordinatorProcess c(23111);
  Conn ctl;
  AF_CHECK(c.connect(ctl));
  Conn bad;
  AF_CHECK(c.connect(bad));
  Message reg; reg.type = MsgType::wk_register; reg.text = "not-a-worker-id"; reg.text2 = "not-a-boot-id";
  bad.send(reg);
  bad.half_close_and_drain();
  Message ping; ping.type = MsgType::ping;
  const Message pong = request(ctl, ping);
  AF_CHECK_MSG(pong.ok && pong.type == MsgType::pong, "the coordinator still serves after a malformed worker registration");
}

AF_TEST_CASE(regression_lost_boot_cannot_register_again) {
  begin_case();
  CoordinatorProcess c(23112);
  Conn ctl;
  AF_CHECK(c.connect(ctl));
  const WorkerId wid = WorkerId::generate();
  const WorkerBootId boot1 = WorkerBootId::generate();
  {
    FakeWorker w(wid, boot1);
    AF_CHECK(w.register_at(c));
    w.conn.close();
    wait_disconnected(ctl, wid);
  }
  {
    FakeWorker replay(wid, boot1);
    AF_CHECK_MSG(!replay.register_at(c), "a replayed registration of the lost boot is rejected");
  }
  FakeWorker fresh(wid, WorkerBootId::generate());
  AF_CHECK(fresh.register_at(c));
  {
    FakeWorker replay(wid, boot1);
    AF_CHECK_MSG(!replay.register_at(c), "a replay of the lost boot is rejected while the fresh boot is registered");
  }
  auto st = worker_state(ctl, wid);
  AF_CHECK_MSG(st && st->connected && st->boot == fresh.boot, "the fresh boot stays the registered, connected boot");
}

AF_TEST_CASE(regression_replaced_connection_close_keeps_live_boot) {
  begin_case();
  CoordinatorProcess c(23113);
  Conn ctl;
  AF_CHECK(c.connect(ctl));
  const WorkerId wid = WorkerId::generate();
  FakeWorker older(wid, WorkerBootId::generate());
  AF_CHECK(older.register_at(c));
  FakeWorker newer(wid, WorkerBootId::generate());
  AF_CHECK(newer.register_at(c));
  older.conn.half_close_and_drain();
  auto st = worker_state(ctl, wid);
  AF_CHECK_MSG(st && st->connected && st->boot == newer.boot,
               "the superseded connection's close leaves the newer boot registered and connected");
  FakeWorker replay(wid, older.boot);
  AF_CHECK_MSG(!replay.register_at(c), "the superseded boot cannot register again");
}

AF_TEST_CASE(regression_disconnect_aborts_only_its_own_requests) {
  begin_case();
  CoordinatorProcess c(23114);
  Conn ctl, ctl2;
  AF_CHECK(c.connect(ctl) && c.connect(ctl2));
  const AdapterDescriptor d = register_adapter(ctl, "a");
  FakeWorker x, y;
  AF_CHECK(x.register_at(c) && y.register_at(c));
  ctl.send(fenced(MsgType::ctl_load, fence_for(d, x, 0)));
  const Message fwd = x.next();
  y.conn.close();
  wait_disconnected(ctl2, y.id);
  x.reply(fwd, true);
  Message out;
  AF_CHECK(ctl.recv(out));
  AF_CHECK_MSG(out.ok, "a load forwarded to one worker survives another worker's disconnect");
}

AF_TEST_CASE(regression_reply_from_another_worker_is_ignored) {
  begin_case();
  CoordinatorProcess c(23115);
  Conn ctl, ctl2;
  AF_CHECK(c.connect(ctl) && c.connect(ctl2));
  const AdapterDescriptor d = register_adapter(ctl, "a");
  FakeWorker x, y;
  AF_CHECK(x.register_at(c) && y.register_at(c));
  ctl.send(fenced(MsgType::ctl_load, fence_for(d, x, 0)));
  const Message fwd = x.next();
  Message forged; forged.type = MsgType::wk_load_ack; forged.req_id = fwd.req_id; forged.ok = true; forged.a = 8192;
  y.conn.send(forged);
  y.conn.close();
  wait_disconnected(ctl2, y.id);  // y's forged reply was handled before its close
  x.reply(fwd, false, "genuine failure");
  Message out;
  AF_CHECK(ctl.recv(out));
  AF_CHECK_MSG(!out.ok, "the load's outcome is the addressed worker's reply, not another worker's");
}

AF_TEST_CASE(regression_load_capacity_is_accounted) {
  begin_case();
  CoordinatorProcess c(23116);
  Conn ctl;
  AF_CHECK(c.connect(ctl));
  const AdapterDescriptor d = register_adapter(ctl, "a");
  FakeWorker x;
  AF_CHECK(x.register_at(c));
  x.serve();
  const Message loaded = request(ctl, fenced(MsgType::ctl_load, fence_for(d, x, 0)));
  AF_CHECK(loaded.ok);
  AF_CHECK_MSG(capacity(ctl).find("device_memory=8192 ") != std::string::npos, "a load holds its adapter's bytes");
  Message ev; ev.type = MsgType::ctl_evict; ev.text = loaded.text2; ev.text2 = x.id.str();
  AF_CHECK(request(ctl, ev).ok);
  AF_CHECK_MSG(capacity(ctl).find("device_memory=0 ") != std::string::npos, "eviction returns the bytes");
  AF_CHECK(request(ctl, fenced(MsgType::ctl_load, fence_for(d, x, 0))).ok);
  x.conn.interrupt();
  wait_disconnected(ctl, x.id);
  AF_CHECK_MSG(capacity(ctl).find("device_memory=0 ") != std::string::npos, "a lost worker's bytes are returned");
}

AF_TEST_CASE(regression_stale_migration_rejected) {
  begin_case();
  CoordinatorProcess c(23117);
  Conn ctl;
  AF_CHECK(c.connect(ctl));
  const AdapterDescriptor d = register_adapter(ctl, "a");
  FakeWorker x;
  AF_CHECK(x.register_at(c));
  x.serve();
  const AuthorityFence f = fence_for(d, x, 0);
  AF_CHECK(request(ctl, fenced(MsgType::ctl_load, f)).ok);
  AF_CHECK(request(ctl, fenced(MsgType::ctl_activate, f)).ok);
  Message e; e.type = MsgType::ctl_epoch;
  AF_CHECK(request(ctl, e).ok);
  AF_CHECK_MSG(!request(ctl, fenced(MsgType::ctl_migrate, f)).ok, "a migration under a stale epoch is rejected");
  AF_CHECK_MSG(x.received(MsgType::wk_migrate) == 0, "the stale migration never reaches the worker");
}

AF_TEST_CASE(regression_conflicting_activation_not_forwarded) {
  begin_case();
  CoordinatorProcess c(23118);
  Conn ctl;
  AF_CHECK(c.connect(ctl));
  const AdapterDescriptor a = register_adapter(ctl, "a");
  const AdapterDescriptor b = register_adapter(ctl, "b");
  FakeWorker x;
  AF_CHECK(x.register_at(c));
  x.serve();
  const AuthorityFence fa = fence_for(a, x, 0);
  const AuthorityFence fb = fence_for(b, x, 0);
  AF_CHECK(request(ctl, fenced(MsgType::ctl_load, fa)).ok);
  AF_CHECK(request(ctl, fenced(MsgType::ctl_activate, fa)).ok);
  AF_CHECK(request(ctl, fenced(MsgType::ctl_load, fb)).ok);
  AF_CHECK(!request(ctl, fenced(MsgType::ctl_activate, fb)).ok);
  AF_CHECK_MSG(x.received(MsgType::wk_activate) == 1, "an activation refused for exclusivity never reaches the worker");
}

AF_TEST_CASE(regression_deactivation_releases_authority) {
  begin_case();
  CoordinatorProcess c(23119);
  Conn ctl;
  AF_CHECK(c.connect(ctl));
  const AdapterDescriptor a = register_adapter(ctl, "a");
  const AdapterDescriptor b = register_adapter(ctl, "b");
  FakeWorker x;
  AF_CHECK(x.register_at(c));
  x.serve();
  const AuthorityFence fa = fence_for(a, x, 0);
  AF_CHECK(request(ctl, fenced(MsgType::ctl_load, fa)).ok);
  AF_CHECK(request(ctl, fenced(MsgType::ctl_activate, fa)).ok);
  Message dac; dac.type = MsgType::ctl_deactivate; dac.text = a.id.str(); dac.text2 = x.id.str();
  AF_CHECK(request(ctl, dac).ok);
  const AuthorityFence fb = fence_for(b, x, 0);
  AF_CHECK(request(ctl, fenced(MsgType::ctl_load, fb)).ok);
  AF_CHECK_MSG(request(ctl, fenced(MsgType::ctl_activate, fb)).ok, "after a is deactivated, b can be activated");
}

AF_TEST_CASE(regression_malformed_worker_frame_marks_worker_down) {
  begin_case();
  CoordinatorProcess c(23120);
  Conn ctl;
  AF_CHECK(c.connect(ctl));
  FakeWorker x;
  AF_CHECK(x.register_at(c));
  // A frame with a valid checksum whose message cannot be decoded.
  x.conn.send_frame({0x01, 0x02, 0x03});
  wait_disconnected(ctl, x.id);
  AF_CHECK(true);
}

AF_TEST_CASE(regression_shutdown_with_open_connections_exits) {
  begin_case();
  CoordinatorProcess c(23121);
  Conn ctl;
  AF_CHECK(c.connect(ctl));
  FakeWorker x;
  AF_CHECK(x.register_at(c));
  Message sd; sd.type = MsgType::ctl_shutdown;
  AF_CHECK(request(ctl, sd).ok);
  c.wait_exit();  // no time limit: a coordinator that never exits hangs here
  AF_CHECK(!c.alive());
}

// `--only <case>` runs one case by itself.
int main(int argc, char** argv) {
  if (argc == 3 && std::string(argv[1]) == "--only") {
    auto& r = af_test::registry();
    const std::string only = argv[2];
    r.erase(std::remove_if(r.begin(), r.end(), [&](const af_test::TestCase& t) { return t.name != only; }), r.end());
  }
  return af_test::run_all();
}
