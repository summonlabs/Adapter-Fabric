// Adapter Fabric — regression tests for activation authority, eviction,
// recovery and load capacity accounting.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "test.hpp"
#include "fixtures.hpp"
#include "adapter_fabric/coordinator.hpp"
#include "adapter_fabric/fabric.hpp"
#include "adapter_fabric/persistence.hpp"
#include "adapter_fabric/protocol.hpp"

using namespace adapter_fabric;
namespace fx = af_test_fixture;

namespace {

WorkerRecord make_worker() {
  WorkerRecord w;
  w.id = WorkerId::generate(); w.boot = WorkerBootId::generate(); w.connected = true; w.device = DeviceId::generate();
  return w;
}

AuthorityFence fence_for(const Fabric& f, const AdapterDescriptor& d, const WorkerRecord& w, DeviceId dev, AttemptId attempt) {
  AuthorityFence fence;
  fence.adapter = d.id; fence.adapter_generation = d.generation; fence.base_model_revision = d.base_model_revision;
  fence.epoch = f.epoch(); fence.worker = w.id; fence.boot = w.boot; fence.attempt = attempt; fence.device = dev;
  fence.residency_generation = ResidencyGeneration{1}; fence.composition_generation = CompositionGeneration{1};
  fence.artifact_generation = ArtifactGeneration{1};
  return fence;
}

}  // namespace

AF_TEST_CASE(regression_invalidated_activation_cannot_be_rebound) {
  Fabric f;
  auto bm = fx::base(); auto mr = fx::rev();
  AdapterDescriptor d = f.register_adapter(fx::make_lora("a", bm, mr));
  WorkerRecord w = make_worker(); f.register_worker(w);
  DeviceId dev = DeviceId::generate();
  f.create_instance(d.id, w.id, w.boot, dev, d.memory_bytes);
  AuthorityFence first = fence_for(f, d, w, dev, AttemptId::generate());
  AF_CHECK(f.bind_authority(d.id, first).authorized());
  f.invalidate(d.id, InvalidationTrigger::manual, "manual");
  // Replaying the invalidated activation does not restore its authority.
  AF_CHECK(!f.bind_authority(d.id, first).authorized());
  AF_CHECK(!f.authority_record(d.id)->active);
  // After a reload, a fresh activation attempt is accepted.
  f.create_instance(d.id, w.id, w.boot, dev, d.memory_bytes);
  AuthorityFence fresh = fence_for(f, d, w, dev, AttemptId::generate());
  AF_CHECK(f.bind_authority(d.id, fresh).authorized());
}

AF_TEST_CASE(regression_active_instance_not_evicted) {
  Fabric f;
  auto bm = fx::base(); auto mr = fx::rev();
  AdapterDescriptor d = f.register_adapter(fx::make_lora("a", bm, mr));
  WorkerRecord w = make_worker(); f.register_worker(w);
  DeviceId dev = DeviceId::generate();
  AdapterInstanceId inst = f.create_instance(d.id, w.id, w.boot, dev, d.memory_bytes);
  AF_CHECK(f.bind_authority(d.id, fence_for(f, d, w, dev, AttemptId::generate())).authorized());
  std::string reason;
  AF_CHECK(!f.evict(inst, reason));
  AF_CHECK(f.has_instance(inst));
}

AF_TEST_CASE(regression_recovery_does_not_restore_authority) {
  Fabric f1;
  auto bm = fx::base(); auto mr = fx::rev();
  AdapterDescriptor d = f1.register_adapter(fx::make_lora("a", bm, mr));
  WorkerRecord w = make_worker(); f1.register_worker(w);
  DeviceId dev = DeviceId::generate();
  f1.create_instance(d.id, w.id, w.boot, dev, d.memory_bytes);
  AuthorityFence before = fence_for(f1, d, w, dev, AttemptId::generate());
  AF_CHECK(f1.bind_authority(d.id, before).authorized());

  Fabric f2;
  f2.recover(deserialize_snapshot(serialize_snapshot(f1.snapshot())));
  // A fence issued before the restart is not current, and the worker is not
  // connected until it registers with the recovered coordinator.
  AF_CHECK(!f2.check_fence(before).authorized());
  f2.create_instance(d.id, w.id, w.boot, dev, d.memory_bytes);
  AF_CHECK(!f2.bind_authority(d.id, before).authorized());
  AF_CHECK(f2.worker(w.id) != nullptr && !f2.worker(w.id)->connected);
}

AF_TEST_CASE(regression_default_coordinator_capacity) {
  CoordinatorServer server(23990);  // never started: no listener
  AF_CHECK(server.fabric().capacity().limit(ResidencyLocation::device_memory) > 0);
}

AF_TEST_CASE(regression_load_reserves_capacity_before_loading) {
  CoordinatorServer server(23991, {{ResidencyLocation::device_memory, 4096}});  // never started
  auto bm = fx::base(); auto mr = fx::rev();
  Message reg; reg.type = MsgType::ctl_register_adapter; reg.payload = serialize_adapter(fx::make_lora("big", bm, mr, 8192));
  Message r = server.process_control(reg);
  AF_CHECK(r.ok);
  if (!r.ok) return;
  AdapterDescriptor d = deserialize_adapter(r.payload);
  WorkerRecord w = make_worker(); server.fabric().register_worker(w);
  Message load; load.type = MsgType::ctl_load; load.text = d.id.str(); load.text2 = w.id.str();
  load.payload = encode_fence(fence_for(server.fabric(), d, w, DeviceId::generate(), AttemptId::generate()));
  AF_CHECK(!server.process_control(load).ok);
  // A load that does not fit creates nothing and holds nothing.
  AF_CHECK(server.fabric().authority_record(d.id) == nullptr);
  AF_CHECK(server.fabric().capacity().is_clean());
}

AF_TEST_MAIN
