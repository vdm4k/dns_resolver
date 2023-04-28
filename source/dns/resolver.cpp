#include <dns/resolver.h>

namespace bro::net::dns {

resolver::resolver(config const &conf, std::shared_ptr<ev::factory> factory)
  : _factory(factory == nullptr ? std::make_shared<ev::factory>() : factory)
  , _config(conf) {
  if (_config._free_query_after_use) {
    _free_query = _factory->generate_timer();
    _free_query->start(std::chrono::seconds(1), [&]() {
      free_resources_per_query();
      _queries.erase(std::remove_if(_queries.begin(), _queries.end(), [](auto const &q) { return q->is_idle(); }),
                     _queries.end());
    });
  }

  _free_resources = _factory->generate_timer();
  _free_resources->start(std::chrono::seconds(1), [&]() { free_resources_per_query(); });
}

bool resolver::resolve(std::string const &host_name, proto::ip::address::version host_addr_ver, result_cbt &&result_cb) {
  // reuse old
  for (auto &q : _queries) {
    if (q->is_idle()) {
      return q->run(host_name, host_addr_ver, std::move(result_cb));
    }
  }
  if (_config._max_active_queries) {
    if (*_config._max_active_queries > _queries.size()) {
      result_cb({}, host_name, "limit on active queries exceeded");
      return false;
    }
  }

  //generate new query
  auto q = std::make_unique<query>(_factory->generate_io(ev::io::type::e_read),
                                   _factory->generate_io(ev::io::type::e_write),
                                   _factory->generate_timer(),
                                   _query_done_q);
  if (_config._query_conf)
    q->set_config(*_config._query_conf);
  bool res = q->run(host_name, host_addr_ver, std::move(result_cb));
  _queries.push_back(std::move(q));
  return res;
}

void resolver::free_resources_per_query() {
  if (!_query_done_q.empty()) {
    for (auto &q : _query_done_q) {
      q->free_resources_per_query();
    }
    _query_done_q.clear();
  }
}

void resolver::proceed() {
  _factory->proceed();
}

} // namespace bro::net::dns
