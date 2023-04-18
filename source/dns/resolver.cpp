#include <dns/resolver.h>

namespace bro::net::dns {

resolver::resolver(config const &conf)
  : _config(conf) {
  if (_config._free_query_after_use) {
    _free_query = _factory.generate_timer();
    _free_query->start(std::chrono::seconds(1), [&]() {
      _queries.erase(std::remove_if(_queries.begin(), _queries.end(), [](auto const &q) { return q->is_idle(); }),
                     _queries.end());
    });
  }
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
      result_cb({}, "limit on active queries exceeded");
      return false;
    }
  }

  //generate new query
  auto q = std::make_unique<query>(_factory.generate_io(ev::io::type::e_read),
                                   _factory.generate_io(ev::io::type::e_write),
                                   _factory.generate_timer(),
                                   _query_done_q);
  if (_config._query_conf)
    q->set_config(*_config._query_conf);
  if (!q->run(host_name, host_addr_ver, std::move(result_cb)))
    return false;
  _queries.push_back(std::move(q));
  return true;
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
  _factory.proceed();
  free_resources_per_query();
}

} // namespace bro::net::dns