#include <dns/client.h>

namespace bro::net::dns {

client::client(client::config const &conf)
  : _config(conf)
  , _resolver(_config._resolver_conf)
  , _run(true) {
  _thread = std::thread(&client::run, this);
}

client::~client() {
  _run = false;
  _thread.join();
}

bool client::resolve(std::string const &host_name, proto::ip::address::version host_addr_ver, result_cbt &&result_cb) {
  std::lock_guard<std::mutex> lock(_mutex);
  _queries.push_back({host_name, host_addr_ver, std::move(result_cb)});
  return true;
}

void client::send_queries() {
  std::lock_guard<std::mutex> lock(_mutex);
  if (!_queries.empty()) {
    for (auto &q : _queries)
      _resolver.resolve(std::get<0>(q), std::get<1>(q), std::move(std::get<2>(q)));
    _queries.clear();
  }
}

void client::run() {
  while (_run.load(std::memory_order_acquire)) {
    _resolver.proceed();
    send_queries();
  }
}

} // namespace bro::net::dns
