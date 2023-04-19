#include <dns/query.h>
#include <netdb.h>
#include <ares.h>

namespace bro::net::dns {

constexpr std::chrono::milliseconds timeval_to_ms(timeval ts) {
  auto duration = std::chrono::seconds{ts.tv_sec} + std::chrono::microseconds{ts.tv_usec};
  return std::chrono::duration_cast<std::chrono::milliseconds>(duration);
}

query::query(ev::io_t &&read_ev, ev::io_t &&write_ev, ev::timer_t &&timer, std::vector<query *> &resolv_done)
  : _read_ev(std::move(read_ev))
  , _write_ev(std::move(write_ev))
  , _timer(std::move(timer))
  , _query_done_q(resolv_done) {}

query::~query() {
  //NOTE: I don't think we need to call _result_cb function here because we will free it in active state only if programm ended

  _state = state::e_idle; // we need it because gethostbyname_cb will call
                          // by library and we will check state in done function
  free_resources_per_query();
}

bool query::run(std::string const &host_name, proto::ip::address::version host_addr_ver, result_cbt &&result_cb) {
  if (!is_idle()) {
    result_cb({}, host_name, "couldn't reuse query cause query class is running");
    return false;
  }
  if (host_addr_ver == proto::ip::address::version::e_none) {
    result_cb({}, host_name, "host address version not set");
    return false;
  }
  free_resources_per_query(); // maybe we reuse this query before free old resources
  _host_name = host_name;
  _host_addr_ver = host_addr_ver;

  ares_options opts{};
  opts.sock_state_cb = sock_state_cb;
  opts.sock_state_cb_data = this;
  auto optmask = ARES_OPT_SOCK_STATE_CB;
  if (_config._timeout) {
    opts.timeout = _config._timeout->count();
    optmask |= ARES_OPT_TIMEOUTMS;
  }
  if (_config._tries) {
    opts.timeout = *_config._tries;
    optmask |= ARES_OPT_TRIES;
  }

  ares_channel chan;
  int ret_val = ares_init_options(&chan, &opts, optmask);
  if (ret_val != ARES_SUCCESS) {
    result_cb({}, host_name, "couldn't init ares");
    return false;
  }

  _ares_channel = chan;
  _state = state::e_running;
  _result_cb = std::move(result_cb);
  switch (_host_addr_ver) {
  case proto::ip::address::version::e_v4:
    ares_gethostbyname(_ares_channel, _host_name.c_str(), AF_INET, gethostbyname_cb, this);
    break;
  case proto::ip::address::version::e_v6:
    ares_gethostbyname(_ares_channel, _host_name.c_str(), AF_INET6, gethostbyname_cb, this);
    break;
  default:
    break;
  }

  // NOTE: looks strange, but ares can fast detect if something go wrong and call ares_gethostbyname,
  // hence here we just check if query already failed - do nothing
  if (is_idle())
    return false;

  _timer->set_callback([this]() {
    ares_process_fd(_ares_channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
    restart_timer(); // restart if many tries
  });
  restart_timer();
  return true;
}

void query::restart_timer() {
  if (is_idle()) // we can call this after all timers expired, hence just check if query is active
    return;
  timeval tvout;
  auto tv = ares_timeout(_ares_channel, nullptr, &tvout);
  if (tv == nullptr) {
    return;
  }
  _timer->start(timeval_to_ms(*tv));
}

void query::start_io(ares_socket_t file_descriptor, bool read, bool write) {
  if (read) {
    _read_ev->start(file_descriptor, [socekt_fd = file_descriptor, this]() {
      ares_process_fd(_ares_channel, socekt_fd, ARES_SOCKET_BAD);
      restart_timer();
    });
  }
  if (write) {
    _write_ev->start(file_descriptor, [socekt_fd = file_descriptor, this]() {
      ares_process_fd(_ares_channel, ARES_SOCKET_BAD, socekt_fd);
      restart_timer();
    });
  }
}

void query::stop_io() {
  _read_ev->stop();
  _write_ev->stop();
}

void query::gethostbyname_cb(void *arg, int status, int /*timeouts*/, hostent *hostent) {
  auto q = static_cast<query *>(arg);
  q->done(status, hostent);
}

void query::done(int status, hostent *hostent) {
  // NOTE: we can't call free_resources_per_query here, because of specific how library works ( double free will be )

  if (is_idle()) // need to check because library may call it in our desctructor
    return;
  _state = state::e_idle;
  _timer->stop();
  _query_done_q.push_back(this); // may have duplicates, it's ok

  if (status != ARES_SUCCESS) {
    if (_result_cb)
      _result_cb({}, _host_name, ares_strerror(status));
    return;
  }

  auto address = *hostent->h_addr_list;
  if (!address) {
    if (_result_cb)
      _result_cb({}, _host_name, "ares return empty list of addresses from name server");
    return;
  }

  switch (hostent->h_addrtype) {
  case AF_INET: {
    struct in_addr sin_addr;
    memcpy(&sin_addr, address, sizeof(sin_addr));
    if (_result_cb) // probably it can't be here
      _result_cb(sin_addr, _host_name, nullptr);
    break;
  }
  case AF_INET6:
    struct in6_addr sin6_addr;
    memcpy(&sin6_addr, address, sizeof(sin6_addr));
    if (_result_cb) // probably it can't be here
      _result_cb(sin6_addr, _host_name, nullptr);
    break;
  default:
    break;
  }
}

void query::sock_state_cb(void *data, ares_socket_t socket_fd, int read, int write) {
  auto q = static_cast<query *>(data);
  if (read || write) {
    q->start_io(socket_fd, read, write);
  } else {
    q->stop_io();
  }
}

void query::free_resources_per_query() {
  if (!is_idle()) // just check, maybe we already reuse this query
    return;
  _result_cb = nullptr;
  if (_ares_channel) {
    ares_destroy(_ares_channel);
    _ares_channel = nullptr;
  }
}

void query::set_config(config const &conf) {
  _config = conf;
}

} // namespace bro::net::dns
