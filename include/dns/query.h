#pragma once

#include <libev_wrapper/io.h>
#include <libev_wrapper/timer.h>
#include <optional>
#include <protocols/ip/address.h>

struct hostent;
typedef int ares_socket_t;
typedef struct ares_channeldata *ares_channel;

namespace bro::net::dns {

/** @addtogroup dns_resolver
 *  @{
 */

/**
 * \brief A type alias for a callback function that returns a result.
 *
 * This function will be called with filled ip::address or error
 * pointer on error is a pointer on static buffer, no need to call free
 */
using result_cbt = std::function<void(proto::ip::address, std::string const &hostname, char const *const error)>;

/*!\brief dns query
 */
class query {
public:
  /*!\brief query config
 */
  struct config {
    std::optional<std::chrono::milliseconds> _timeout; ///< timeout for this query
    std::optional<size_t> _tries;                      ///< tries before giveup
  };

  /*!\brief query state
 */
  enum class state {
    e_idle,   ///< not in active state
    e_running ///< is running
  };

  /*!\brief ctor with config
   * \param [in] read_ev read-event
   * \param [in] write_ev write-event
   * \param [in] timer timer-event
   * \param [in] resolv_done queue to set than resolve done
 */
  query(ev::io_t &&read_ev, ev::io_t &&write_ev, ev::timer_t &&timer, std::vector<query *> &resolv_done);

  /**
   * \brief disabled copy ctor
   */
  query(query const &) = delete;

  /**
   * \brief disabled move ctor
   */
  query(query &&) = delete;

  /**
   * \brief disabled move assign operator
   */
  query &operator=(query &&) = delete;

  /**
   * \brief disabled assign operator
   */
  query &operator=(query const &) = delete;

  ~query();

  /*! \brief resolve hostname to an address
   * \param [in] host_name host name
   * \param [in] host_addr_ver address type
   * \param [in] result_cb callback to call for result.
   * \result true if queiry send, false otherwise (result_cb will call with error)
   */
  bool run(std::string const &host_name, proto::ip::address::version host_addr_ver, result_cbt &&result_cb);

  /*! \brief set configuration for this query
   * \param [in] conf configuration
   */
  void set_config(config const &conf);

  /*! \brief check if query is in an idle state
   * \result true if in an idle, false otherwise
   */
  bool is_idle() const noexcept { return _state == state::e_idle; }

  /*! \brief free resources per query
   */
  void free_resources_per_query();

private:
  /*! \brief callback function for ares library (sock_state_cb)
   *  \param [in] data pointer on user data
   *  \param [in] socket_fd socket descriptor
   *  \param [in] read if need to start wait read event set 1
   *  \param [in] write if need to start wait read event set 1
   */
  static void sock_state_cb(void *data, ares_socket_t socket_fd, int read, int write);

  /*! \brief callback function for ares library (ares_gethostbyname)
   *  \param [in] arg pointer on user data
   *  \param [in] status result of operation
   *  \param [in] timeouts how many timouts was in this query
   *  \param [in] hostent pointer on resolved host
   */
  static void gethostbyname_cb(void *arg, int status, int timeouts, hostent *hostent);

  /*! \brief query done
   *  \param [in] status ares status
   *  \param [in] hostent from ares
   */
  void done(int status, hostent *hostent);

  /*! \brief restart/start timer with timeout from ares
   */
  void restart_timer();

  /*! \brief start some of io operation
   *  \param [in] file_descriptor specific file descriptor on which we will wait events
   *  \param [in] read is read event
   *  \param [in] write is write event
   */
  void start_io(ares_socket_t file_descriptor, bool read, bool write);

  /*! \brief stop all io events
   */
  void stop_io();

  ev::io_t _read_ev;                                                               ///< read event
  ev::io_t _write_ev;                                                              ///< write event
  ev::timer_t _timer;                                                              ///< timer
  proto::ip::address::version _host_addr_ver{proto::ip::address::version::e_none}; ///< host address type
  ares_channel _ares_channel{nullptr};                                             ///< ares channel
  std::string _host_name;                                                          ///< host name
  result_cbt _result_cb;                                                           ///< result callback function
  state _state{state::e_idle};                                                     ///< current state
  config _config;                                                                  ///< current configuration
  std::vector<query *> &_query_done_q;                                             ///< query done queue
};

} // namespace bro::net::dns
