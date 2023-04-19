#pragma once
#include <thread>
#include <atomic>
#include <mutex>
#include "resolver.h"

namespace bro::net::dns {

/** @addtogroup dns_resolver
 *  @{
 */

/*!\brief dns client. using thread to resolve query
 */
class client {
public:
  /*!\brief client config
 */
  struct config {
    resolver::config _resolver_conf;                                ///< resolver configuration
    std::chrono::milliseconds _sleep{std::chrono::milliseconds(1)}; ///< sleep time on every iteration
  };

  /*!\brief ctor with config
   * \param [in] conf configuration
 */
  client(config const &conf);
  ~client();

  /*! \brief resolve hostname to address
   * \param [in] host_name host name
   * \param [in] host_addr_ver address type
   * \param [in] result_cb callback to call for result.
   * \result true if queiry send, false otherwise and result_cb will call with error
   */
  bool resolve(std::string const &host_name, proto::ip::address::version host_addr_ver, result_cbt &&result_cb);

private:
  /*!\brief thread function
 */
  void run();

  /*!\brief send new queries
 */
  void send_queries();

  std::mutex _mutex;                                                                      ///< synchro mutex )
  std::vector<std::tuple<std::string, proto::ip::address::version, result_cbt>> _queries; ///< queries to process
  config _config;                                                                         ///< current configuration
  resolver _resolver;                                                                     ///< query resolver
  std::thread _thread;                                                                    ///< thread
  std::atomic_bool _run;                                                                  ///< is running
};

} // namespace bro::net::dns
