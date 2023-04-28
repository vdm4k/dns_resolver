#pragma once
#include "query.h"
#include <libev_wrapper/factory.h>

namespace bro::net::dns {

/** @defgroup dns_resolver dns_resolver
 *  @{
 */

/*!\brief manager for queries
 */
class resolver {
public:
  /*!\brief resover configuration
 */
  struct config {
    std::optional<query::config> _query_conf; ///< configuration for queries
    std::optional<size_t> _max_active_queries; ///< maximux active queries ( if limit exceeded will not proceed new query )
    std::optional<std::chrono::milliseconds> _free_query_after_use; ///< free querie after query finished
  };

  /*!\brief ctor with config
   * \param [in] conf configuration
 */
  resolver(config const &conf, std::shared_ptr<bro::ev::factory> factory = nullptr);

  /*! \brief resolve hostname to address
   * \param [in] host_name host name
   * \param [in] host_addr_ver address type
   * \param [in] result_cb callback to call for result.
   * \result true if queiry send, false otherwise and result_cb will call with error
   */
  bool resolve(std::string const &host_name, proto::ip::address::version host_addr_ver, result_cbt &&result_cb);

  /*! \brief main fanction to process queries and callback ( call periodicaly if don't use external factory)
 */
  void proceed();

private:
  /*! \brief free resources per specific query ( not reusable )
 */
  void free_resources_per_query();

  std::shared_ptr<bro::ev::factory> _factory;   ///< event generator
  config _config;                               ///< current config
  std::vector<std::unique_ptr<query>> _queries; ///< queries pool
  std::vector<query *> _query_done_q;           ///< query done queue ( need this because we can't delete
  bro::ev::timer_t _free_query;                 ///< timer to free finished query ( if option set )
  bro::ev::timer_t _free_resources;             ///< using timer to free not using resources ( in c-ares )
};

} // namespace bro::net::dns
