#include <dns/client.h>
#include <iostream>
#include "CLI/CLI.hpp"

int main(int argc, char **argv) {
  CLI::App app{"dns_client"};
  std::vector<std::string> host_names;
  bool is_ipv6 = false;
  bro::net::dns::client::config config;

  app.add_option("-w,--host", host_names, "host name")->required();
  app.add_option("-p,--proto_v6", is_ipv6, "protocol ip v6");
  app.add_option("-f,--free_q", config._resolver_conf._free_query_after_use, "free query after use");
  app.add_option("-q,--max_active_q", config._resolver_conf._max_active_queries, "maximum active queries");
  CLI11_PARSE(app, argc, argv);

  size_t res = 0;
  auto cb = [&](bro::net::proto::ip::address const &addr, std::string const &hostname, char const *err) {
    res++;
    if (err) {
      std::cout << "query failed with error " << err << ", hostname is - " << hostname << std::endl;
    } else {
      std::cout << "query done for hostname " << hostname << ", address - " << addr << std::endl;
    }
  };

  bro::net::dns::client client(config);
  auto ip_ver = is_ipv6 ? bro::net::proto::ip::address::version::e_v6 : bro::net::proto::ip::address::version::e_v4;
  for (std::string const &hname : host_names) {
    client.resolve(hname, ip_ver, cb);
  }

  while (res < host_names.size())
    ;
  if (config._resolver_conf._free_query_after_use)
    std::this_thread::sleep_for((*config._resolver_conf._free_query_after_use)
                                * 10); // just check were there enought time to expire
  return 0;
}
