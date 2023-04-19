#include <dns/resolver.h>
#include <iostream>

int main() {
  bro::net::dns::resolver dns;
  std::string fq = "google.com";
  std::string sq = "blahbalh.com";
  size_t res = 0;
  auto cb = [&](bro::net::proto::ip::address const &addr, std::string const &hostname, char const *err) {
    res++;
    if (err) {
      std::cout << "query failed with error " << err << ", hostname is - " << hostname << std::endl;
    } else {
      std::cout << "query done for hostname " << hostname << ", address - " << addr << std::endl;
    }
  };
  dns.resolve(fq, bro::net::proto::ip::address::version::e_v6, cb);
  dns.resolve(sq, bro::net::proto::ip::address::version::e_v4, cb);
  while (res < 2)
    dns.proceed();

  //reuse
  dns.resolve(sq, bro::net::proto::ip::address::version::e_v6, cb);
  dns.resolve(fq, bro::net::proto::ip::address::version::e_v4, cb);
  while (res < 4)
    dns.proceed();
  return 0;
}
