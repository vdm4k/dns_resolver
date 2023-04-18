#include <dns/resolver.h>
#include <iostream>

using q_result = std::optional<std::pair<bro::net::proto::ip::address, char const *>>;

void print_query_result(std::string q_name, q_result &q_res) {
  if (q_res->second) {
    std::cout << q_name << " " << q_res->second << std::endl;
  } else {
    std::cout << q_name << " " << q_res->first << std::endl;
  }
}

int main() {
  bro::net::dns::resolver dns;
  q_result first_q_res, second_q_res;
  std::string fq = "google.com";
  std::string sq = "blahbalh.com";
  dns.resolve(fq,
              bro::net::proto::ip::address::version::e_v6,
              [&first_q_res](bro::net::proto::ip::address const &addr, char const *err) {
                first_q_res = {addr, err};
              });
  dns.resolve(sq,
              bro::net::proto::ip::address::version::e_v4,
              [&second_q_res](bro::net::proto::ip::address const &addr, char const *err) {
                second_q_res = {addr, err};
              });

  while (!first_q_res || !second_q_res)
    dns.proceed();
  print_query_result(fq, first_q_res);
  print_query_result(sq, second_q_res);
  first_q_res.reset();
  second_q_res.reset();

  //reuse
  dns.resolve(sq,
              bro::net::proto::ip::address::version::e_v6,
              [&first_q_res](bro::net::proto::ip::address const &addr, char const *err) {
                first_q_res = {addr, err};
              });
  dns.resolve(fq,
              bro::net::proto::ip::address::version::e_v4,
              [&second_q_res](bro::net::proto::ip::address const &addr, char const *err) {
                second_q_res = {addr, err};
              });

  while (!first_q_res || !second_q_res)
    dns.proceed();
  print_query_result(sq, first_q_res);
  print_query_result(fq, second_q_res);
  return 0;
}
