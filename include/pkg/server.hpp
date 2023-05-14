#pragma once

#include <iostream>
#include <utility>

#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>

#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/db_driver.hpp"
#include "../../include/drivers/network_driver.hpp"
#include "config.hpp"
#include "keyloaders.hpp"

class ServerClient {
public:
  ServerClient(ServerConfig server_config);
  void run(int port);
  bool HandleConnection(std::shared_ptr<NetworkDriver> network_driver,
                        std::shared_ptr<CryptoDriver> crypto_driver);
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
  HandleKeyExchange(std::shared_ptr<NetworkDriver> network_driver,
                    std::shared_ptr<CryptoDriver> crypto_driver);
  void
  HandleLogin(std::shared_ptr<NetworkDriver> network_driver,
              std::shared_ptr<CryptoDriver> crypto_driver, std::string id,
              std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);
  void HandleRegister(
      std::shared_ptr<NetworkDriver> network_driver,
      std::shared_ptr<CryptoDriver> crypto_driver, std::string id,
      std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);
  void MessageReceiver(
          std::shared_ptr<NetworkDriver> network_driver,
          std::shared_ptr<CryptoDriver> crypto_driver, std::string id,
          std::pair<SecByteBlock, SecByteBlock> keys);
  void MessageSender(
          std::shared_ptr<NetworkDriver> network_driver,
          std::shared_ptr<CryptoDriver> crypto_driver, std::string id,
          std::pair<SecByteBlock, SecByteBlock> keys);

private:
  ServerConfig server_config;
  std::shared_ptr<CLIDriver> cli_driver;
  std::shared_ptr<DBDriver> db_driver;

  CryptoPP::DSA::PrivateKey DSA_signing_key;
  CryptoPP::DSA::PublicKey DSA_verification_key;

  // mutex on the table
  std::mutex table_mutex;
  std::condition_variable table_cv;

  std::atomic_int gid_counter;

  // mapping of user_id ==> pair (lock, message queue);
  std::map<std::string, std::deque<std::vector<unsigned char>>> forwarding_table;

  void ListenForConnections(int port);
  void Reset(std::string _);
  void Users(std::string _);

  bool shutdown;
};
