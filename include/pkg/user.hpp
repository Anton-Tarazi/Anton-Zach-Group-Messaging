#pragma once

#include <iostream>

#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>

#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/network_driver.hpp"
#include "config.hpp"
#include "keyloaders.hpp"

class UserClient {
public:
  UserClient(std::shared_ptr<NetworkDriver> network_driver,
             std::shared_ptr<CryptoDriver> crypto_driver,
             UserConfig user_config);
  void run();
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
  HandleServerKeyExchange();
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
  HandleUserKeyExchange();
  void HandleLoginOrRegister(std::string input);
  void DoLoginOrRegister(std::string input);

private:
  std::string id;
  Certificate_Message certificate;

  UserConfig user_config;
  std::shared_ptr<CLIDriver> cli_driver;
  std::shared_ptr<CryptoDriver> crypto_driver;
  std::shared_ptr<NetworkDriver> network_driver;

  CryptoPP::DSA::PrivateKey DSA_signing_key;
  CryptoPP::DSA::PublicKey DSA_verification_key;
  CryptoPP::DSA::PublicKey DSA_server_verification_key;
  CryptoPP::DSA::PublicKey DSA_remote_verification_key;
  CryptoPP::SecByteBlock prg_seed;

  // group messaging structs
  // map from group chat -> user -> aes, hmac keys
  std::map<std::string, std::map<std::string, std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>>> group_keys;
  std::mutex mtx;

  std::mutex network_mut; // for network driver


  void
  ReceiveThread(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);
  void
  SendThread(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);

    bool CreateGroupChat(std::string name);
};
