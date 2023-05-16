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
  std::map<std::string, std::map<std::string, CryptoPP::SecByteBlock>> publicKeys;

  std::map<std::string, std::tuple<CryptoPP::DH, CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>> ownKeys;
  std::map<std::string, std::string> waiting_on;


  std::mutex mtx;

  std::mutex network_mut; // for network driver

  std::mutex unclaimed_mtx;
  std::vector<std::pair<CryptoPP::SecByteBlock , CryptoPP::SecByteBlock>> unclaimed_keys;


  void
  ReceiveThread(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);
  void
  SendThread(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);

    // functions to be called by send thread
    void CreateGroupChat(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);
    void AddMember(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys,
                   std::string group, std::string member);
    void SendMessage(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys,
                     std::string group, std::string message);

    // functions to be called by receive thread
    void HandleNewMemberInfoMessage(std::vector<unsigned char> message, std::string sender_id);
    void HandleOldMembersInfoMessage(std::vector<unsigned char> message, std::string sender_id);
    void ReadMessage(std::vector<unsigned char> message, std::string sender_id);
    // this function returns the data payload decrypted or false in the boolean flag.
    std::pair<std::vector<unsigned char>, bool> TrySenderGroupKeys(std::vector<unsigned char> message, std::string sender_id);

    // this function tries to decrypt using the keys in unclaimed_keys
    std::pair<UserToUser_Old_Members_Info_Message, bool> TryUnclaimedKeys(std::vector<unsigned char> message, std::string sender_id);

    void GenerateGroupKeys(std::vector<CryptoPP::SecByteBlock> other_public_values,
                                       std::vector<std::string> group_members, std::string group_id);
    std::pair<CryptoPP::SecByteBlock , CryptoPP::SecByteBlock> GenerateUserToUserKeys(CryptoPP::SecByteBlock other_public_value);


    void RespondToInvite(std::pair<CryptoPP::SecByteBlock , CryptoPP::SecByteBlock> keys, std::vector<unsigned char> message, std::string sender);

    void RespondToResponse(std::pair<CryptoPP::SecByteBlock , CryptoPP::SecByteBlock> keys, std::vector<unsigned char> message, std::string sender);
};
