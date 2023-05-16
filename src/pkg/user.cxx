#include <cmath>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>
#include <vector>
#include <numeric>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/messages.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/pkg/user.hpp"

/**
 * Constructor. Loads server public key.
 */
UserClient::UserClient(std::shared_ptr<NetworkDriver> network_driver,
                       std::shared_ptr<CryptoDriver> crypto_driver,
                       UserConfig user_config) {

  // Make shared variables.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->crypto_driver = crypto_driver;
  this->network_driver = network_driver;
  this->user_config = user_config;

  this->cli_driver->init();

  // Load server's key
  try {
    LoadDSAPublicKey(user_config.server_verification_key_path,
                     this->DSA_server_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading server keys; exiting");
    throw std::runtime_error("Client could not open server's keys.");
  }

  // Load keys
  try {
    LoadDSAPrivateKey(this->user_config.user_signing_key_path,
                      this->DSA_signing_key);
    LoadDSAPublicKey(this->user_config.user_verification_key_path,
                     this->DSA_verification_key);
    LoadCertificate(this->user_config.user_certificate_path, this->certificate);
    this->DSA_verification_key = this->certificate.verification_key;
    LoadPRGSeed(this->user_config.user_prg_seed_path, this->prg_seed);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading keys, you may consider "
                                    "registering or logging in again!");
  } catch (std::runtime_error &_) {
    this->cli_driver->print_warning("Error loading keys, you may consider "
                                    "registering or logging in again!");
  }

    this->id = this->user_config.user_username;
}

/**
 * Starts repl.
 */
void UserClient::run() {
  REPLDriver<UserClient> repl = REPLDriver<UserClient>(this);
  repl.add_action("login", "login <address> <port>",
                  &UserClient::HandleLoginOrRegister);
  repl.add_action("register", "register <address> <port>",
                  &UserClient::HandleLoginOrRegister);
  repl.run();
}

/**
 * Diffie-Hellman key exchange with server. This function should:
 * 1) Generate a keypair, a, g^a and send it to the server.
 * 2) Receive a public value (g^a, g^b) from the server and verify its
 * signature. 3) Verify that the public value the server received is g^a. 4)
 * Generate a DH shared key and generate AES and HMAC keys.
 * @return tuple of AES_key, HMAC_key
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
UserClient::HandleServerKeyExchange() {

    auto [dh, privateKey, publicKey] =
            this->crypto_driver->DH_initialize();

    // send public key
    UserToServer_DHPublicValue_Message publicKeyMsg;
    publicKeyMsg.public_value = publicKey;
    std::vector<unsigned char> msg;
    publicKeyMsg.serialize(msg);
    this->network_driver->send(msg);

    // receive signed g^a, g^b from server
    std::vector<unsigned char> response = this->network_driver->read();
    ServerToUser_DHPublicValue_Message serverResponse;
    serverResponse.deserialize(response);

    // verify response
    bool valid = this->crypto_driver->DSA_verify(
            this->DSA_server_verification_key,
            concat_byteblocks(serverResponse.server_public_value, serverResponse.user_public_value),
            serverResponse.server_signature
            );

    if (!valid)
        throw std::runtime_error("failed to verify server response");

    // compute keys
    SecByteBlock sharedKey = this->crypto_driver->DH_generate_shared_key(
            dh, privateKey, serverResponse.server_public_value
            );

    SecByteBlock AESKey = this->crypto_driver->AES_generate_key(sharedKey);
    SecByteBlock HMACKey = this->crypto_driver->HMAC_generate_key(sharedKey);

    return {AESKey, HMACKey};

}

/**
 * Diffie-Hellman key exchange with another user. This function shuold:
 * 1) Generate a keypair, a, g^a, signs it, and sends it to the other user.
 *    Use concate_pk_gid_and_cert to sign the message.
 * 2) Receive a public value from the other user and verifies its signature and
 * certificate.
 * 3) Generate a DH shared key and generate AES and HMAC keys.
 * 4) Store the other user's verification key in DSA_remote_verification_key.
 * @return tuple of AES_key, HMAC_key
 */
void UserClient::GenerateGroupKeys(std::vector<CryptoPP::SecByteBlock> other_public_values,
                                  std::vector<std::string> group_members, std::string group_id) {
    std::map<std::string, std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>> group_map;

    std::unique_lock<std::mutex> group_key_lock(this->mtx);
    for (int i = 0; i < group_members.size(); i++) {
        this->group_keys[group_id][group_members[i]] = this->GenerateUserToUserKeys(other_public_values[i]);
    }
}


std::pair<CryptoPP::SecByteBlock , CryptoPP::SecByteBlock> UserClient::GenerateUserToUserKeys(CryptoPP::SecByteBlock other_public_value) {
    auto [dh, privateKey, publicKey] =
            this->crypto_driver->DH_initialize();
    SecByteBlock sharedKey = this->crypto_driver->DH_generate_shared_key(
            dh, privateKey, other_public_value);
    SecByteBlock AESKey = this->crypto_driver->AES_generate_key(sharedKey);
    SecByteBlock HMACKey = this->crypto_driver->HMAC_generate_key(sharedKey);
    return {AESKey, HMACKey};
}

/**
 * User login or register.
 */
void UserClient::HandleLoginOrRegister(std::string input) {
  // Connect to server and check if we are registering.
  std::vector<std::string> input_split = string_split(input, ' ');
  if (input_split.size() != 3) {
    this->cli_driver->print_left("invalid number of arguments.");
    return;
  }
  std::string address = input_split[1];
  int port = std::stoi(input_split[2]);
  this->network_driver->connect(address, port);
  this->DoLoginOrRegister(input_split[0]);
}

/**
 * User login or register. This function should:
 * 1) Handles key exchange with the server.
 * 2) Tells the server our ID and intent.
 * 3) Receives a salt from the server.
 * 4) Generates and sends a hashed and salted password.
 * 5) (if registering) Receives a PRG seed from the server, store in
 * this->prg_seed. 6) Generates and sends a 2FA response. 7) Generates a DSA
 * keypair, and send vk to the server for signing. 8) Receives and save cert in
 * this->certificate 9) Receives and saves the keys, certificate, and prg seed.
 * Remember to store DSA keys in this->DSA_signing_key and
 * this->DSA_verification_key
 */
void UserClient::DoLoginOrRegister(std::string input) {

    std::vector<unsigned char> encryptedMessage, encryptedResponse, decryptedResponse;
    bool valid;

    auto [AESKey, HMACKey] = this->HandleServerKeyExchange();

    // send ID and intent
    UserToServer_IDPrompt_Message userIDMsg;
    userIDMsg.id = this->id;
    userIDMsg.new_user = input == "register";
    encryptedMessage =
            this->crypto_driver->encrypt_and_tag(AESKey, HMACKey, &userIDMsg);
    this->network_driver->send(encryptedMessage);

    // receive salt
    ServerToUser_Salt_Message serverSaltMsg;
    encryptedResponse = this->network_driver->read();
    std::tie(decryptedResponse, valid) =
            this->crypto_driver->decrypt_and_verify(AESKey, HMACKey, encryptedResponse);
    if (!valid)
        throw std::runtime_error{"Received invalid server response"};
    serverSaltMsg.deserialize(decryptedResponse);

    // get password
    std::string password = this->user_config.user_password;

    // send salted password
    UserToServer_HashedAndSaltedPassword_Message hashedPasswordMsg;
    hashedPasswordMsg.hspw = this->crypto_driver->hash(password + serverSaltMsg.salt);
    encryptedMessage =
            this->crypto_driver->encrypt_and_tag(AESKey, HMACKey, &hashedPasswordMsg);
    this->network_driver->send(encryptedMessage);

    // get seed if registering
    if (input == "register") {
        ServerToUser_PRGSeed_Message serverPRGSeedMsg;
        encryptedResponse = this->network_driver->read();
        std::tie(decryptedResponse, valid) =
                this->crypto_driver->decrypt_and_verify(AESKey, HMACKey, encryptedResponse);
        if (!valid)
            throw std::runtime_error("Received invalid server response");

        serverPRGSeedMsg.deserialize(decryptedResponse);
        this->prg_seed = serverPRGSeedMsg.seed;
        SavePRGSeed(this->user_config.user_prg_seed_path, this->prg_seed);
    }

    // calculate and send PRG value
    UserToServer_PRGValue_Message userPRGValueMsg;
    SecByteBlock r = this->crypto_driver->prg(
            this->prg_seed,
            integer_to_byteblock(this->crypto_driver->nowish()),
            PRG_SIZE
            );
    userPRGValueMsg.value = r;
    encryptedMessage =
            this->crypto_driver->encrypt_and_tag(AESKey, HMACKey, &userPRGValueMsg);
    this->network_driver->send(encryptedMessage);

    // generate and store DSA keys
    if (input == "register") {
        std::tie(this->DSA_signing_key, this->DSA_verification_key) =
                this->crypto_driver->DSA_generate_keys();
        SaveDSAPrivateKey(this->user_config.user_signing_key_path, this->DSA_signing_key);
        SaveDSAPublicKey(this->user_config.user_verification_key_path, this->DSA_verification_key);
    }

    // send verification key
    UserToServer_VerificationKey_Message userVerificationKeyMsg;
    userVerificationKeyMsg.verification_key = this->DSA_verification_key;
    encryptedMessage =
            this->crypto_driver->encrypt_and_tag(AESKey, HMACKey, &userVerificationKeyMsg);
    this->network_driver->send(encryptedMessage);

    // receive and store server certificate
    ServerToUser_IssuedCertificate_Message serverCertMsg;
    encryptedResponse = this->network_driver->read();
    std::tie(decryptedResponse, valid) =
            this->crypto_driver->decrypt_and_verify(AESKey, HMACKey, encryptedResponse);
    if (!valid)
        throw std::runtime_error("Invalid server response");

    serverCertMsg.deserialize(decryptedResponse);
    this->certificate = serverCertMsg.certificate;
    SaveCertificate(this->user_config.user_certificate_path, this->certificate);

    auto keys = std::make_pair(AESKey, HMACKey);

    // At this point we have a secure connection to server

  boost::thread msgListener =
      boost::thread(boost::bind(&UserClient::ReceiveThread, this, keys));
  this->SendThread(keys);
  msgListener.join();
}

/**
 * Listen for messages and print to CLI.
 */
void UserClient::ReceiveThread(
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {
  while (true) {
    std::vector<unsigned char> encrypted_msg_data;
    try {
      encrypted_msg_data = this->network_driver->read();
    } catch (std::runtime_error &_) {
      this->cli_driver->print_info("Received EOF; closing connection.");
      return;
    }
    this->cli_driver->print_info("Received message");
    // Check if HMAC is valid.
    auto msg_data = this->crypto_driver->decrypt_and_verify(
        keys.first, keys.second, encrypted_msg_data);
    if (!msg_data.second) {
      this->cli_driver->print_warning(
          "Invalid MAC on message; closing connection.");
      this->network_driver->disconnect();
      throw std::runtime_error("User sent message with invalid MAC.");
    }


    if (msg_data.first[0] == (char) MessageType::ServerToUser_GID_Message) {
        ServerToUser_GID_Message gid;
        gid.deserialize(msg_data.first);
        std::scoped_lock<std::mutex> l(this->mtx);
        this->group_keys[gid.group_id]; // put an entry in map

        this->ownKeys[gid.group_id] = this->crypto_driver->DH_initialize();
        this->cli_driver->print_info("Received GID value of :" + gid.group_id);
        continue;
    }

    assert(msg_data.first[0] == MessageType::ServerToUser_Wrapper_Message);

    ServerToUser_Wrapper_Message server_msg;
    server_msg.deserialize(msg_data.first);

    auto sender = server_msg.sender_id;
    MessageType::T type = server_msg.type;
    auto command = server_msg.message;
    switch(type) {

          case MessageType::UserToUser_Invite_Message:
                this->RespondToInvite(keys, command, sender);
                break;
          case MessageType::UserToUser_Invite_Response_Message:
              this->RespondToResponse(keys, command, sender);
              break;
          case MessageType::UserToUser_New_Member_Info_Message:
              this->HandleNewMemberInfoMessage(command, sender);
              break;
          case MessageType::UserToUser_Old_Members_Info_Message:
              this->HandleOldMembersInfoMessage(command, sender);
              break;
          case MessageType::UserToUser_Message_Message:
                this->ReadMessage(command, sender);
              break;
          default:
              throw std::runtime_error("received unexpected message type");
    }
  }
}


void UserClient::RespondToInvite(std::pair<CryptoPP::SecByteBlock , CryptoPP::SecByteBlock> keys, std::vector<unsigned char> message, std::string sender) {


    std::unique_lock<std::mutex> l(this->network_mut);
    std::unique_lock<std::mutex> key_lock(this->unclaimed_mtx);

    UserToUser_Invite_Message userResponse;
    userResponse.deserialize(message);

    this->DSA_remote_verification_key = userResponse.certificate.verification_key;

    // verify response
    bool valid1 = this->crypto_driver->DSA_verify(
            userResponse.certificate.verification_key,
            concat_byteblock_and_cert(userResponse.public_value, userResponse.certificate),
            userResponse.user_signature
    );

    bool valid2 = this->crypto_driver->DSA_verify(
            this->DSA_server_verification_key,
            concat_string_and_dsakey(userResponse.certificate.id, userResponse.certificate.verification_key),
            userResponse.certificate.server_signature
    );

    if (!valid1 || !valid2)
        throw std::runtime_error("failed to verify user response");

    // generate own key pair

    auto [dh, privateKey, publicKey] =
            this->crypto_driver->DH_initialize();

    // send public key
    std::vector<unsigned char> publicKeyAndCert =
            concat_byteblock_and_cert(publicKey, this->certificate);
    std::string signature =
            this->crypto_driver->DSA_sign(this->DSA_signing_key, publicKeyAndCert);
    UserToUser_Invite_Response_Message userMsg;
    userMsg.public_value = publicKey;
    userMsg.certificate = this->certificate;
    userMsg.user_signature = signature;

    std::vector<unsigned char> msg;
    userMsg.serialize(msg);

    UserToServer_Wrapper_Message wrapper;
    wrapper.sender_id = this->id;
    wrapper.receiver_id = sender;
    wrapper.type = MessageType::UserToUser_Invite_Response_Message;
    wrapper.message = msg;

    auto encrypted_msg = this->crypto_driver->encrypt_and_tag(
            keys.first, keys.second, &wrapper
            );

    this->network_driver->send(encrypted_msg);


    // compute keys
    SecByteBlock sharedKey = this->crypto_driver->DH_generate_shared_key(
            dh, privateKey, userResponse.public_value
    );

    SecByteBlock AESKey = this->crypto_driver->AES_generate_key(sharedKey);
    SecByteBlock HMACKey = this->crypto_driver->HMAC_generate_key(sharedKey);

    this->unclaimed_keys.emplace_back(AESKey, HMACKey);


}


void UserClient::RespondToResponse(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys,
                                   std::vector<unsigned char> message, std::string sender) {
    std::unique_lock<std::mutex> l(this->network_mut);
    std::unique_lock<std::mutex> key_lock(this->mtx);
    cli_driver->print_info("Handling response from: " + sender);

    UserToUser_Invite_Response_Message userResponse;
    userResponse.deserialize(message);

    this->DSA_remote_verification_key = userResponse.certificate.verification_key;

    // verify response
    bool valid1 = this->crypto_driver->DSA_verify(
            userResponse.certificate.verification_key,
            concat_byteblock_and_cert(userResponse.public_value, userResponse.certificate),
            userResponse.user_signature
    );

    bool valid2 = this->crypto_driver->DSA_verify(
            this->DSA_server_verification_key,
            concat_string_and_dsakey(userResponse.certificate.id, userResponse.certificate.verification_key),
            userResponse.certificate.server_signature
    );

    if (!valid1 || !valid2)
        throw std::runtime_error("failed to verify user response");

    std::string group = this->waiting_on[sender];

    cli_driver->print_info("Group ID: " + group);

    auto ownKeys = this->ownKeys[group];

    this->publicKeys[group][sender] = userResponse.public_value;

    // compute keys
    SecByteBlock sharedKey = this->crypto_driver->DH_generate_shared_key(
            std::get<0>(ownKeys), std::get<1>(ownKeys), userResponse.public_value
    );

    SecByteBlock AESKey = this->crypto_driver->AES_generate_key(sharedKey);
    SecByteBlock HMACKey = this->crypto_driver->HMAC_generate_key(sharedKey);

    this->group_keys[group][sender] = {AESKey, HMACKey};

    // send old member info
    std::vector<std::string> group_members;
    std::vector<CryptoPP::SecByteBlock> other_vals;
    for (auto member: this->publicKeys[group]) {
        if (member.first != this->id && member.first != sender) {
            group_members.push_back(member.first);
            other_vals.push_back(member.second);

        }
    }

    UserToUser_Old_Members_Info_Message membersInfo;
    membersInfo.num_members = std::to_string(group_members.size());
    membersInfo.group_id = group;
    membersInfo.group_members = group_members;
    membersInfo.other_public_values = other_vals;

    cli_driver->print_info("MEMBER COUNT :" + membersInfo.num_members);

    auto encrypted_other = this->crypto_driver->encrypt_and_tag(
            AESKey, HMACKey, &membersInfo
            );

    UserToServer_Wrapper_Message serverMsg;
    serverMsg.sender_id = this->id;
    serverMsg.receiver_id = sender;
    serverMsg.type = MessageType::UserToUser_Old_Members_Info_Message;
    serverMsg.message = encrypted_other;

    auto encrypted_server = this->crypto_driver->encrypt_and_tag(
            keys.first, keys.second, &serverMsg
            );
    this->network_driver->send(encrypted_server);

    // send new member info
    for (auto member: this->group_keys[group]) {
        if (member.first != this->id && member.first != sender) {
            cli_driver->print_info("TAGGED");
            UserToUser_New_Member_Info_Message newInfo;
            newInfo.other_public_value = userResponse.public_value;
            newInfo.group_id = group;
            newInfo.group_member = sender;

            auto encrypted_new_info = this->crypto_driver->encrypt_and_tag(
                    member.second.first, member.second.second, &newInfo
                    );

            UserToServer_Wrapper_Message server_message;
            server_message.sender_id = this->id;
            server_message.receiver_id = member.first;
            server_message.type = MessageType::UserToUser_New_Member_Info_Message;
            server_message.message = encrypted_new_info;

            auto encrypted_server_message = this->crypto_driver->encrypt_and_tag(
                    keys.first, keys.second, &server_message
                    );
            this->network_driver->send(encrypted_server_message);

        }

    }


}

void UserClient::ReadMessage(std::vector<unsigned char> message, std::string sender_id) {
    cli_driver->print_info("Reading text message from sender: " + sender_id);
    auto [payload, ok] = this->TrySenderGroupKeys(message, sender_id);
    if (!ok) {
        throw std::runtime_error("Received a message which we cannot decrypt");
    }
    UserToUser_Message_Message utumm;
    utumm.deserialize(payload);
    this->cli_driver->print_info(sender_id + " said: " + utumm.msg +  " in group " + utumm.group_id);
}

std::pair<std::vector<unsigned char>, bool> UserClient::TrySenderGroupKeys(std::vector<unsigned char> message, std::string sender_id) {
    std::unique_lock<std::mutex> key_lock(this->mtx);
    for (auto iter: this->group_keys) {
        cli_driver->print_info("ITERATING THROUGH GROUPS");
        cli_driver->print_info("Trying keys from group: ");
        cli_driver->print_info("Trying keys from sender: " + sender_id);
        cli_driver->print_info(std::to_string(this->group_keys["0"].contains(sender_id)));
        auto key_pair = iter.second.find(sender_id);
        cli_driver->print_info("Does group_key contain? " + std::to_string(iter.second.contains(sender_id)));
        if (key_pair != iter.second.end()) {
            cli_driver->print_info("TRYING A KEY");
            auto [payload, ok] = this->crypto_driver->decrypt_and_verify(
                     key_pair->second.first,
                     key_pair->second.second,
                     message);
            if (ok) {
                return std::make_pair(payload, ok);
            }
        }
    }
    std::vector<unsigned char> null;
    return std::make_pair(null, false);
}

void UserClient::HandleOldMembersInfoMessage(std::vector<unsigned char> message, std::string sender_id) {
    auto [utuomim, ok] = this->TryUnclaimedKeys(message, sender_id);
    if (!ok) {
        throw std::runtime_error("Received a message that can't be decrypted");
    }
    cli_driver->print_info("INSERTED?: " + std::to_string(this->group_keys["0"].contains(sender_id)));
    int length = std::stoi(utuomim.num_members);
    assert(length == utuomim.other_public_values.size());
    this->GenerateGroupKeys(utuomim.other_public_values, utuomim.group_members, utuomim.group_id);
    cli_driver->print_info("INSERTED?: " + std::to_string(this->group_keys["0"].contains(sender_id)));
}

std::pair<UserToUser_Old_Members_Info_Message, bool> UserClient::TryUnclaimedKeys(std::vector<unsigned char> message,
                                                                         std::string sender_id) {
    std::unique_lock<std::mutex> key_lock(this->unclaimed_mtx);
    UserToUser_Old_Members_Info_Message utuomim;
    for (auto iter = this->unclaimed_keys.begin(); iter != this->unclaimed_keys.end(); iter++) {
        auto [aes_key, hmac_key] = *iter.base();
        auto [payload, ok] = this->crypto_driver->decrypt_and_verify(
                aes_key,
                hmac_key,
                message);
        if (ok) {
            // found a valid keypair, we want to now add it to the group_keys mapping
            utuomim.deserialize(payload);
            this->unclaimed_keys.erase(iter);
            key_lock.unlock();
            std::unique_lock<std::mutex> group_keys_lock(this->mtx);
            this->group_keys[utuomim.group_id].insert({sender_id, {aes_key, hmac_key}});
            assert((this->group_keys[utuomim.group_id][sender_id].first == aes_key) &&
            (this->group_keys[utuomim.group_id][sender_id].second == hmac_key));
            cli_driver->print_info("ADDED: " + sender_id + " to group " + utuomim.group_id);
            return {utuomim, ok };
        }
    }
    return {utuomim, false};
}


void UserClient::HandleNewMemberInfoMessage(std::vector<unsigned char> message, std::string sender_id) {
    auto [payload, ok] = this->TrySenderGroupKeys(message, sender_id);
    if (!ok) {
        throw std::runtime_error("Received a message which we cannot decrypt");
    }
    cli_driver->print_info("Handling New Member Info Message");
    UserToUser_New_Member_Info_Message utunmim;
    utunmim.deserialize(payload);
    std::unique_lock<std::mutex> group_keys_lock(this->mtx);
    this->group_keys[utunmim.group_id][utunmim.group_member] = this->GenerateUserToUserKeys(utunmim.other_public_value);
    this->cli_driver->print_info("Added new user " + utunmim.group_member + " to group " + utunmim.group_id);
}

/**
 * Listen for stdin and send to other party.
 */
void UserClient::SendThread(
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {
  std::string plaintext;
  while (std::getline(std::cin, plaintext)) {
    // Read from STDIN.
    if (!plaintext.empty()) {

        auto commands = string_split(plaintext, ' ');
        if (commands[0] == "help") {
            this->cli_driver->print_info("commands: \n create <group name>"
                                         "\n add <group name> <user id> \n"
                                         "send <group name> <message>"
                                         "\n info");
        } else if (commands[0] == "create") {
            if (commands.size() != 2) {
                this->cli_driver->print_info("usage: create <group name>");
            } else {
                this->CreateGroupChat(keys);
            }
        } else if (commands[0] == "add") {
            if (commands.size() != 3) {
                this->cli_driver->print_info("usage: add <group name> <user id>");
            } else {
                this->AddMember(keys, commands[1], commands[2]);
            }
        } else if (commands[0] == "send") {
            if (commands.size() != 3) {
                this->cli_driver->print_info("usage: send <group name> <message>");
            } else {

                std::string message = std::accumulate(commands.begin() + 2, commands.end(), std::string(""));
                this->SendMessage(keys, commands[1], message);
            }
        } else if (commands[0] == "info") {
            if (commands.size() != 1) {
                this->cli_driver->print_info("usage: info");
            } else { // print all group chats we're part of
//                std::scoped_lock<std::mutex> l(this->mtx);

//                for (auto &group_chat: this->group_keys) {
//                    this->cli_driver->print_info("name: " + group_chat.first + ":");
//                    for (auto &member: group_chat.second) {
//                        this->cli_driver->print_info(member.first);
//                    }
//                    this->cli_driver->print_info(""); // blank line
//                } // todo: rewrite info command
            }
        } else {
            this->cli_driver->print_info("invalid command \n commands: \n create <group name>"
                                         "\n add <group name> <user id> \n"
                                         "send <group name> <message>"
                                         "\n info");
        }
    }
  }
  this->cli_driver->print_info("Received EOF from user; closing connection");
  this->network_driver->disconnect();
}


void UserClient::CreateGroupChat(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {

    std::unique_lock<std::mutex> l(this->network_mut);

    UserToServer_GID_Message msg;
    auto enc =
            this->crypto_driver->encrypt_and_tag(keys.first, keys.second, &msg);
    this->network_driver->send(enc);
}

void UserClient::AddMember(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys,
                           std::string group, std::string member) {

    std::unique_lock<std::mutex> l(this->network_mut);
    std::unique_lock<std::mutex> lk(this->mtx);

    if (!this->group_keys.count(group)) {
        this->cli_driver->print_warning("group does not exist");
        return;
    }

    waiting_on[member] = group;

    UserToServer_Wrapper_Message userMsg;
    userMsg.type = MessageType::UserToUser_Invite_Message;
    userMsg.sender_id = this->id;
    userMsg.receiver_id = member;

    UserToUser_Invite_Message invite;
    invite.public_value = std::get<2>(this->ownKeys[group]);
    invite.certificate = this->certificate;

    std::vector<unsigned char> publicKeyAndCert =
            concat_byteblock_and_cert(invite.public_value, this->certificate);
    invite.user_signature =
            this->crypto_driver->DSA_sign(this->DSA_signing_key, publicKeyAndCert);

    cli_driver->print_info("1");
    std::vector<unsigned char> payload;
    invite.serialize(payload);
    userMsg.message = payload;

    cli_driver->print_info("1");
    auto encrypted_server_msg = this->crypto_driver->encrypt_and_tag(
            keys.first, keys.second, &userMsg
            );

    cli_driver->print_info("1");
    this->network_driver->send(encrypted_server_msg);

}


void UserClient::SendMessage(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys,
                             std::string group, std::string message) {

    std::unique_lock<std::mutex> l(this->network_mut);
    std::unique_lock<std::mutex> lk(this->mtx);

    cli_driver->print_info("Sending message to group: " + group);

    if (!this->group_keys.count(group)) {
        this->cli_driver->print_warning("group does not exist");
        return;
    }

    UserToUser_Message_Message message_message;
    message_message.msg = message;
    message_message.group_id = group;

    // send separate message to each member of group
    for (auto &group_member: this->group_keys[group]) {
        auto encrypted_message = this->crypto_driver->encrypt_and_tag(
                group_member.second.first, group_member.second.second, &message_message
                );

        UserToServer_Wrapper_Message wrapper;
        wrapper.type = MessageType::UserToUser_Message_Message;
        wrapper.sender_id = this->id;
        wrapper.receiver_id = group_member.first;
        wrapper.message = encrypted_message;

        auto encrypt_to_server = this->crypto_driver->encrypt_and_tag(
                keys.first, keys.second, &wrapper
                );
        this->network_driver->send(encrypt_to_server);
    }
}
