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
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
UserClient::HandleUserKeyExchange() {

    auto [dh, privateKey, publicKey] =
            this->crypto_driver->DH_initialize();

    // send public key
    std::vector<unsigned char> publicKeyAndCert =
            concat_byteblock_and_cert(publicKey, this->certificate);
    std::string signature =
            this->crypto_driver->DSA_sign(this->DSA_signing_key, publicKeyAndCert);
    UserToUser_DHPublicValue_Message userMsg;
    userMsg.public_value = publicKey;
    userMsg.certificate = this->certificate;
    userMsg.user_signature = signature;

    std::vector<unsigned char> msg;
    userMsg.serialize(msg);
    this->network_driver->send(msg);

    // receive signed g^b from other user
    std::vector<unsigned char> response = this->network_driver->read();
    UserToUser_DHPublicValue_Message userResponse;
    userResponse.deserialize(response);

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

    this->DSA_remote_verification_key = userResponse.certificate.verification_key;

    // compute keys
    SecByteBlock sharedKey = this->crypto_driver->DH_generate_shared_key(
            dh, privateKey, userResponse.public_value
    );

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
                // TODO- validate and respond with UserToUser_Invite_Response_Message
                break;
          case MessageType::UserToUser_Invite_Response_Message:
              // TODO- respond with UserToUser_Old_Members_Info_Message
              // and send UserToUser_New_Member_Info_Message to rest of group
              // also calculate aes and hmac shared keys with new user and
              // update group chats struct
              break;
          case MessageType::UserToUser_New_Member_Info_Message:
              // TODO calculate shared keys and update map
              break;
          case MessageType::UserToUser_Old_Members_Info_Message:
              // TODO calculate shared keys and update map
              break;
          case MessageType::UserToUser_Message_Message:
              std::unique_lock<std::mutex> key_lock(this->mtx);
              break;
          default:
              throw std::runtime_error("received unexpected message type");
    }
  }
}

std::pair<std::vector<unsigned char>, bool> UserClient::TrySenderKeys(std::vector<unsigned char> message, std::string sender_id) {

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
                this->SendMessage(keys, commands[0], message);
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


//        // TODO for reference: should delete most of this
//      UserToUser_Message_Message u2u_msg;
//      u2u_msg.msg = plaintext;
//
//      std::vector<unsigned char> msg_data =
//          this->crypto_driver->encrypt_and_tag(keys.first, keys.second,
//                                               &u2u_msg);
//      try {
//          std::unique_lock l(this->mtx);
//        this->network_driver->send(msg_data);
//      } catch (std::runtime_error &_) {
//        this->cli_driver->print_info(
//            "Other side is closed, closing connection");
//        this->network_driver->disconnect();
//        return;
//      }
    }
    this->cli_driver->print_right(plaintext);
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

    UserToServer_Wrapper_Message userMsg;
    userMsg.type = MessageType::UserToUser_Invite_Message;
    userMsg.sender_id = this->id;
    userMsg.receiver_id = member;

    UserToUser_Invite_Message invite;
    invite.public_value = this->ownKeys[group].second;
    invite.certificate = this->certificate;
    invite.group_id = group;

    std::vector<unsigned char> publicKeyAndCert =
            concat_byteblock_group_and_cert(invite.public_value, group, this->certificate);
    invite.user_signature =
            this->crypto_driver->DSA_sign(this->DSA_signing_key, publicKeyAndCert);


    auto encrypted_invite = this->crypto_driver->encrypt_and_tag(
                                                this->group_keys[group][member].first,
                                                this->group_keys[group][member].second,
                                                                 &invite);
    userMsg.message = encrypted_invite;

    auto encrypted_server_msg = this->crypto_driver->encrypt_and_tag(
            keys.first, keys.second, &userMsg
            );
    this->network_driver->send(encrypted_server_msg);

}


void UserClient::SendMessage(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys,
                             std::string group, std::string message) {

    std::unique_lock<std::mutex> l(this->network_mut);
    std::unique_lock<std::mutex> lk(this->mtx);

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
