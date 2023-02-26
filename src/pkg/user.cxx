#include <cmath>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>
#include <vector>

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
  repl.add_action("listen", "listen <port>", &UserClient::HandleUser);
  repl.add_action("connect", "connect <address> <port>",
                  &UserClient::HandleUser);
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
 *    Use concat_byteblock_and_cert to sign the message.
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
    userIDMsg.id = this->user_config.user_username;
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

}

/**
 * Handles communicating with another user. This function
 * 1) Prompts the CLI to see if we're registering or logging in.
 * 2) Handles key exchange with the other user.
 */
void UserClient::HandleUser(std::string input) {
  // Handle if connecting or listening; parse user input.
  std::vector<std::string> args = string_split(input, ' ');
  bool isListener = args[0] == "listen";
  if (isListener) {
    if (args.size() != 2) {
      this->cli_driver->print_warning("Invalid args, usage: listen <port>");
      return;
    }
    int port = std::stoi(args[1]);
    this->network_driver->listen(port);
  } else {
    if (args.size() != 3) {
      this->cli_driver->print_warning(
          "Invalid args, usage: connect <ip> <port>");
      return;
    }
    std::string ip = args[1];
    int port = std::stoi(args[2]);
    this->network_driver->connect(ip, port);
  }

  // Exchange keys.
  auto keys = this->HandleUserKeyExchange();

  // Clear the screen
  this->cli_driver->init();
  this->cli_driver->print_success("Connected!");

  // Set up communication
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

    // Decrypt and print.
    UserToUser_Message_Message u2u_msg;
    u2u_msg.deserialize(msg_data.first);
    this->cli_driver->print_left(u2u_msg.msg);
  }
}

/**
 * Listen for stdin and send to other party.
 */
void UserClient::SendThread(
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {
  std::string plaintext;
  while (std::getline(std::cin, plaintext)) {
    // Read from STDIN.
    if (plaintext != "") {
      UserToUser_Message_Message u2u_msg;
      u2u_msg.msg = plaintext;

      std::vector<unsigned char> msg_data =
          this->crypto_driver->encrypt_and_tag(keys.first, keys.second,
                                               &u2u_msg);
      try {
        this->network_driver->send(msg_data);
      } catch (std::runtime_error &_) {
        this->cli_driver->print_info(
            "Other side is closed, closing connection");
        this->network_driver->disconnect();
        return;
      }
    }
    this->cli_driver->print_right(plaintext);
  }
  this->cli_driver->print_info("Received EOF from user; closing connection");
  this->network_driver->disconnect();
}
