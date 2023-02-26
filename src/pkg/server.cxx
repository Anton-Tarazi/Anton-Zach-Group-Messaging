#include <cmath>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/messages.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/pkg/server.hpp"
#include "../../include/pkg/user.hpp"

/**
 * Constructor
 */
ServerClient::ServerClient(ServerConfig server_config) {
  // Initialize cli driver.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->cli_driver->init();

  // Initialize database driver.
  this->db_driver = std::make_shared<DBDriver>();
  this->db_driver->open(server_config.server_db_path);
  this->db_driver->init_tables();

  // Load server keys.
  try {
    LoadDSAPrivateKey(server_config.server_signing_key_path,
                      this->DSA_signing_key);
    LoadDSAPublicKey(server_config.server_verification_key_path,
                     this->DSA_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Could not find server keys, generating them instead.");
    CryptoDriver crypto_driver;
    auto keys = crypto_driver.DSA_generate_keys();
    this->DSA_signing_key = keys.first;
    this->DSA_verification_key = keys.second;
    SaveDSAPrivateKey(server_config.server_signing_key_path,
                      this->DSA_signing_key);
    SaveDSAPublicKey(server_config.server_verification_key_path,
                     this->DSA_verification_key);
  }
}

/**
 * Run the server on the given port. First initializes the CLI and database,
 * then starts listening for connections.
 */
void ServerClient::run(int port) {
  // Start listener thread
  std::thread listener_thread(&ServerClient::ListenForConnections, this, port);
  listener_thread.detach();

  // Start REPL
  REPLDriver<ServerClient> repl = REPLDriver<ServerClient>(this);
  repl.add_action("reset", "reset", &ServerClient::Reset);
  repl.add_action("users", "users", &ServerClient::Users);
  repl.run();
}

/**
 * Reset database
 *
 */
void ServerClient::Reset(std::string _) {
  this->cli_driver->print_info("Erasing users!");
  this->db_driver->reset_tables();
}

/**
 * Prints all usernames
 */
void ServerClient::Users(std::string _) {
  this->cli_driver->print_info("Printing users!");
  std::vector<std::string> usernames = this->db_driver->get_users();
  if (usernames.size() == 0) {
    this->cli_driver->print_info("No registered users!");
    return;
  }
  for (std::string username : usernames) {
    this->cli_driver->print_info(username);
  }
}

/**
 * @brief This is the logic for the listener thread
 */
void ServerClient::ListenForConnections(int port) {
  while (1) {
    // Create new network driver and crypto driver for this connection
    std::shared_ptr<NetworkDriver> network_driver =
        std::make_shared<NetworkDriverImpl>();
    std::shared_ptr<CryptoDriver> crypto_driver =
        std::make_shared<CryptoDriver>();
    network_driver->listen(port);
    std::thread connection_thread(&ServerClient::HandleConnection, this,
                                  network_driver, crypto_driver);
    connection_thread.detach();
  }
}

/**
 * Handle keygen and handle either logins or registrations. This function
 * should: 1) Handle key exchange with the user. 2) Reads a
 * UserToServer_IDPrompt_Message and determines whether the user is attempting
 * to login or register and calls the corresponding function. 3) Disconnect the
 * network_driver, then return true.
 */
bool ServerClient::HandleConnection(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver) {
    try {

        std::vector<unsigned char> encryptedResponse, decryptedResponse;
        bool valid;

        auto [AESKey, HMACKey] =
                this->HandleKeyExchange(network_driver, crypto_driver);

        UserToServer_IDPrompt_Message userIdMsg;
        encryptedResponse = network_driver->read();
        std::tie(decryptedResponse, valid) =
                crypto_driver->decrypt_and_verify(AESKey, HMACKey, encryptedResponse);
        if (!valid)
            throw std::runtime_error("Received invalid user response");
        userIdMsg.deserialize(decryptedResponse);


        if (userIdMsg.new_user) {
            this->HandleRegister(network_driver, crypto_driver, userIdMsg.id, {AESKey, HMACKey});
        } else {
            this->HandleLogin(network_driver, crypto_driver, userIdMsg.id, {AESKey, HMACKey});
        }

        network_driver->disconnect();
        return false;

    } catch (...) {
        this->cli_driver->print_warning("Connection threw an error");
        network_driver->disconnect();
        return false;
    }
}

/**
 * Diffie-Hellman key exchange. This function should:
 * 1) Receive the user's public value
 * 2) Generate and send a signed DH public value
 * 2) Generate a DH shared key and generate AES and HMAC keys.
 * @return tuple of AES_key, HMAC_key
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
ServerClient::HandleKeyExchange(std::shared_ptr<NetworkDriver> network_driver,
                                std::shared_ptr<CryptoDriver> crypto_driver) {

    auto [dh, privateKey, publicKey] =
            crypto_driver->DH_initialize();

    // receive user public value
    std::vector<unsigned char> userPublicKeyMsg = network_driver->read();
    UserToServer_DHPublicValue_Message userPublicKey;
    userPublicKey.deserialize(userPublicKeyMsg);

    // sign user public value + server public value
    std::vector<unsigned char> concatPublicKeys =
            concat_byteblocks(publicKey, userPublicKey.public_value);
    std::string serverPublicKeySignature = crypto_driver->DSA_sign(this->DSA_signing_key, concatPublicKeys);

    // send public value + signature back to user
    ServerToUser_DHPublicValue_Message serverPublicValue;
    serverPublicValue.server_public_value = publicKey;
    serverPublicValue.user_public_value = userPublicKey.public_value;
    serverPublicValue.server_signature = serverPublicKeySignature;
    std::vector<unsigned char> serverPublicValueMsg;
    serverPublicValue.serialize(serverPublicValueMsg);
    network_driver->send(serverPublicValueMsg);

    // generate shared keys
    SecByteBlock sharedKey = crypto_driver->DH_generate_shared_key(
            dh, privateKey, userPublicKey.public_value
            );

    SecByteBlock AESKey = crypto_driver->AES_generate_key(sharedKey);
    SecByteBlock HMACKey = crypto_driver->HMAC_generate_key(sharedKey);

    return {AESKey, HMACKey};

}

/**
 * Log in the given user. This function should:
 * 1) Find the user in the database.
 * 2) Send the user's salt and receive a hash of the salted password.
 * 3) Try all possible peppers until one succeeds.
 * 4) Receive a 2FA response and verify it was generated in the last 60 seconds.
 * 5) Receive the user's verification key, and sign it to create a certificate.
 * @param id id of the user logging in
 * @param keys tuple of AES_key, HMAC_key corresponding to this session
 */
void ServerClient::HandleLogin(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver, std::string id,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {

    std::vector<unsigned char> encryptedMessage, encryptedResponse, decryptedResponse;
    bool valid;

    auto [AESKey, HMACKey] = keys;

    UserRow user = this->db_driver->find_user(id);
    if (user.user_id.empty())
        throw std::runtime_error("user never registered");

    // send salt
    ServerToUser_Salt_Message saltMsg;
    saltMsg.salt = user.password_salt;
    encryptedMessage = crypto_driver->encrypt_and_tag(AESKey, HMACKey, &saltMsg);
    network_driver->send(encryptedMessage);

    // receive hashed and salted password
    UserToServer_HashedAndSaltedPassword_Message userHashSalt;
    encryptedResponse = network_driver->read();
    std::tie(decryptedResponse, valid) =
            crypto_driver->decrypt_and_verify(AESKey, HMACKey, encryptedResponse);
    if (!valid)
        throw std::runtime_error("server received invalid message");

    userHashSalt.deserialize(decryptedResponse);

    // find pepper
    bool foundPepper = false;
    for (int i = 0; i < (1 << 8); i++) {
        std::string pepper = std::bitset<8>(i).to_string();
        if (crypto_driver->hash(userHashSalt.hspw + pepper) == user.password_hash) {
            foundPepper = true;
            break;
        }
    }

    if (!foundPepper)
        throw std::runtime_error("failed to authenticate user");

    // get prng value
    UserToServer_PRGValue_Message userPRGValue;
    encryptedResponse = network_driver->read();
    std::tie(decryptedResponse, valid) =
            crypto_driver->decrypt_and_verify(AESKey, HMACKey, encryptedResponse);
    if (!valid)
        throw std::runtime_error("server received invalid message");
    userPRGValue.deserialize(decryptedResponse);

    // validate prg
    bool prgMatch = false;
    Integer now = crypto_driver->nowish();
    for (int i = 0; i <= 60; i++) {
        SecByteBlock r = crypto_driver->prg(
                string_to_byteblock(user.prg_seed),
                integer_to_byteblock(now - i),
                PRG_SIZE
                );
        if (r == userPRGValue.value) {
            prgMatch = true;
            break;
        }
    }

    if (!prgMatch)
        throw std::runtime_error("server failed to validate prg");

    // receive user verification key
    UserToServer_VerificationKey_Message userVerificationKey;
    encryptedResponse = network_driver->read();
    std::tie(decryptedResponse, valid) =
            crypto_driver->decrypt_and_verify(AESKey, HMACKey, encryptedResponse);
    if (!valid)
        throw std::runtime_error("server received invalid message");
    userVerificationKey.deserialize(decryptedResponse);

    ServerToUser_IssuedCertificate_Message serverCertificateMsg;
    Certificate_Message userCertificate;
    userCertificate.id = id;
    userCertificate.verification_key = userVerificationKey.verification_key;
    userCertificate.server_signature =
            crypto_driver->DSA_sign(
                    this->DSA_signing_key,
                    concat_string_and_dsakey(
                            id,
                            userVerificationKey.verification_key
                            ));
    serverCertificateMsg.certificate = userCertificate;
    encryptedMessage = crypto_driver->encrypt_and_tag(AESKey, HMACKey, &serverCertificateMsg);
    network_driver->send(encryptedMessage);

}

/**
 * Register the given user. This function should:
 * 1) Confirm that the user in not the database.
 * 2) Generate and send a salt and receives a hash of the salted password.
 * 3) Generate a pepper and store a second hash of the response + pepper.
 * 4) Generate and sends a PRG seed to the user
 * 4) Receive a 2FA response and verify it was generated in the last 60 seconds.
 * 5) Receive the user's verification key, and sign it to create a certificate.
 * 6) Store the user in the database.
 * @param id id of the user logging in
 * @param keys tuple of AES_key, HMAC_key corresponding to this session
 */
void ServerClient::HandleRegister(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver, std::string id,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {

    std::vector<unsigned char> encryptedMessage, encryptedResponse, decryptedResponse;
    bool valid;

    auto [AESKey, HMACKey] = keys;

    UserRow user = this->db_driver->find_user(id);
    if (!user.user_id.empty())
        throw std::runtime_error("user already registered");

    // generate and send salt
    std::string salt = byteblock_to_string(crypto_driver->png(SALT_SIZE));
    ServerToUser_Salt_Message saltMsg;
    saltMsg.salt = salt;
    encryptedMessage = crypto_driver->encrypt_and_tag(AESKey, HMACKey, &saltMsg);
    network_driver->send(encryptedMessage);

    // receive hashed and salted password
    UserToServer_HashedAndSaltedPassword_Message userHashSalt;
    encryptedResponse = network_driver->read();
    std::tie(decryptedResponse, valid) =
            crypto_driver->decrypt_and_verify(AESKey, HMACKey, encryptedResponse);
    if (!valid)
        throw std::runtime_error("server received invalid message");
    userHashSalt.deserialize(decryptedResponse);

    // generate pepper, hash, and prg seed
    std::string pepper =
            byteblock_to_string(crypto_driver->png(PEPPER_SIZE));
    std::string saltedAndPepperedHashedPassword =
            crypto_driver->hash(userHashSalt.hspw + pepper);
    SecByteBlock prgSeed =crypto_driver->png(PRG_SIZE);

    // send seed
    ServerToUser_PRGSeed_Message prgSeedMsg;
    prgSeedMsg.seed = prgSeed;
    encryptedMessage = crypto_driver->encrypt_and_tag(AESKey, HMACKey, &prgSeedMsg);
    network_driver->send(encryptedMessage);


    // get prng value
    UserToServer_PRGValue_Message userPRGValue;
    encryptedResponse = network_driver->read();
    std::tie(decryptedResponse, valid) =
            crypto_driver->decrypt_and_verify(AESKey, HMACKey, encryptedResponse);
    if (!valid)
        throw std::runtime_error("server received invalid message");
    userPRGValue.deserialize(decryptedResponse);

    // validate prg
    bool prgMatch = false;
    Integer now = crypto_driver->nowish();
    for (int i = 0; i <= 60; i++) {
        SecByteBlock r = crypto_driver->prg(
                prgSeed,
                integer_to_byteblock(now - i),
                PRG_SIZE
        );
        if (r == userPRGValue.value) {
            prgMatch = true;
            break;
        }
    }

    if (!prgMatch)
        throw std::runtime_error("server failed to validate prg");

    // receive user verification key
    UserToServer_VerificationKey_Message userVerificationKey;
    encryptedResponse = network_driver->read();
    std::tie(decryptedResponse, valid) =
            crypto_driver->decrypt_and_verify(AESKey, HMACKey, encryptedResponse);
    if (!valid)
        throw std::runtime_error("server received invalid message");
    userVerificationKey.deserialize(decryptedResponse);

    ServerToUser_IssuedCertificate_Message serverCertificateMsg;
    Certificate_Message userCertificate;
    userCertificate.id = id;
    userCertificate.verification_key = userVerificationKey.verification_key;
    userCertificate.server_signature =
            crypto_driver->DSA_sign(
                    this->DSA_signing_key,
                    concat_string_and_dsakey(
                            id,
                            userVerificationKey.verification_key
                    ));
    serverCertificateMsg.certificate = userCertificate;
    encryptedMessage = crypto_driver->encrypt_and_tag(AESKey, HMACKey, &serverCertificateMsg);
    network_driver->send(encryptedMessage);

    user.user_id = id;
    user.password_hash = saltedAndPepperedHashedPassword;
    user.password_salt = salt;
    user.prg_seed = byteblock_to_string(prgSeed);

    this->db_driver->insert_user(user);

}
