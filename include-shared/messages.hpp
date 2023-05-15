#pragma once

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <boost/chrono.hpp>
#include <boost/thread.hpp>
#include <crypto++/cryptlib.h>
#include <crypto++/dsa.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>

// ================================================
// MESSAGE TYPES
// ================================================

namespace MessageType {
enum T {
  HMACTagged_Wrapper = 0,
  Certificate_Message = 1,
  UserToServer_DHPublicValue_Message = 2,
  ServerToUser_DHPublicValue_Message = 3,
  UserToServer_IDPrompt_Message = 4,
  ServerToUser_Salt_Message = 5,
  UserToServer_HashedAndSaltedPassword_Message = 6,
  ServerToUser_PRGSeed_Message = 7,
  UserToServer_PRGValue_Message = 8,
  UserToServer_VerificationKey_Message = 9,
  ServerToUser_IssuedCertificate_Message = 10,
  UserToUser_DHPublicValue_Message = 11,

  UserToServer_Wrapper_Message = 12,
  ServerToUser_Wrapper_Message = 13,

  // to create a group with the server
  UserToServer_GID_Message = 14,
  ServerToUser_GID_Message = 15,

  // All following messages will always be contained in 12 or 13

  // to add a new member to the group
  UserToUser_Invite_Message = 16, // inviter -> new member
  UserToUser_Invite_Response_Message = 17, // new member -> inviter
  UserToUser_New_Member_Info_Message = 18, // inviter -> all other members
  UserToUser_Old_Members_Info_Message = 19, // inviter -> new member

  UserToUser_Message_Message = 20, // user -> user
};
};
MessageType::T get_message_type(std::vector<unsigned char> &data);

// ===============================================
// SERIALIZABLE
// ================================================

struct Serializable {
  virtual void serialize(std::vector<unsigned char> &data) = 0;
  virtual int deserialize(std::vector<unsigned char> &data) = 0;
};

// serializers.
int put_bool(bool b, std::vector<unsigned char> &data);
int put_string(std::string s, std::vector<unsigned char> &data);
int put_integer(CryptoPP::Integer i, std::vector<unsigned char> &data);

// deserializers
int get_bool(bool *b, std::vector<unsigned char> &data, int idx);
int get_string(std::string *s, std::vector<unsigned char> &data, int idx);
int get_integer(CryptoPP::Integer *i, std::vector<unsigned char> &data,
                int idx);

// ================================================
// WRAPPERS
// ================================================

struct HMACTagged_Wrapper : public Serializable {
  std::vector<unsigned char> payload;
  CryptoPP::SecByteBlock iv;
  std::string mac;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct Certificate_Message : public Serializable {
  std::string id;
  CryptoPP::DSA::PublicKey verification_key;
  std::string server_signature; // computed on id + verification_key

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// ================================================
// USER <=> SERVER MESSAGES
// ================================================

struct UserToServer_DHPublicValue_Message : public Serializable {
  CryptoPP::SecByteBlock public_value;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct ServerToUser_DHPublicValue_Message : public Serializable {
  CryptoPP::SecByteBlock server_public_value;
  CryptoPP::SecByteBlock user_public_value;
  std::string server_signature; // computed on server_value + user_value

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct UserToServer_IDPrompt_Message : public Serializable {
  std::string id;
  bool new_user;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct ServerToUser_Salt_Message : public Serializable {
  std::string salt;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct UserToServer_HashedAndSaltedPassword_Message : public Serializable {
  std::string hspw;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct ServerToUser_PRGSeed_Message : public Serializable {
  CryptoPP::SecByteBlock seed;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct UserToServer_PRGValue_Message : public Serializable {
  CryptoPP::SecByteBlock value;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct UserToServer_VerificationKey_Message : public Serializable {
  CryptoPP::DSA::PublicKey verification_key;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct ServerToUser_IssuedCertificate_Message : public Serializable {
  Certificate_Message certificate;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct UserToServer_Wrapper_Message : public Serializable {
    std::string sender_id;
    std::string receiver_id;
    MessageType::T type;
    std::vector<unsigned char> message;

    void serialize(std::vector<unsigned char> &data);
    int deserialize(std::vector<unsigned char> &data);
};

struct ServerToUser_Wrapper_Message : public Serializable {
    std::string sender_id;
    std::string receiver_id;
    MessageType::T type;
    std::vector<unsigned char> message;

    void serialize(std::vector<unsigned char> &data);
    int deserialize(std::vector<unsigned char> &data);
};

struct UserToServer_GID_Message : public Serializable {
    // literally doesn't need any fields

    void serialize(std::vector<unsigned char> &data);
    int deserialize(std::vector<unsigned char> &data);
};

struct ServerToUser_GID_Message :  public Serializable {
    std::string group_id;

    void serialize(std::vector<unsigned char> &data);
    int deserialize(std::vector<unsigned char> &data);
};

// ================================================
// USER <=> USER MESSAGES
// ================================================

struct UserToUser_DHPublicValue_Message : public Serializable {
  CryptoPP::SecByteBlock public_value;
  Certificate_Message certificate;
  std::string user_signature; // computed on public_value + certificate

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct UserToUser_Invite_Message : public Serializable {
    // UserToUser_DHPublicValue_Message + group id
    CryptoPP::SecByteBlock public_value;
    Certificate_Message certificate;
    std::string user_signature; // computed on public_value + gid + certificate

    void serialize(std::vector<unsigned char> &data);
    int deserialize(std::vector<unsigned char> &data);

};

/// ^ and v are the same thing,

struct UserToUser_Invite_Response_Message : public Serializable {
    // UserToUser_DHPublicValue_Message + group id

    CryptoPP::SecByteBlock public_value;
    Certificate_Message certificate;
    std::string user_signature; // computed on public_value + gid + certificate

    void serialize(std::vector<unsigned char> &data);
    int deserialize(std::vector<unsigned char> &data);

};


struct UserToUser_New_Member_Info_Message : public Serializable {
    CryptoPP::SecByteBlock other_public_value;
    Certificate_Message other_certificate;

    void serialize(std::vector<unsigned char> &data);
    int deserialize(std::vector<unsigned char> &data);
};


struct UserToUser_Old_Members_Info_Message : public Serializable {
    std::string num_members;
    std::string group_id;
    std::vector<std::string> group_members;
    std::vector<CryptoPP::SecByteBlock> other_public_values;

    void serialize(std::vector<unsigned char> &data);
    int deserialize(std::vector<unsigned char> &data);
};


struct UserToUser_Message_Message : public Serializable {
  std::string msg;
  std::string group_id;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};


// ================================================
// SIGNING HELPERS
// ================================================

std::vector<unsigned char>
concat_string_and_dsakey(std::string &s, CryptoPP::DSA::PublicKey &k);
std::vector<unsigned char> concat_byteblocks(CryptoPP::SecByteBlock &b1,
                                             CryptoPP::SecByteBlock &b2);
std::vector<unsigned char> concat_byteblock_and_cert(CryptoPP::SecByteBlock &b,
                                                     Certificate_Message &cert);

std::vector<unsigned char> concat_byteblock_group_and_cert(CryptoPP::SecByteBlock &b, std::string group,
                                                     Certificate_Message &cert);
