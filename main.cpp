/*
Author: Pavel Horáček
 */

#include "ChatClient.h"
#include "DoubleRatchet.h"
#include "KDF.h"
#include "KeyManager.h"

#include <csignal>
#include <iostream>
#include <string>
#include <thread>

volatile sig_atomic_t run = 1;
ChatClient client;
DoubleRatchet axolotl;

std::thread thr_recv;
std::thread thr_send;

bytes_t INIT_MSG = {'i', 'n', 'i', 't'};

void sig_term(int) {
  run = 0;
  client.shutdown();
}



int main(int argc, char *argv[]) {
  KeyPair key_pair = KeyManager::genDHKeys();

  if(argc != 3) {
    std::cerr << "Invalid number of arguments. Expecting [LOCAL PORT] [REMOTE IP:REMOTE PORT]\n";
  }

  struct sigaction action{};
  action.sa_handler = sig_term;
  sigaction(SIGTERM, &action, nullptr);

  client.setPort(std::stoi(argv[1]));
  client.connect(argv[2]);
  bytes_t pubkey = KeyManager::serializePublicKey(key_pair.pubKey);
  client.send(pubkey);
  bytes_t other_pubkey_bytes = client.recv();
  KeyPair other_pubkey = KeyManager::deserializePublicKey(other_pubkey_bytes);

  auto shared_secret = KeyManager::deriveDHSecret(key_pair, {other_pubkey});

  if(key_pair.pubKey > other_pubkey.pubKey) {
    axolotl.init(shared_secret, key_pair);
    bytes_t init_enc = client.recv();
    bytes_t init_msg = axolotl.decrypt(init_enc);
  }else {
    axolotl.init(shared_secret, {other_pubkey});
    bytes_t init_enc = axolotl.encrypt(INIT_MSG);
    client.send(init_enc);
  }

  thr_recv = std::thread([&argv]() {
    while (run) {
      bytes_t recv_enc = client.recv();
      bytes_t recv_msg = axolotl.decrypt(recv_enc);
      std::string str(recv_msg.begin(), recv_msg.end());
      std::cout << "New message: " << str << std::endl;
    }
  });
  thr_send = std::thread([]() {
    while (run) {
      std::string str;
      std::getline(std::cin, str);
      if(!run) break;
      bytes_t send_msg(str.begin(), str.end());
      bytes_t send_enc = axolotl.encrypt(send_msg);
      client.send(send_enc);
    }
  });
  thr_recv.join();
  thr_send.join();
}