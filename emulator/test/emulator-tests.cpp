#include <iostream>

#include "td/utils/tests.h"

#include "block/block-auto.h"
#include "block/block.h"
#include "block/block-parse.h"

#include "fift/Fift.h"
#include "fift/words.h"
#include "fift/utils.h"

#include "crypto/Ed25519.h"
#include "crypto/vm/boc.h"

#include "td/utils/base64.h"
#include "td/utils/crypto.h"
#include "td/utils/Random.h"
#include "td/utils/tests.h"
#include "td/utils/ScopeGuard.h"
#include "td/utils/StringBuilder.h"
#include "td/utils/Timer.h"
#include "td/utils/PathView.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"
#include "td/utils/Variant.h"

#include "smc-envelope/WalletV3.h"


#include "emulator/emulator-extern.h"

const char *config_boc = "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";

TEST(Emulator, get_method) {
  void *emulator = tvm_emulator_create("te6cckEBAQEAcQAA3v8AIN0gggFMl7ohggEznLqxn3Gw7UTQ0x/THzHXC//jBOCk8mCDCNcYINMf0x/TH/gjE7vyY+1E0NMf0x/T/9FRMrryoVFEuvKiBPkBVBBV+RDyo/gAkyDXSpbTB9QC+wDo0QGkyMsfyx/L/8ntVBC9ba0=", "te6cckEBAQEAKgAAUAAAAAwpqaMXn5gvKZUFgJiOyy9X6j+K9KipclUYVl2At0IUXrVfOgC4VMxt", 1);
  auto x = tvm_emulator_run_get_method(emulator, 78748, "[{\"type\": \"number\", \"value\":\"123123\"}, {\"type\": \"tuple\", \"value\": [{\"type\": \"number\", \"value\":\"999\"}]}]");
  std::cout << std::string(x);
}

TEST(Emulator, send_ext_msg) {
  void *emulator = tvm_emulator_create("te6cckEBAQEAcQAA3v8AIN0gggFMl7ohggEznLqxn3Gw7UTQ0x/THzHXC//jBOCk8mCDCNcYINMf0x/TH/gjE7vyY+1E0NMf0x/T/9FRMrryoVFEuvKiBPkBVBBV+RDyo/gAkyDXSpbTB9QC+wDo0QGkyMsfyx/L/8ntVBC9ba0=", "te6cckEBAQEAKgAAUAAAAAAAAADvUp/kmI8TrgZu8GrK8UKibu8BJCT4Hl47oM60kIop2Btz5qy2", 1);
  auto x = tvm_emulator_send_external_message(emulator, "te6cckEBAQEATgAAmCLdXCTyFknMtvDv6rwcANe4MjixnyYzL8tzlz/oyH3b8afsuYInp8v0zDGBh1xzCCz3wM+8atcpubOfiwf1xQYAAADv/////wAAAAANFQ3r");
  std::cout << std::string(x);
}

TEST(Emulator, trans) {
  void *emulator = transaction_emulator_create(config_boc, 3);
  std::cout << transaction_emulator_set_rand_seed(emulator, "97dcbf36cd11debca03b59fdce454ffe8e3f3cc91b9815c82f063d626753395b");
  std::cout << transaction_emulator_set_rand_seed(emulator, "123123");
}

TEST(Emulator, deploy_wallet) {
  td::Ed25519::PrivateKey priv_key = td::Ed25519::generate_private_key().move_as_ok();
  auto pub_key = priv_key.get_public_key().move_as_ok();
  ton::WalletV3::InitData init_data;
  init_data.public_key = pub_key.as_octet_string();
  init_data.wallet_id = 239;
  auto wallet = ton::WalletV3::create(init_data, 2);

  auto address = wallet->get_address();

  auto init_message = wallet->get_init_message(priv_key).move_as_ok();
  td::Ref<vm::Cell> ext_init_message = ton::GenericAccount::create_ext_message(
      address, ton::GenericAccount::get_init_state(wallet->get_state()), init_message);
  auto ext_init_message_boc = td::base64_encode(std_boc_serialize(ext_init_message).move_as_ok());

  td::Ref<vm::Cell> account_root;
  block::gen::Account().cell_pack_account_none(account_root);
  auto shard_account_cell = vm::CellBuilder().store_ref(account_root).store_bits(td::Bits256::zero().as_bitslice()).store_long(0).finalize();
  auto shard_account_boc = td::base64_encode(std_boc_serialize(shard_account_cell).move_as_ok());


  // TODO: create ShardAccout with non-zero balance
  vm::CellBuilder cb;
  block::gen::StorageUsed::Record
  block::gen::StorageInfo::Record record

  void *emulator = transaction_emulator_create(config_boc, 3);


  // td::Ed25519::PrivateKey sender_priv_key = td::Ed25519::generate_private_key().move_as_ok();
  // auto sender_pub_key = sender_priv_key.get_public_key().move_as_ok();
  // ton::WalletV3::InitData sender_init_data;
  // sender_init_data.public_key = pub_key.as_octet_string();
  // sender_init_data.wallet_id = 239;
  // auto sender_wallet = ton::WalletV3::create(sender_init_data, 2);


  // ton::WalletInterface::Gift gift;
  // gift.gramms = 1;
  // gift.destination = address;
  // gift.message = "gift";
  // auto gift_cell = sender_wallet->make_a_gift_message(sender_priv_key, td::Time::now() + 60, {gift}).move_as_ok();
  // auto gift_cell_boc = td::base64_encode(std_boc_serialize(gift_cell).move_as_ok());
  // block::gen::CommonMsgInfo::Record_int_msg_info(false, true, false, sender_wallet->get_address().)


  


  auto result = transaction_emulator_emulate_transaction(emulator, shard_account_boc.c_str(), ext_init_message_boc.c_str());
  LOG(ERROR) << result;
}