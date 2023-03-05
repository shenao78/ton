/*
    This file is part of TON Blockchain Library.

    TON Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TON Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TON Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2017-2020 Telegram Systems LLP
*/
#include "td/db/RocksDbSecondary.h"

#include "rocksdb/db.h"
#include "rocksdb/table.h"
#include "rocksdb/statistics.h"
#include "rocksdb/write_batch.h"
// #include "rocksdb/utilities/optimistic_transaction_db.h"
#include "rocksdb/utilities/transaction.h"

namespace td {
namespace {
static Status from_rocksdb(rocksdb::Status status) {
  if (status.ok()) {
    return Status::OK();
  }
  return Status::Error(status.ToString());
}
static Slice from_rocksdb(rocksdb::Slice slice) {
  return Slice(slice.data(), slice.size());
}
static rocksdb::Slice to_rocksdb(Slice slice) {
  return rocksdb::Slice(slice.data(), slice.size());
}
}  // namespace

Status RocksDbSecondary::destroy(Slice path) {
  return from_rocksdb(rocksdb::DestroyDB(path.str(), {}));
}

RocksDbSecondary::RocksDbSecondary(RocksDbSecondary &&) = default;
RocksDbSecondary &RocksDbSecondary::operator=(RocksDbSecondary &&) = default;

RocksDbSecondary::~RocksDbSecondary() {
  if (!db_) {
    return;
  }
  end_snapshot().ensure();
}

RocksDbSecondary RocksDbSecondary::clone() const {
  return RocksDbSecondary{db_, statistics_};
}

Result<RocksDbSecondary> RocksDbSecondary::open(std::string path) {
  rocksdb::DB *db;
  auto statistics = rocksdb::CreateDBStatistics();
  {
    rocksdb::Options options;

    static auto cache = rocksdb::NewLRUCache(1 << 30);

    rocksdb::BlockBasedTableOptions table_options;
    table_options.block_cache = cache;
    options.table_factory.reset(rocksdb::NewBlockBasedTableFactory(table_options));

    options.manual_wal_flush = true;
    options.create_if_missing = true;
    options.max_background_compactions = 4;
    options.max_background_flushes = 2;
    options.bytes_per_sync = 1 << 20;
    options.writable_file_max_buffer_size = 2 << 14;
    options.statistics = statistics;
    rocksdb::ColumnFamilyOptions cf_options(options);
    std::vector<rocksdb::ColumnFamilyDescriptor> column_families;
    column_families.push_back(rocksdb::ColumnFamilyDescriptor(rocksdb::kDefaultColumnFamilyName, cf_options));
    std::vector<rocksdb::ColumnFamilyHandle *> handles;
    TRY_STATUS(from_rocksdb(
      rocksdb::DB::OpenAsSecondary(options, path, path + "/secondary_path", column_families, &handles, &db)));
    CHECK(handles.size() == 1);
    // i can delete the handle since DBImpl is always holding a reference to
    // default column family
    delete handles[0];
  }
  TRY_STATUS(from_rocksdb(db->TryCatchUpWithPrimary()));
  return RocksDbSecondary(std::shared_ptr<rocksdb::DB>(db), std::move(statistics));
}

Status RocksDbSecondary::try_catch_up_with_primary() {
  return from_rocksdb(db_->TryCatchUpWithPrimary());
}

std::unique_ptr<KeyValueReader> RocksDbSecondary::snapshot() {
  auto res = std::make_unique<RocksDbSecondary>(clone());
  res->begin_snapshot().ensure();
  return std::move(res);
}

std::string RocksDbSecondary::stats() const {
  std::string out;
  db_->GetProperty("rocksdb.stats", &out);
  //db_->GetProperty("rocksdb.cur-size-all-mem-tables", &out);
  return out;
  return statistics_->ToString();
}

Result<RocksDbSecondary::GetStatus> RocksDbSecondary::get(Slice key, std::string &value) {
  //LOG(ERROR) << "GET";
  rocksdb::Status status;
  if (snapshot_) {
    rocksdb::ReadOptions options;
    options.snapshot = snapshot_.get();
    status = db_->Get(options, to_rocksdb(key), &value);
  } else if (transaction_) {
    status = transaction_->Get({}, to_rocksdb(key), &value);
  } else {
    status = db_->Get({}, to_rocksdb(key), &value);
  }
  if (status.ok()) {
    return GetStatus::Ok;
  }
  if (status.code() == rocksdb::Status::kNotFound) {
    return GetStatus::NotFound;
  }
  return from_rocksdb(status);
}

Status RocksDbSecondary::set(Slice key, Slice value) {
  CHECK(false)
  // if (write_batch_) {
  //   return from_rocksdb(write_batch_->Put(to_rocksdb(key), to_rocksdb(value)));
  // }
  // if (transaction_) {
  //   return from_rocksdb(transaction_->Put(to_rocksdb(key), to_rocksdb(value)));
  // }
  // return from_rocksdb(db_->Put({}, to_rocksdb(key), to_rocksdb(value)));
}

Status RocksDbSecondary::erase(Slice key) {
  CHECK(false)
  // if (write_batch_) {
  //   return from_rocksdb(write_batch_->Delete(to_rocksdb(key)));
  // }
  // if (transaction_) {
  //   return from_rocksdb(transaction_->Delete(to_rocksdb(key)));
  // }
  // return from_rocksdb(db_->Delete({}, to_rocksdb(key)));
}

Result<size_t> RocksDbSecondary::count(Slice prefix) {
  rocksdb::ReadOptions options;
  options.snapshot = snapshot_.get();
  std::unique_ptr<rocksdb::Iterator> iterator;
  if (snapshot_ || !transaction_) {
    iterator.reset(db_->NewIterator(options));
  } else {
    iterator.reset(transaction_->GetIterator(options));
  }

  size_t res = 0;
  for (iterator->Seek(to_rocksdb(prefix)); iterator->Valid(); iterator->Next()) {
    if (from_rocksdb(iterator->key()).truncate(prefix.size()) != prefix) {
      break;
    }
    res++;
  }
  if (!iterator->status().ok()) {
    return from_rocksdb(iterator->status());
  }
  return res;
}

Status RocksDbSecondary::begin_write_batch() {
  CHECK(false)
  // CHECK(!transaction_);
  // write_batch_ = std::make_unique<rocksdb::WriteBatch>();
  // return Status::OK();
}

Status RocksDbSecondary::begin_transaction() {
  CHECK(false)
  // CHECK(!write_batch_);
  // rocksdb::WriteOptions options;
  // options.sync = true;
  // transaction_.reset(db_->BeginTransaction(options, {}));
  // return Status::OK();
}

Status RocksDbSecondary::commit_write_batch() {
  CHECK(false)
  // CHECK(write_batch_);
  // auto write_batch = std::move(write_batch_);
  // rocksdb::WriteOptions options;
  // options.sync = true;
  // return from_rocksdb(db_->Write(options, write_batch.get()));
}

Status RocksDbSecondary::commit_transaction() {
  CHECK(false)
  // CHECK(transaction_);
  // auto transaction = std::move(transaction_);
  // return from_rocksdb(transaction->Commit());
}

Status RocksDbSecondary::abort_write_batch() {
  CHECK(false)
  // CHECK(write_batch_);
  // write_batch_.reset();
  // return Status::OK();
}

Status RocksDbSecondary::abort_transaction() {
  CHECK(false)
  // CHECK(transaction_);
  // transaction_.reset();
  // return Status::OK();
}

Status RocksDbSecondary::flush() {
  CHECK(false)
  // return from_rocksdb(db_->Flush({}));
}

Status RocksDbSecondary::begin_snapshot() {
  snapshot_.reset(db_->GetSnapshot());
  return td::Status::OK();
}

Status RocksDbSecondary::end_snapshot() {
  if (snapshot_) {
    db_->ReleaseSnapshot(snapshot_.release());
  }
  return td::Status::OK();
}

RocksDbSecondary::RocksDbSecondary(std::shared_ptr<rocksdb::DB> db, std::shared_ptr<rocksdb::Statistics> statistics)
    : db_(std::move(db)), statistics_(std::move(statistics)) {
}
}  // namespace td
