#pragma once
#include "json.hpp"
namespace wxcx {
// Hashes module files once per process, and compares mapped/disk PE headers.
// This is binary identity evidence, not a hash of patched runtime code pages.
nlohmann::json RuntimeIdentity();
}
