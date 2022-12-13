#ifndef INTRUSIVE_PTR_BASE
#define INTRUSIVE_PTR_BASE

#include <atomic>
#include <cstddef>

#include "utils/intrusive/intrusive_ptr.hpp"

namespace util::mem {

template <typename T>
class intrusive_base_c;
template <typename T>
inline void intrusive_ptr_add_ref(const intrusive_base_c<T> *p) noexcept;
template <typename T>
inline void intrusive_ptr_release(const intrusive_base_c<T> *p) noexcept;

template <typename T>
class intrusive_base_c {
public:
  intrusive_base_c() noexcept : _ref_cnt{0} {}
  intrusive_base_c(intrusive_base_c const &r) noexcept : _ref_cnt{0} {};

public:
  intrusive_base_c &operator=(intrusive_base_c const &r) noexcept { return *this; }
  std::uint32_t use_count() const noexcept { return _ref_cnt.load(std::memory_order_seq_cst); }

public:
  friend void intrusive_ptr_add_ref<T>(const intrusive_base_c<T> *p) noexcept;
  friend void intrusive_ptr_release<T>(const intrusive_base_c<T> *p) noexcept;

protected:
  ~intrusive_base_c() = default;

private:
  mutable std::atomic<std::uint32_t> _ref_cnt;
};

template <typename T>
inline void intrusive_ptr_add_ref(const intrusive_base_c<T> *p) noexcept
{
  if (p) {
    p->_ref_cnt.fetch_add(1, std::memory_order::relaxed);
  }
}

template <typename T>
inline void intrusive_ptr_release(const intrusive_base_c<T> *p) noexcept
{
  if (p) {
    if (p->_ref_cnt.fetch_sub(1, std::memory_order::release) == 1) {
      std::atomic_thread_fence(std::memory_order::acquire);
      delete static_cast<T *>(const_cast<intrusive_base_c<T> *>(p));
    }
  }
}

} // namespace util::mem

#endif // INTRUSIVE_PTR_BASE
