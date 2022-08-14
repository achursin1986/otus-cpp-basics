in class in public


struct Iterator {
                     using iterator_category = std::random_access_iterator_tag;
                     using difference_type   = std::ptrdiff_t;
                     using value_type        = T;
                     using pointer           = T*;
                     using reference         = T&;

                     Iterator(pointer ptr) : m_ptr(ptr) {}
                     pointer operator->() { return m_ptr; }
                     Iterator& operator++() { m_ptr++; return *this; }  < ---- can iterate only in sequencial manner
                     Iterator operator++(int) { Iterator tmp = *this; ++(*this); return tmp; }
                     reference operator*() const { return *m_ptr; }
                     friend bool operator== (const Iterator& a, const Iterator& b) { return a.m_ptr == b.m_ptr; };
                     friend bool operator!= (const Iterator& a, const Iterator& b) { return a.m_ptr != b.m_ptr; };

                 private:
                     pointer m_ptr;

                };


Iterator begin() { return Iterator(&Head->value); }
Iterator end()   { return Iterator(&Tail->value); }

