#pragma once

#include <string>

#include "astnode.hpp"

class Variable : public ASTNode {
  public:
    Variable(std::string val)
        : ASTNode(val)
        , val_(val) {}

    std::string value() const { return val_; }

  private:
    std::string val_;
};
