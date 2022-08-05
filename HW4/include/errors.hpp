#pragma once

#include <string>

#include "astnode.hpp"


// error handling  

class Error : public ASTNode {
  public:
    Error(const std::string val) 
        : ASTNode(val), error(val) {}

  std::string get_error() const { return error; }

  private:
    std::string error;

};


