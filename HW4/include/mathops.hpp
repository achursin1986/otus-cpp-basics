#pragma once

#include <string>

#include "astnode.hpp"


// Addition

class Add : public ASTNode {
  public:
    Add(ASTNode* left, ASTNode* right)
        : ASTNode("+", left, right ) {}

};

// Subsctraction

class Sub : public ASTNode {
  public:
    Sub(ASTNode* left, ASTNode* right)
        : ASTNode("-", left, right )  {}

};

// Multiplication

class Mul : public ASTNode {
  public:
    Mul(ASTNode* left, ASTNode* right)
        : ASTNode("*", left, right ) {}
};


// Division

class Div : public ASTNode {
  public:
    Div(ASTNode* left, ASTNode* right)
        : ASTNode("/", left, right) {}
};

