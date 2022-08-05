#include "parser.hpp"
#include "number.hpp"
#include "mathops.hpp"
#include "variable.hpp"
#include "errors.hpp"

using Token = Lexer::Token;

ASTNode *Parser::parse() { return expr(); }

void Parser::next_token() { tok_ = lexer_.next_token(); }

ASTNode *Parser::expr() {
    // parse addition and subsctruction
    ASTNode *root = term();
    for (;;) {
        switch (tok_) {
        case Token::Operator: {
            std::string op = lexer_.get_operator();
            switch (op.front()) {
            case '+':
                // Implement Add class and uncomment this line
                root = new Add(root, term());
                break;
            case '-':
                // Implement Sub class and uncomment this line
                root = new Sub(root, term());
                break;
            default:
                return root;
            }
            break;
        }
        default:
            return root;
            
        }
    }
}

ASTNode *Parser::term() {
    // parse multiplication and division
    ASTNode *root = prim();
    for (;;) {
        switch (tok_) {
        case Token::Operator: {
            std::string op = lexer_.get_operator();
            switch (op.front()) {
            case '*':
                // Implement Mul class and uncomment this line
                root = new Mul(root, prim());
                break;
            case '/':
                // Implement Div class and uncomment this line
                root = new Div(root, prim());
                break;
            default:
                return root;
            }
            break;
        }
        break;

        default:
            return root;
        }
   }
}

ASTNode *Parser::prim() {
    // parse numbers and names
    ASTNode *node = nullptr;
    next_token();
    switch (tok_) {
    case Token::Number:
            node = new Number(lexer_.get_number());
            break;
    case Token::Name:
        // Implement Variable class and uncomment this line
            node = new Variable(lexer_.get_name());
            break;
    case Token::Lbrace:
        node = expr();
        if ( tok_ != Token::Rbrace ) {
              node = new Error("Error: expected )");
              return node;
        } 
        next_token();  
        return node;
        
        break; 
    default:
        node = new Error("Error: expected a var or number");
        return node; 
    }

    next_token();
    if ( tok_ == Token::Name || tok_ == Token::Number || tok_ == Token::Lbrace ) {
              node = new Error("Error: expected an operation");

    }

    return node;
}
