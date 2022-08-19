#pragma once


#include <iterator>
#include <cstddef>
#include <iostream>


/* Linked L2 - two way linked container implementation, element index starts with 1 */


template <typename T> struct Data {
                     T value;
                     struct Data<T>* next;
                     struct Data<T>* prev;
                 };




template <typename T> class L2_Node { 
              
         public:
                struct Iterator { 
                      Iterator() :
                          CurrentNode () { }
 
                      Iterator(const Data<T>* Node):
                           CurrentNode (Node) { }
 
                      Iterator& operator=(Data<T>* Node){
                           this->CurrentNode = Node;
                           return *this;
                      }
                      Iterator& operator++(){
                           if (CurrentNode){
                                  CurrentNode = CurrentNode->next;
                           }
                           return *this;
                      }
                      Iterator operator++(int){
                           Iterator iterator = *this;
                           ++*this;
                           return iterator;
                      }
                      bool operator!=(const Iterator& iterator){
                            return CurrentNode != iterator.CurrentNode;

                      }
 
                      int operator*(){
                             return CurrentNode->value;
                      }
 

                 private: 
                         const Data<T>* CurrentNode;
                }; 

               
                L2_Node(int value) {
                     Head = new struct Data<T>;
                     std::cout << "Allocate new node" << std::endl;
                     Head->value = value;
                     Head->prev = NULL;
                     Head->next = NULL;
                }
                ~L2_Node() {
                     struct Data<T>* Temp;
                     if ( Tail && Head ) {
                     Temp = Tail->prev;                   
                     while ( Temp ) {
                            delete Temp->next;
                            Temp = Temp->prev;
                     }
                     }
                     delete Head;
                }
                void Insert(int pos, T value);


                void Print();
                

                void Erase(int pos);
                
                void Push_back(T value);


                int Size() { 
                     struct Data<T>* Temp;
                     int size{};
                     Temp = Head;
                     while ( Temp ) {
                        size++;
                        Temp = Temp -> next;                        
                     }
                     return size; 
                }


                T& operator[](int index)
                {
                   struct Data<T>* Temp;
                   Temp = Head;
                   int size{};
                   while ( Temp ) {
                        if ( size == index-1 ) { 
                               return Temp->value;
                        }
                        size++;
                        Temp = Temp -> next;
                      
                  }
                  return Temp->value;
                   
                }
                L2_Node(L2_Node&& Other)  {
                                 std::cout << "move is called" << std::endl;
                                 std::swap(Head, Other.Head);
                                 std::swap(Tail, Other.Tail);
                                 Other.Head = NULL;
                                 Other.Tail = NULL;
                        
                }                  
                L2_Node& operator= (const L2_Node& Other)  {
                                 struct Data<T>* Temp{},*New{},*Temp1;
                                 if ( !Other.Head && !Other.Tail ) {
                                        std::exit(1);
                                 }
                                 Temp = Other.Head->next;
                                 Temp1 = Head;
                                 Head->value = Other.Head->value;

                                 while ( Temp ) {
                                      New = new struct Data<T>;
                                      New->value = Temp->value;
                                      New->prev = Temp1;
                                      New->next = NULL;  
                                      Temp1->next = New;
                                      Temp1 = Temp1->next;
                                      Temp = Temp -> next;

                                 };
                           
                                 Tail = New;
                                 return *this;
                } 

                Iterator begin() { return Iterator(Head); }
                Iterator end()   { return Iterator(NULL); }



         private:
                struct Data<T>* Head{};
                struct Data<T>* Tail{};

                
                

};




template <typename T> void L2_Node<T>::Push_back(T value) {
              struct Data<T>* Temp,*Before,*New;
              Temp = Head;
              if ( Temp ) {
                 while ( Temp ) {
                      Before = Temp; 
                      Temp = Temp->next;
                 }
              New = new Data<T>;
              Tail = New; // for iterator
              New->value = value;
              New->next = NULL;
              New->prev = Before; 
              Before->next = New;
              }

                   
}





template <typename T> void L2_Node<T>::Insert(int pos, T value) {  // insert implies that we have something in front
              struct Data<T>* Temp,*Before,*New;
              int i{};
              Temp = Head;
              while ( Temp ) {
                      Before = Temp->prev;
                      if ( i == pos-1 ) {
                        New = new struct Data<T>;
                              if ( Before ) {
                                    Before->next = New;  
                              } else { 
                                    Head = New;
                              } 
                              Temp->prev = New;
                              New->next = Temp;
                              New->prev = Before;
                              New->value = value;
                              return;

                        }

                        Temp = Temp->next;
                        i++;

                      }
}


template <typename T> void L2_Node<T>::Erase(int pos) {
              struct Data<T>* Temp,*After,*Before;
              int i{};
              Temp = Head;
              while ( Temp ) {
                      Before = Temp->prev;
                      After = Temp->next;
                      if ( i == pos-1 ) {
                          if ( Before ) {
                                Before->next = After;
                          }
                          if ( After ) {
                                After->prev = Before;
                          } 
                        delete Temp;  
                        return;

                      }
                      Temp = Temp -> next;
                      i++;
                 }


}

template <typename T> void L2_Node<T>::Print() {
             struct Data<T>* Temp;
             Temp = Head;
             while ( Temp ) {
                 std::cout << Temp->value << " ";
                 Temp = Temp -> next;
                  
             }
             std::cout << std::endl;
}







