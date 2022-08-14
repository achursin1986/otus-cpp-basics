#pragma once


/* Linked L2 - two way linked container implementation, element index starts with 1 */


template <typename T> struct Data {
                     T value;
                     struct Data<T>* next;
                     struct Data<T>* prev;
                 };

template <typename T> struct Iter {
                     T value;
                     struct Data<T>* next;
                     struct Data<T>* prev;
                 };



template <typename T> class L2_Node { 
              
         public:
                L2_Node(int value) {
                     Head = new struct Data<T>;
                     Head->value = value;
                     Head->prev = NULL;
                     Head->next = NULL;
                }
                ~L2_Node() {
                     struct Data<T>* Temp,*Before;
                     Temp = Head; 
                     while ( Temp ) {
                        Before = Temp; 
                        Temp = Temp -> next;
                     }
                     Temp = Before;
                     // need to walk the whole thing back
                     while ( Temp ) {
                        if ( Temp->next ) {
                            delete Temp->next;         
                        }
                        Temp = Temp->prev;
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



         private:
                struct Data<T>* Head{};

                
                

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


