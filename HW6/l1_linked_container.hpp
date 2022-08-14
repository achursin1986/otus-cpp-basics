#pragma once


/* Linked L1 - one way linked container implementation, element index starts with 1 */


template <typename T> struct Data1 {
                     T value;
                     struct Data1<T>* next;
                 };


template <typename T> class L1_Node { 
              
         public:
                L1_Node(int value) {
                     Head = new struct Data1<T>;
                     Head->value = value;
                     Head->next = NULL;
                }
                ~L1_Node() {      
                     struct Data1<T>*Temp,*Before{};
                     Temp = Head;
                     while ( Temp ) {
                        Before = Temp;
                        Temp = Temp->next;
                        delete Before;

                     }  
                     
                }
                void Insert(int pos, T value);


                void Print();
                

                void Erase(int pos);
                
                void Push_back(T value);


                int Size() { 
                     struct Data1<T>* Temp;
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
                   struct Data1<T>* Temp;
                   Temp = Head;
                   int size{};
                   while ( Temp ) {
                        if ( size == index-1 ) { 
                               return Temp->value;
                        }
                        size++;
                        Temp = Temp->next;
                      
                  }
                   
                  return Temp->value; 
                }


         private:
                struct Data1<T>* Head{};

                
                

};




template <typename T> void L1_Node<T>::Push_back(T value) {
              struct Data1<T>* Temp,*Before,*New;
              Temp = Head;
              if ( Temp ) {
                 while ( Temp ) {
                      Before = Temp; 
                      Temp = Temp->next;
                 }
              New = new Data1<T>;
              New->value = value;
              New->next = NULL; 
              Before->next = New;
              }

                   
}





template <typename T> void L1_Node<T>::Insert(int pos, T value) {  // insert implies that we have something in front
              struct Data1<T>* Temp,*Before{},*New;
              int i{};
              Temp = Head;
              while ( Temp ) {
                      if ( i == pos-2 ) {
                         Before = Temp;
                      }
                     
                      if ( i == pos-1 ) {
                        New = new struct Data1<T>;
                              if ( Before ) {
                                    Before->next = New;  
                              } else { 
                                    Head = New;
                              } 
                              New->next = Temp;
                              New->value = value;
                              return;

                        }

                        Temp = Temp->next;
                        i++;

                      }
}


template <typename T> void L1_Node<T>::Erase(int pos) {
              struct Data1<T>* Temp,*After,*Before{};
              int i{};
              Temp = Head;
              while ( Temp ) {
                      if ( i == pos-2 ) { 
                         Before = Temp;
                      }
                      After = Temp->next;
                      if ( i == pos-1 ) {
                          if ( Before ) {
                                Before->next = After;
                          } else {
                                Head = After;
                          }
                            
                        delete Temp;  
                        return;

                      }
                      Temp = Temp->next;
                      i++;
                 }


}

template <typename T> void L1_Node<T>::Print() {
             struct Data1<T>* Temp;
             Temp = Head;
             while ( Temp ) {
                 std::cout << Temp->value << " ";
                 Temp = Temp -> next;
                  
             }
             std::cout << std::endl;
}


