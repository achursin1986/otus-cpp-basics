#pragma once


/* Serial container implementation, element index starts with 1 */



template <typename T> class S_Node { 
              
         public:
                S_Node(int size): capacity(size),free(size) {
                     array = new T[size];
                }
                ~S_Node() {
                     delete []array;
                }
                void Insert(int pos, const T &value);

                void Print();

                void Erase(int pos);
                
                void Push_back(T value);


                int Size() { 
                    return capacity - free;  

                }


                T& operator[](int index)
                {
                     if ( index <= 0 || index > capacity - free ) {

                         std::cout<< "Out of boundary access attempt, 1st element" << std::endl;
                         std::exit(1); 
                         
                     }
                     return array[index-1];
                }
                T& operator[](int index) const { 
                     if ( index <= 0 || index > capacity - free ) {

                         std::cout<< "Out of boundary access attempt, 1st element" << std::endl;
                         std::exit(1);

                     }
                     return array[index-1];

                }


         private:
                 //service funcs
                 T* Expand05(T* array);
                 void Shift(T* array, int pos);
                
                int capacity = 0 ;
                int free = 0;
                T* array;

};


template <typename T> T* S_Node<T>::Expand05(T* array) {
                 T* temp = new T[capacity + capacity/2];                 
                 for (int i=0;i<capacity;i++) {
                                 temp[i] = array [i];
                 }
                 free = capacity/2;
                 capacity = capacity + capacity/2;
                 return temp; 
}

template <typename T> void S_Node<T>::Shift(T* array, int pos) {
                 if ( pos <= 0 || pos > capacity-free )  {
                      std::cout<< "Out of boundary access attempt" << std::endl;
                      return; 
                 } 
                 T* temp = new T[capacity - pos + 1];
                 for (int i=pos-1;i<capacity;i++) {
                             temp[i-pos+1] = array [i]; // saving elements to move
                      }
                 for (int i=pos-1;i<capacity;i++) {
                             array[i+1] = temp [i-pos+1]; // recovering elements
                      }
                 delete []temp;
                 
}




template <typename T> void S_Node<T>::Push_back(T value) {
                if ( ! free ) { 
                       array = Expand05(array);
                       array[capacity-free] = value;
                       free--; 
                        
                       
                } else {
                       array[capacity-free] = value;
                       free--;

                }

}





template <typename T> void S_Node<T>::Insert(int pos, const T &value) {
                   if ( pos <= 0 || pos > capacity-free )  {
                      std::cout<< "Out of boundary access attempt" << std::endl;
                      return;
                   }
                   if ( ! free ) {     
                      array = Expand05(array);
                      Shift(array, pos);
                      array[pos-1]= value;
                      free--;
                      
                   } else { 
                      Shift(array, pos);
                      array[pos-1]= value;
                      free--;

                   }
                    
         

}


template <typename T> void S_Node<T>::Erase(int pos) {
                     if ( pos <= 0 || pos > capacity-free )  {
                                std::cout<< "Out of boundary access attempt" << std::endl;
                                return;
                     } 
                     for (int i=pos-1;i<capacity;i++) {
                         array[i] = array[i+1];         
                     }
                     free++;


}

template <typename T> void S_Node<T>::Print() {
         for ( int i=0; i < capacity-free; i++ ) {
              if ( i == capacity -1 ) { 
                         std::cout<< array[i];
                         break;
               } 
         std::cout<< array[i] << " "; 
         }
         std::cout<< std::endl;

}


