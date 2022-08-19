#include<iostream>
#include<vector>
#include"serial_container.hpp"
#include"l1_linked_container.hpp"
#include"l2_linked_container.hpp"



L2_Node<int> get_container(int value)
{
   L2_Node<int> cont(value);
   return cont;

}





int main(){

    S_Node<int> cont(10);
    L2_Node<int> cont2(0); // inited first element as 0
    L1_Node<int> cont3(0);
    L2_Node<int> cont4(0);
    std::vector<L2_Node<int>> vec; 

    std::cout << "==============================" << std::endl;    
    std::cout << "->Serial container type:" << std::endl;
    std::cout << "==============================" << std::endl;
    
    for ( int i=0; i<10; i++ ) { 
           cont.Push_back(i);
    } 


    cont.Print();
    std::cout << "Container size: " << cont.Size() <<std::endl;

    std::cout << "Remove 3,5,7th elements: " <<std::endl;
    cont.Erase(3);
    cont.Erase(4);
    cont.Erase(5);

    cont.Print();

    std::cout << "Appending 10 to the beginning: " <<std::endl;
    cont.Insert(1,10);
    cont.Print();

    std::cout << "Inserting 20 to the middle: " <<std::endl;
    cont.Insert(5,20);
    cont.Print();

    std::cout << "Inserting 30 to the end: " <<std::endl;
    cont.Push_back(30);
    cont.Print();

    std::cout << "4th element: " <<std::endl;
    std::cout << cont[4];
    std::cout << std::endl; 

    
    std::cout << "==============================" << std::endl;
    std::cout << "->Linked 2 way container type:" << std::endl;
    std::cout << "==============================" << std::endl;
    
    for ( int i=1; i<10; i++ ) {
           cont2.Push_back(i);
    }
    cont2.Print();
    std::cout << "Container Size: " << cont2.Size() << std::endl;

    std::cout << "Remove 3,5,7th elements: " <<std::endl;
    cont2.Erase(3);
    cont2.Erase(4);
    cont2.Erase(5);
    cont2.Print();

    std::cout << "Appending 10 to the beginning: " <<std::endl;
    cont2.Insert(1,10);
    cont2.Print();

    std::cout << "Inserting 20 to the middle: " <<std::endl;
    cont2.Insert(5,20);
    cont2.Print();

    std::cout << "Inserting 30 to the end: " <<std::endl;
    cont2.Push_back(30);
    cont2.Print();

    std::cout << "4th element: " <<std::endl;
    std::cout << cont2[4];
    std::cout << std::endl;


    std::cout << "==============================" << std::endl;
    std::cout << "->Linked 1 way container type:" << std::endl;
    std::cout << "==============================" << std::endl;

    for ( int i=1; i<10; i++ ) {
           cont3.Push_back(i);
    }
    cont3.Print();
    std::cout << "Container Size: " << cont2.Size() << std::endl;

    std::cout << "Remove 3,5,7th elements: " <<std::endl;
    cont3.Erase(3);
    cont3.Erase(4);
    cont3.Erase(5);
    cont3.Print();

    std::cout << "Appending 10 to the beginning: " <<std::endl;
    cont3.Insert(1,10);
    cont3.Print();

    std::cout << "Inserting 20 to the middle: " <<std::endl;
    cont3.Insert(5,20);
    cont3.Print();

    std::cout << "Inserting 30 to the end: " <<std::endl;
    cont3.Push_back(30);
    cont3.Print();

    std::cout << "4th element: " <<std::endl;
    std::cout << cont3[4];
    std::cout << std::endl;


    std::cout << "==============================" << std::endl;
    std::cout << "->Linked 2 way iterator:" << std::endl;
    std::cout << "==============================" << std::endl;


    for (auto i = cont2.begin(), end = cont2.end(); i != end; ++i) { 
               std::cout << *i << " ";
    }
     std::cout << std::endl;


    std::cout << "===========================================" << std::endl;
    std::cout << "->Linked 2 way move with rvalue:" << std::endl;
    std::cout << "===========================================" << std::endl;
    std::cout << "Creating vector of containers L2 with 1 element each..." << std::endl;
    for ( int i =0 ; i<10; i++ ) {
             vec.push_back(get_container(i));

    }
    std::cout << "Vector values: " << std::endl;
    for ( int i =0 ; i<10; i++ ) {
             vec[i].Print();
    }
    std::cout << std::endl;



    cont4= std::move(cont2); 
    


     
    return 0; 

}







