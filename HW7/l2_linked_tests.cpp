#include "l2_linked_container.hpp"
#include <gtest/gtest.h>
#include "gmock/gmock.h" 


template <typename T> class Mock : public L2_Node<T> {
public:
    Mock(T value): L2_Node<T>(value) {}
    MOCK_METHOD(void, Die, ());
    ~Mock() { Die(); }

};





template<typename T, int size>
    ::testing::AssertionResult ArraysMatch(const T (&expected)[size], L2_Node<T>&actual){
        for (int i=1; i <= size; i++){
            if (expected[i-1] != actual[i]){
                return ::testing::AssertionFailure() << "array[" << i
                    << "] (" << actual[i] << ") != expected[" << i
                    << "] (" << expected[i] << ")";
            }
        }

        return ::testing::AssertionSuccess();
    }

template<typename T>
    ::testing::AssertionResult ArraysMatch(L2_Node<T>&expected, L2_Node<T>&actual){
        for (int i=1; i <= expected.Size(); i++){
            if (expected[i] != actual[i]){
                return ::testing::AssertionFailure() << "array[" << i
                    << "] (" << actual[i] << ") != expected[" << i
                    << "] (" << expected[i] << ")";
            }
        }

        return ::testing::AssertionSuccess();
    }







TEST(L2_linked,creation_with_int0) {

            L2_Node<int> cont(0);
            ASSERT_EQ(0,cont[1]);

} 

TEST(L2_linked,creation_with_double5) {

            L2_Node<double> cont(5.0);
            ASSERT_EQ(5.0,cont[1]);

}


TEST(L2_linked,10_int_elements) {

            L2_Node<int> cont(0);
            int expected[10]={0,1,2,3,4,5,6,7,8,9};
            for ( int i=1; i<10; i++ ) {
                     cont.Push_back(i);
            }
            EXPECT_TRUE(ArraysMatch<int>(expected, cont));

}

TEST(L2_linked,int_size) {

            L2_Node<int> cont(0);
            int expected=10;
            for ( int i=1; i<expected; i++ ) {
                     cont.Push_back(i);
            }
            ASSERT_EQ(expected,cont.Size());

}


TEST(L2_linked,append_int_begin) {

            L2_Node<int> cont(0);
            int expected[11]={10,0,1,2,3,4,5,6,7,8,9};
            int expected_size=11;
            for ( int i=1; i<10; i++ ) {
                     cont.Push_back(i);
            }
            cont.Insert(1,10);
            EXPECT_TRUE(ArraysMatch<int>(expected, cont));
            ASSERT_EQ(expected_size,cont.Size());
}

TEST(L2_linked,erase_int_357elem) {

            L2_Node<int> cont(0);
            int expected[7]={0,1,3,5,7,8,9};
            int expected_size=7;
            for ( int i=1; i<10; i++ ) {
                     cont.Push_back(i);
            }
            cont.Erase(3);
            cont.Erase(4);
            cont.Erase(5);
            ASSERT_EQ(expected_size,cont.Size());
            EXPECT_TRUE(ArraysMatch<int>(expected, cont));
}

TEST(L2_linked,insert_int_middle) {

            L2_Node<int> cont(0);
            int expected[11]={0,1,2,3,20,4,5,6,7,8,9};
            int expected_size=11;
            for ( int i=1; i<10; i++ ) {
                     cont.Push_back(i);
            }
            cont.Insert(5,20);
            ASSERT_EQ(expected_size,cont.Size());
            EXPECT_TRUE(ArraysMatch<int>(expected, cont));
}


TEST(L2_linked,append_int_end) {

            L2_Node<int> cont(0);
            int expected[11]={0,1,2,3,4,5,6,7,8,9,30};
            int expected_size=11;
            for ( int i=1; i<10; i++ ) {
                     cont.Push_back(i);
            }
            cont.Push_back(30);
            ASSERT_EQ(expected_size,cont.Size());
            EXPECT_TRUE(ArraysMatch<int>(expected, cont));
}




TEST(L2_linked,container_int_copy) {

            L2_Node<int> cont(0),cont1(0);
            int expected[10]={0,1,2,3,4,5,6,7,8,9};
            for ( int i=1; i<10; i++ ) {
                     cont.Push_back(i);
            }
            cont1=cont;

            EXPECT_TRUE(ArraysMatch<int>(cont1, cont));

}




TEST(L2_linked,container_int_delete) {
             /* "for each element destructor is called", in my case I have a struct so destructor is "delete" 
             *  found this way to do that: https://godbolt.org/z/srqaoxar9
             */
             Mock<int> test(0);
             for ( int i=1; i<10; i++ ) {
                     test.Push_back(i);
             }
             EXPECT_CALL(test, Die());
}



TEST(L2_linked,container_int_move) {

            L2_Node<int> cont(0);
            Mock<int> test(0);
            for ( int i=1; i<10; i++ ) {
                     test.Push_back(i);
            }
            cont= std::move(test);
            EXPECT_CALL(test, Die());
           
                        

}





int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}








