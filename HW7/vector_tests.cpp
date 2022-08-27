#include <vector>
#include <gtest/gtest.h>
#include "gmock/gmock.h" 

using namespace std;


class Mocker : public vector<int> {

public:
    Mocker(): vector<int>() {}
 
    MOCK_METHOD(void, Die, ());
     ~Mocker() { Die(); }

};


class Mock {
public:
     MOCK_METHOD(void, Die, ());


};


class DtorTest {
public:
    DtorTest(Mock& counter)
        : counter_{counter}
    {}

    ~DtorTest() {
         counter_.Die();
    }
private:
    Mock& counter_;
};



template<typename T>
    ::testing::AssertionResult ArraysMatch(vector<T>&expected, vector<T>&actual){
        for (int i=0; i < expected.size(); i++){
            if (expected[i] != actual[i]){
                return ::testing::AssertionFailure() << "array[" << i
                    << "] (" << actual[i] << ") != expected[" << i
                    << "] (" << expected[i] << ")";
            }
        }

        return ::testing::AssertionSuccess();
    }







TEST(vector,creation_with_int0) {

            vector<int> vec={0};
            ASSERT_EQ(0,vec[0]);

} 

TEST(vector,creation_with_double5) {

            vector<double> vec={5.0};
            ASSERT_EQ(5.0,vec[0]);

}


TEST(vector,10_int_elements) {

            vector<int> vec,expected{0,1,2,3,4,5,6,7,8,9};
            for ( int i=0; i<10; i++ ) {
                     vec.push_back(i);
            }
            EXPECT_TRUE(ArraysMatch<int>(expected, vec));

}

TEST(vector,int_size) {

            vector<int> vec,expected{0,1,2,3,4,5,6,7,8,9};
            
            for ( int i=0; i<10; i++ ) {
                     vec.push_back(i);
            }
            ASSERT_EQ(expected.size(),vec.size());

}


TEST(vector,append_int_begin) {

            vector<int> vec,expected{10,0,1,2,3,4,5,6,7,8,9};
            for ( int i=0; i<10; i++ ) {
                     vec.push_back(i);
            }
            vec.insert(vec.begin(),10);
            ASSERT_EQ(expected.size(),vec.size());
            EXPECT_TRUE(ArraysMatch<int>(expected, vec));
}

TEST(vector,erase_int_357elem) {

            vector<int> vec,expected{0,1,3,5,7,8,9};
            for ( int i=0; i<10; i++ ) {
                     vec.push_back(i);
            }
            vec.erase(vec.begin()+2);
            vec.erase(vec.begin()+3);
            vec.erase(vec.begin()+4);
            ASSERT_EQ(expected.size(),vec.size());
            EXPECT_TRUE(ArraysMatch<int>(expected, vec));
}

TEST(vector,insert_int_middle) {

            vector<int> vec,expected{0,1,2,3,20,4,5,6,7,8,9};
            for ( int i=0; i<10; i++ ) {
                     vec.push_back(i);
            }
            vec.insert(vec.begin()+4,20);
            ASSERT_EQ(expected.size(),vec.size());
            EXPECT_TRUE(ArraysMatch<int>(expected, vec));
}


TEST(vector,append_int_end) {
            
            vector<int> vec,expected{0,1,2,3,4,5,6,7,8,9,30};
            for ( int i=0; i<10; i++ ) {
                     vec.push_back(i);
            }
            vec.push_back(30);
            ASSERT_EQ(expected.size(),vec.size());
            EXPECT_TRUE(ArraysMatch<int>(expected, vec));
}




TEST(vector,container_int_copy) {

            vector<int> vec,vec1;
            for ( int i=0; i<10; i++ ) {
                     vec.push_back(i);
            }
            vec1=vec;

            EXPECT_TRUE(ArraysMatch<int>(vec1, vec));

}



TEST(vector,container_int_delete) {
            //using ::testing::Mock;
            Mocker vec;
            for ( int i=0; i<10; i++ ) {
                     vec.push_back(i);
             }
             EXPECT_CALL(vec, Die());
             //Mock::VerifyAndClearExpectations(&vec);
}



TEST(vector,container_n_destructor_call) {
            vector<DtorTest> vec;
            Mock counter;
            for ( int i=0; i<10; i++ ) {
                     vec.push_back(DtorTest(counter));

             }
             EXPECT_CALL(counter, Die()).Times(19);
  
             
}






TEST(vector,container_int_move) {

            vector<int> vec1;
            Mocker vec;
            for ( int i=0; i<10; i++ ) {
                     vec.push_back(i);
            }
            vec1= std::move(vec);
            EXPECT_CALL(vec, Die());

}


