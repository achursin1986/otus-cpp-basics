#include <iostream>
#include <string>
#include <cstdlib>
#include <fstream>
#include <ctime>
#include <cstring>


struct userRec {
         char user[20];
         int score;
};



int main(int argc, char** argv) 
{
       
       int score{0}, guess{0},max_value{0},level{0},pos;
       bool skip{false}, found{false};
       std::string user{0};
       const std::string scores_filename = "high_scores.bin";
       userRec* record = new userRec;
       userRec* test = new userRec;
       std::fstream file;
       
       /*parse args */ 

       if (argc >= 2) {

            for ( int i=1; i<argc; ++i ) {
                     std::string arg{ argv[i] };
                     if (arg == "-max") {
                                      max_value = std::stoi(argv[i+1]);
                                      ++i;
                     }
                     if (arg == "-table") {
                                      skip = true;
                                      break;
                     }
                     if (arg == "-level") {
                                      level = std::stoi(argv[i+1]);
                                      ++i;
                     }
            } 


       }
       if ( level > 0 && max_value > 0 )  {
             std::cout << "Entered both -max and -level, use either of two, terminating" << std::endl;
             return -1;

       } 
       if ( level < 0 || level  > 3 )  {
             std::cout << "Entered -level is incorrect, use values 1,2 or 3, terminating" << std::endl;
             return -1;

       }
       if ( max_value == 0 ) {

            max_value = 100;
       }
       if ( level == 1 )  { 
            max_value = 10;

       } 
       if ( level == 2 )  {
           max_value = 50;

       }
       if ( level == 3 )  {
          max_value = 100;

       }


       if ( ! skip ) { 
              std::cout << "Hi! Enter your name please:\n";
              std::cin.getline(record->user,20);
              if (std::cin.fail()) {
                          std::cout << "Bad value!" << std::endl;
                          return -1;
              }

              std::srand(std::time(nullptr));
              const int random_value = std::rand() % max_value;

              do {  
                    std::cout << "Enter your guess:";
                    std::cin >> guess;

                    if ( guess < 0 || guess > max_value ) {
                                 std::cout << "out of range value entered, terminating" << std::endl;
                                 return -1; 
                    } 
       
                    if ( guess > random_value ) {
                                 std::cout << "less than " << guess << std::endl;
                                 ++record->score;
                                 continue;
                    }
                    if ( guess < random_value ) {
                                 std::cout << "greater than " << guess << std::endl;
                                 ++record->score;
                                 continue;
                    }
                    if ( guess == random_value ) {
                                 ++record->score;
                                 
                                 std::cout << "you won! attempts = " << record->score << std::endl;
                                 break; 
                    }
       
               } while ( true );

              /*  saving results for an user  */
              file.open(scores_filename, std::ios::in | std::ios::binary | std::ios::out );
              //if (!file.is_open())  {
              //              std::cout << "Failed to open file for read and write: " << scores_filename << "!" << std::endl;
              //              return -1;
              //}
              while (file.read(reinterpret_cast<char*>(test), sizeof(*test)) ) {
                           pos = file.tellg();
                           if ( file )  { 
                                if ( strcmp(test->user,record->user) == 0 ) {
                                            found = true;
                                            if ( record->score < test->score ) {  
                                                          file.seekp(pos-sizeof(*record), std::ios::beg);
                                                          file.write(reinterpret_cast<char*>(record), sizeof(*record));
                                                           break;
                                            }
                                } 

                           } 


              } 
              file.close();
              if ( ! found )  {
                    file.open(scores_filename,  std::ios::binary | std::ios::app);
                    if (!file.is_open())  {
                            std::cout << "Failed to open file for append: " << scores_filename << "!" << std::endl;
                            return -1;
                    }
                    file.write(reinterpret_cast<char*>(record), sizeof(*record));
                    file.close(); 
              }
       } 


       /* high scores table print */
       
          file.open(scores_filename, std::fstream::in | std::fstream::binary);
           if (!file.is_open())  {
                            std::cout << "Failed to open file for read: " << scores_filename << "!" << std::endl;
                            return -1;
             }
           std::cout << "High scores table:" << std::endl;
           while ( file.read(reinterpret_cast<char*>(test), sizeof(*test)) ) {
                  std::cout << test->user << " " << test->score << std::endl;
                  }
                   
           file.close();
           free(record);
           free(test);
                  

return 0;
}
