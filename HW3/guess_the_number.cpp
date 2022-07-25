#include <iostream>
#include <string>
#include <cstdlib>
#include <fstream>
#include <ctime>



int main(int argc, char** argv) 
{
       
       int score{0}, guess{0},max_value{0},level{0};
       bool skip{false}, found{false};
       std::string user{0};
       const std::string scores_filename = "high_scores.txt";
       
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
              std::cin >> user;

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
                                 ++score;
                                 continue;
                    }
                    if ( guess < random_value ) {
                                 std::cout << "greater than " << guess << std::endl;
                                 ++score;
                                 continue;
                    }
                    if ( guess == random_value ) {
                                 ++score;
                                 
                                 std::cout << "you won! attempts = " << score << std::endl;
                                 break; 
                    }
       
               } while ( true );


              /*  saving results for an user  */
              std::ofstream out_file{scores_filename, std::ios_base::app};
              if (!out_file.is_open()) {
                        std::cout << "Failed to open file for write: " << scores_filename << "!" << std::endl;
                        return -1;
              }

              out_file << user << ' ';
              out_file << score;
              out_file << std::endl;      
             
                    
       } 


       /* high scores table print */
       std::ifstream in_file{scores_filename};
       if (!in_file.is_open()) {
                   std::cout << "Failed to open file for read: " << scores_filename << "!" << std::endl;
                   return -1;
        }

       std::cout << "High scores table:" << std::endl;

       while (true) {
            in_file >> user;
            in_file >> score;
            in_file.ignore();
                 if (in_file.fail()) {
                                break;
                 }

                 std::cout << user << '\t' << score << std::endl;
       }
       
                  

return 0;
}
