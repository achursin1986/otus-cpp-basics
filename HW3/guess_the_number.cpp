#include<iostream>
#include<string>
#include<cstdlib>
#include<fstream>
#include<ctime>
#include<cstring>
#include"struct.h"
#include"func.h"



int main(int argc, char** argv) 
{
       
       int score{0}, guess{0},max_value{0},level{0};
       bool skip{false};
       const std::string scores_filename = "high_scores.bin";
       UserRec record{{},0};
       std::fstream file;

       /* parse args, initialize game settings */       
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
              std::cin.getline(record.user,20);
              if (std::cin.fail()) {
                          std::cout << "Bad value!" << std::endl;
                          return -1;
              }

              /* game engine */
              if ( game(&record, max_value) ) {
                   std::cout << "Game got error, likely input is out of boundary, terminating" << std::endl;
                   return -1; 
              }
               /*  saving results for an user  */
              if ( results_save(record, scores_filename) ) {
                   std::cout << "Error saving result, terminating" << std::endl;
                   return -1;
              } 
        }       

       /* high scores table print */
       if ( dump_table(scores_filename) ) {
                std::cout << "Error printing table, terminating" << std::endl;
                return -1;
       } 
              
       
return 0;
}
