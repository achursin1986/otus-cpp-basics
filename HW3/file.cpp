#include<iostream>
#include<fstream>
#include <cstring>
#include <string>
#include"struct.h"
#include"func.h"


int dump_table (const std::string scores_filename) {
           UserRec test;
           std::fstream file;
           file.open(scores_filename, std::fstream::in | std::fstream::binary);
           if (!file.is_open())  {
                            std::cout << "Failed to open file for read: " << scores_filename << "!" << std::endl;
                            return -1;
             }
           std::cout << "High scores table:" << std::endl;
           while ( file.read(reinterpret_cast<char*>(&test), sizeof(test)) ) {
                  std::cout << test.user << " " << test.score << std::endl;
                  }
return 0;
}


int  results_save (UserRec record, const std::string scores_filename) {
            UserRec test{{},0};
            std::fstream file;
            int pos{0};
            bool found{false};
            file.open(scores_filename, std::ios::in | std::ios::binary | std::ios::out );   
            while (file.read(reinterpret_cast<char*>(&test), sizeof(test))  ) {
                         pos = file.tellg();
                         if ( file )  {
                              if ( strcmp(test.user,record.user) == 0 ) {
                                          found = true;
                                          if ( record.score < test.score ) {
                                                        file.seekp(pos-sizeof(record), std::ios::beg);
                                                        file.write(reinterpret_cast<char*>(&record), sizeof(record));
                                                        break;
                                          }
                              }

                         }


            }
            file.close();
            if ( ! found )  {
                  file.open(scores_filename, std::ios::binary | std::ios::app);
                  if (!file.is_open())  {
                          std::cout << "Failed to open file for append: " << scores_filename << "!" << std::endl;
                          return -1;
                  }
                  file.write(reinterpret_cast<char*>(&record), sizeof(record));
                  file.close();
            }
return 0;
}


