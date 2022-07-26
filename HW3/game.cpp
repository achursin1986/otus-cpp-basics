#include<iostream>
#include<ctime>
#include"struct.h"
#include"func.h"


int game(UserRec* record, int max_value) {

              std::srand(std::time(nullptr));
              const int random_value = std::rand() % max_value;
              int guess;

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

               } while (true);
return 0;

}
