// Read files and prints top k word by frequency

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <map>
#include <vector>
#include <chrono>
#include <thread>
//#include <mutex>

const size_t TOPK = 10;

using Counter = std::map<std::string, std::size_t>;

std::string tolower(const std::string &str);

int count_words(char* file, Counter& );

void print_topk(std::ostream& stream, const Counter&, const size_t k);

/*std::mutex Mutex;*/

int main(int argc, char *argv[]) {

    std::vector<std::thread> Threads;

    if (argc < 2) {
        std::cerr << "Usage: topk_words [FILES...]\n";
        return EXIT_FAILURE;
    }
    std::vector<Counter> Freq_dict(argc);

    auto start = std::chrono::high_resolution_clock::now();
    Counter freq_dict_summ;


    for (int i = 1; i < argc; ++i) {
        Threads.emplace_back(std::thread(count_words,std::ref(argv[i]),std::ref(Freq_dict[i-1])));
        
    }

    for ( auto& t: Threads ) { 
        t.join();
    }

    /*if ( freq_dict.size() > 0 ) { 
        print_topk(std::cout, freq_dict, TOPK);
    }*/
    freq_dict_summ = Freq_dict[0];

    for(int i = 1; i < argc; ++i) { 
        for (auto it=Freq_dict[i].begin(); it!=Freq_dict[i].end(); ++it) {
                   if ( freq_dict_summ[it->first] )
                              freq_dict_summ[it->first] += it->second;
                   else
                              freq_dict_summ[it->first] = it->second;
        }

    } 
    
    
    print_topk(std::cout, freq_dict_summ, TOPK);
    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    std::cout << "Elapsed time is " << elapsed_ms.count() << " us\n";
}

std::string tolower(const std::string &str) {
    std::string lower_str;
    std::transform(std::cbegin(str), std::cend(str),
                   std::back_inserter(lower_str),
                   [](unsigned char ch) { return std::tolower(ch); });
    return lower_str;
}

int count_words(char* file, Counter& counter) {
    std::ifstream stream{file};
        if (!stream.is_open()) {
            std::cerr << "Failed to open file " << file << '\n';
            return EXIT_FAILURE;
        }
    std::for_each(std::istream_iterator<std::string>(stream),
                  std::istream_iterator<std::string>(),
                  [&counter](const std::string &s) { /*std::lock_guard<std::mutex> guard(Mutex);*/ ++counter[tolower(s)]; });   
    return 0; 
}

void print_topk(std::ostream& stream, const Counter& counter, const size_t k) {
    std::vector<Counter::const_iterator> words;
    words.reserve(counter.size());
    for (auto it = std::cbegin(counter); it != std::cend(counter); ++it) {
        words.push_back(it);
    }

    std::partial_sort(
        std::begin(words), std::begin(words) + k, std::end(words),
        [](auto lhs, auto &rhs) { return lhs->second > rhs->second; });

    std::for_each(
        std::begin(words), std::begin(words) + k,
        [&stream](const Counter::const_iterator &pair) {
            stream << std::setw(4) << pair->second << " " << pair->first
                      << '\n';
        });
}

