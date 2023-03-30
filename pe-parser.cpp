#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>

const size_t START = 0x3C;

struct section {
    size_t rva;
    size_t size;
    size_t raw;
};

size_t get_raw(std::vector<section> &secs, size_t rva) {
    for (auto &sec: secs) {
        if (sec.rva <= rva && rva < sec.rva + sec.size) {
            return sec.raw + rva - sec.rva;
        }
    }
    return 0;
}

size_t my_read(std::ifstream &inn, size_t start, size_t num) {
    inn.seekg(start, inn.beg);
    size_t ret = 0;
    for (size_t i = 0, mult = 1; i < num; i++, mult <<= 8) {
        size_t temp = inn.get();
        ret += temp * mult;
    }
    return ret;
}

void my_write(std::ifstream &inn) {
    char ch;
    while (true) {
        inn.get(ch);
        if (ch == '\0') {
            break;
        }
        std::cout << ch;
    }
    std::cout << std::endl;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        std::cout << "Mode and file expected" << std::endl;
        return 0;
    }

    std::ifstream inn(argv[2]);
    if (!inn.is_open()) {
        std::cout << "can't open file" << std::endl;
        return 0;
    }

    if (std::strcmp(argv[1], "is-pe") == 0) {
        size_t cnt = 4;
        size_t position = my_read(inn, START, cnt);
        inn.seekg(position, inn.beg);

        char ftype[cnt];
        inn.read(ftype, cnt);
        if (ftype[0] != 'P' || ftype[1] != 'E' || ftype[2] != '\0' || ftype[3] != '\0') {
            inn.close();
            std::cout << "Not PE" << std::endl;
            return 1;
        }
        std::cout << "PE" << std::endl;
        inn.close();
        return 0;
    }

    size_t coff_header = my_read(inn, START, 4) + 4;
    size_t sections_number = my_read(inn, coff_header + 2, 2);
    size_t opt_header = coff_header + 20;
    size_t header_start = opt_header + 240;

    std::vector<section> sections(sections_number);
    for (size_t i = 0; i < sections_number; ++i) {
        size_t section_virtual_size = my_read(inn, header_start + i * 40 + 0x8, 4);
        size_t section_rva = my_read(inn, header_start + i * 40 + 0xC, 4);
        size_t section_raw = my_read(inn, header_start + i * 40 + 0x14, 4);
        sections[i] = {section_rva, section_virtual_size, section_raw};
    }

    if (strcmp(argv[1], "import-functions") == 0) {
        size_t import_table_rva = my_read(inn, opt_header + 0x78, 4);
        size_t import_raw = get_raw(sections, import_table_rva);

        for (size_t i = 0;; i += 20) {
            size_t lookup_table_rva = my_read(inn, import_raw + i, 4);
            size_t time_date_stamp = my_read(inn, import_raw + i + 4, 4);
            size_t forward_chain = my_read(inn, import_raw + i + 8, 4);
            size_t lib_name_rva = my_read(inn, import_raw + i + 12, 4);
            size_t addr_table_rva = my_read(inn, import_raw + i + 16, 4);

            if (lookup_table_rva == 0 && time_date_stamp == 0 && forward_chain == 0 && lib_name_rva == 0 &&
                addr_table_rva == 0) {
                break;
            }

            size_t lib_name_raw = get_raw(sections, lib_name_rva);
            inn.seekg(lib_name_raw, inn.beg);
            my_write(inn);

            size_t lookup_table_raw = get_raw(sections, lookup_table_rva);

            for (size_t j = 0;; j += 8) {
                size_t part1 = my_read(inn, lookup_table_raw + j, 4);
                size_t part2 = my_read(inn, lookup_table_raw + j + 4, 4);

                if (part1 == 0 && part2 == 0) {
                    break;
                }

                size_t flag = part2 >> 31;
                if (flag == 0) {
                    size_t name_table_rva = part1;
                    size_t name_table_raw = get_raw(sections, name_table_rva);
                    inn.seekg(name_table_raw + 2, inn.beg);
                    std::cout << "    ";
                    my_write(inn);
                }
            }
        }
        inn.close();
        return 0;
    } else if (strcmp(argv[1], "export-functions") == 0) {
        size_t exp_table_rva = my_read(inn, opt_header + 112, 4);
        size_t exp_table_raw = get_raw(sections, exp_table_rva);
        size_t ptrs_num = my_read(inn, exp_table_raw + 24, 4);
        size_t exp_name_ptr_rva = my_read(inn, exp_table_raw + 32, 4);
        size_t exp_name_ptr_raw = get_raw(sections, exp_name_ptr_rva);
        size_t ptr_into_exp_name_table_rva = my_read(inn, exp_name_ptr_raw, 4);
        size_t ptr_into_exp_name_table_raw = get_raw(sections, ptr_into_exp_name_table_rva);
        inn.seekg(ptr_into_exp_name_table_raw, inn.beg);

        for (size_t i = 0; i < ptrs_num; ++i) {
            my_write(inn);
        }
        inn.close();
        return 0;
    } else {
        std::cout << "Unexpected command" << std::endl;
        inn.close();
        return 0;
    }
}