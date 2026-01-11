#include <ncurses.h>
#include <string>
#include <openssl/rand.h>
#include "../include/encrypt.hpp"
#include <locale.h>
#include <cctype>
#include "../include/pos_fs.hpp"
#include "../include/posix.hpp"
#include "../include/defin_.hpp"
#include <format>
#include <algorithm>


std::string toStr(const std::vector<unsigned char>& data);
std::vector<unsigned char> strToVec(std::string data);
bool check_decrypt(std::vector<unsigned char> plaintext);


constexpr int key_len = 32;
std::string title = "";

struct ExitStatus {
    int code;
    std::string msg = "";
    std::string trace = "";
};

void add_trace(ExitStatus &status, std::string toAdd) {
    status.trace += toAdd + ";";
}

struct read_ret {unsigned char a; std::string b;};

struct read_ret read_file(std::string path, std::vector<unsigned char> key) {
    if (!fs::exists(path)) {
        return {.a = 18, .b = ""};
    }

    std::fstream f(path, std::ios::binary | std::ios::in);  // Opens the file

    if (!f) {
        printf("write_file(): File failed to open: %s", path.c_str());
        exit(3);  // File failed to open
    }

    f.seekg(0, std::ios::end);
    std::string f_data(f.tellg(), '\0');
    f.seekg(0, std::ios::beg);

    f.read(f_data.data(), f_data.size());

    std::vector<unsigned char> comp_enc_data = strToVec(f_data);

    auto comp_real_data = Decrypt(comp_enc_data, key);
    std::string real_data;

    if (!check_decrypt(comp_real_data)) {
        return {.a = 3, .b = ""};
    }

    real_data = toStr(comp_real_data);

    return {.a = 0, .b = real_data};
}

unsigned char write_file(std::string path, std::string data, std::vector<unsigned char> key, bool append = true) {
    if (!fs::exists(path)) {
        return 18;
    }
    std::ios::openmode mode = std::ios::binary | std::ios::in | std::ios::out;
    if (!append) {
        mode |= std::ios::trunc;
    }
    std::fstream f(path, mode);

    if (!f) {
        printf("write_file(): File failed to open: %s", path.c_str());
        exit(3);  // File failed to open
    }

    std::vector<unsigned char> comp_data = strToVec(data);

    f.seekg(0, std::ios::end);
    std::string f_data(f.tellg(), '\0');
    f.seekg(0, std::ios::beg);

    f.read(f_data.data(), f_data.size());

    if (!append) {f_data = "";}

    std::vector<unsigned char> comp_enc_data = strToVec(f_data);

    auto comp_real_data = Decrypt(comp_enc_data, key);
    std::string real_data;
    if (append) {
        if (!check_decrypt(comp_real_data)) {
            return 1;
        }
        real_data = toStr(comp_real_data);
    } else {
        real_data = "";
    }
    real_data += data;

    f << toStr(Encrypt(strToVec(real_data), key));

    return 0;
}

void _main(ExitStatus* status);

void setup() {
    initscr();              // initialize screen
    setlocale(LC_ALL, "");  // Set locale
    keypad(stdscr, TRUE);
    if (!has_colors()) {
        // terminal does not support colors
    }
    start_color();
    use_default_colors();  // optional but recommended  

    init_pair(1, COLOR_WHITE, COLOR_WHITE);
    init_pair(2, COLOR_RED, COLOR_RED);
    init_pair(3, COLOR_RED, -1);  // Red on black
    init_pair(4, -1, COLOR_WHITE);  // Inverse
}

void on_end() {
    endwin();               // restore terminal
}

std::string toBase64(const std::vector<unsigned char>& data)
{
    // Base64 expands data by 4/3 + padding
    std::string out;
    out.resize(4 * ((data.size() + 2) / 3));

    int encoded_len = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(&out[0]),
        data.data(),
        static_cast<int>(data.size())
    );

    out.resize(encoded_len);
    return out;
}

std::string toStr(const std::vector<unsigned char>& data) {
    return std::string(data.begin(), data.end());
}

std::vector<unsigned char> strToVec(std::string data) {
    return std::vector<unsigned char>(data.begin(), data.end());
}

bool check_decrypt(std::vector<unsigned char> plaintext) {
    if (plaintext.size() == 208 &&
        std::all_of(plaintext.begin(), plaintext.end(), [](unsigned char c) { return c == 0; })) {
        return false;
    }
    return true;
}

std::string random_alnum_32_openssl() {
    static constexpr char charset[] =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    unsigned char buf[32];
    RAND_bytes(buf, sizeof(buf));

    std::string out;
    out.reserve(32);

    for (unsigned char b : buf) {
        out.push_back(charset[b % (sizeof(charset) - 1)]);
    }

    return out;
}

int main() {
    setup();

    ExitStatus status{.code = 0, .msg = "\0"};
    _main(&status);
    on_end();
    printf("Docmanage exited.\n\t| Code: %d\n\t| Message: '%s'\n\t| Trace: %s", status.code, status.msg.c_str(), status.trace.c_str());
    return status.code;
}

void clearscreen() {
    clear();
    printw("\t\t\t\t==== Docmanage ====\n");
    if (*title.c_str()) printw("\t\t\t\t==== %s ====\n", title.c_str());
    printw("\n");
    
    refresh();
    return;
}

void set_title(std::string title) {
    ::title = title;
}

std::string get_input(std::string prompt, void (*perIter)(std::string input) = [](std::string input){}) {
    std::string input;
    int ch;

    noecho();
    clearscreen();
    printw(prompt.c_str());
    perIter(input);
    refresh();
    while ((ch = getch()) != '\n') {   // Enter ends input
        clearscreen();
        printw(prompt.c_str());
        if (ch == KEY_UP) {
            continue;   // Ignore Up Arrow
        }

        if (ch == KEY_BACKSPACE || ch == 127) {
            if (!input.empty()) {
                input.pop_back();
                int y, x;
                getyx(stdscr, y, x);
                //mvdelch(y, x - 1);
            }
        } else if (isprint(ch)) {
            input.push_back(ch);
        }
        perIter(input);
        refresh();
    }

    return input;
}

void _main(ExitStatus* status) {
    #ifdef NONROOT_OK
    goto debug_bypass_rootcheck;
    #endif

    if (!is_running_as_root()) {
        add_trace(*status, "Running as non-root");
        add_trace(*status, "Exiting (euid!=1/uid!=1)");
        printw("Please run this program as root! (sudo)");
        printw("\n\nPress any character to exit");
        getch();
        add_trace(*status, "Exiting");
        status->code = 8;  // Not enough permissions
        return;
    }

    debug_bypass_rootcheck:

    //printw("Hello, ncurses");
    //refresh();              // flush buffer to terminal
    //getch();                // wait for key
    
    printw("\t\t\t\t==== Docmanage ====\n");
    printw("Press any key to load.");
    refresh();
    getch();
    clearscreen();
    printw("You will soon be prompted to enter a passkey. Enter the wrong passkey, and you will be locked out from files using the previous passkey.\nIf this is your first time using the program, however, you may press ENTER to be automatically generated a passkey. \
When that happens, store it in a root-only file, or on a piece of paper -- do NOT forget it.\n[!]You are responsible for managing your own key.");
    getch();
    clearscreen();
    printw("Key: ");

    get_key_1:
    std::string key = get_input("Key: ", [](std::string input) {
        for (int i = 0; i < key_len; i++) {
            if (i >= input.length()) break;
            if (!std::isalnum(input[i])) {
                attron(COLOR_PAIR(3));
            }
            printw("%c", input[i]);
            if (!std::isalnum(input[i])) {
                attroff(COLOR_PAIR(3));
            }
        }
        for (int i = input.length(); i < key_len; i++) {
            attron(COLOR_PAIR(1)); printw("*"); attroff(COLOR_PAIR(1));
        }
        for (int i = key_len; i < input.length(); i++) {
            if (std::isalnum(input[i])) {
                attron(COLOR_PAIR(1)); printw("X"); attroff(COLOR_PAIR(1));
            } else {
                attron(COLOR_PAIR(2)); printw("X"); attroff(COLOR_PAIR(2));
            }
        }
        if (input.length() > key_len) {
            printw("\n");
            for (int i = 0; i < key_len + 5; i++) {
                printw(" ");
            }
            for (int i = key_len; i < input.length(); i++) {
                printw("%c", input[i]);
            }
        }
        printw("\n\n(%s)\n\n", toBase64(SHA512(strToVec(input))).c_str());
        for (char c : input) {
            if (!std::isalnum(c)) {
                printw("All keys are purely alphanumeric characters! This is not the correct key!\n\n");
                break;
            }
        }
        #ifndef _DISABLE_FIX_ISSUE_NO2
        printw("If this is your first time using the program, please press ENTER without typing anything to generate a key.\n");
        attron(COLOR_PAIR(3));
        printw("Please do not enter a custom key! Generate one first, if you haven't already!");
        attroff(COLOR_PAIR(3));
        #endif
    });

    if (!*key.c_str()) {
        // GENERATE RANDOM KEY

        clearscreen();
        key = random_alnum_32_openssl();
        int state = 0;
        int cursor = 0;
        while (true) {
            clearscreen();

            if (state == 0) {
                printw("%s\n\n", key.c_str());
                printw("\n\nPress DOWN arrow to edit first half.\n\nPress SPACE to save.\n");
            }
            if (state == 1) {
                attron(COLOR_PAIR(4));
                for (int i = 0; i < key_len / 2; i++) {
                    if (i == cursor) {attroff(COLOR_PAIR(4));};
                    printw("%c", key[i]);
                    if (i == cursor) {attron(COLOR_PAIR(4));};
                }
                attroff(COLOR_PAIR(4));
                for (int i = key_len / 2; i < key_len; i++) {
                    printw("%c", key[i]);
                }
                printw("\n\n");
                for (int i = 0; i < key_len / 2; i++) {
                    if (i == cursor) attron(COLOR_PAIR(4));
                    printw("%c", key[i]);
                    if (i == cursor) attroff(COLOR_PAIR(4));
                }
                printw("\n\n\n\nPress UP arrow to save edits.\n\nNote: You may only type alphanumeric characters.");
            }
            refresh();

            auto ch = getch();
            if (ch == KEY_DOWN && state == 0) {
                state = 1;
                add_trace(*status, "Edited key");
            } else if (ch == KEY_UP && state == 1) {
                state = 0;
                cursor = 0;
            } else if (ch == KEY_LEFT && state == 1) {
                if (cursor > 0) cursor--;
            } else if (ch == KEY_RIGHT && state == 1) {
                if (cursor < key_len / 2 - 1) cursor++;
            } else if (ch == ' ' && state == 0) {
                break;
            }
            else if (state == 1) {
                if (ch < 0 || ch > 255 || !std::isalnum(static_cast<unsigned char>(ch))) {
                    continue;
                }

                char ascii = static_cast<char>(ch);

                key[cursor] = ascii;
            }
        }

        clearscreen();
        printw("Key: %s\n\nWARNING: Remember this!!", key.c_str());
        add_trace(*status, "Randomly generated key");
        printw("\n\n\nPress any key to exit the program.");
        getch();
        return;

    } else {
        for (char c : key) {
            if (!std::isalnum(c)) {
                clearscreen();
                attron(COLOR_PAIR(3)); printw("The entered key is not valid (missing criteria: purely alphanumeric). Press any key to try again."); attroff(COLOR_PAIR(3));
                getch();
                goto get_key_1;
            }
        }
        if (key.length() != key_len) {
            clearscreen();
            attron(COLOR_PAIR(3)); printw("The entered key is not valid (missing criteria: lenght=32; current criteria: lenght=%d). Press any key to try again.", key.length()); attroff(COLOR_PAIR(3));
            getch();
            goto get_key_1;
        }

        idk_do_smth:
        add_trace(*status, "User-entered key");
    }

    #ifdef _DISABLE_FIX_ISSUE_NO1
    clearscreen();
    getch();
    #endif

    goto_file_view_1:
    auto encryption_key = SHA512(strToVec(key));
    if (!directory_exists(DOC_LOC)) {
        mk_dir(DOC_LOC);
        add_trace(*status, "Created doc directory");
    }

    set_title("File List");
    clearscreen();

    std::vector<std::string> files;

    for (auto file : get_dirs(DOC_LOC)) {
        if (!file.exists()) continue;
        if (file.is_directory()) continue;
        if (!file.path().has_filename()) continue;
        if (file.is_symlink()) printf("Ignoring %s for security reasons (symlink)", file.path().string());
        files.push_back(file.path().string());
    }

    files.push_back("Create file");

    int cursor = 0;
    std::string selection;
    while (true) {
        clearscreen();
        int i = 0;
        for (std::string file : files) {
            if (i == cursor) attron(COLOR_PAIR(4));
            printw("> %s\n", file.c_str());
            if (i == cursor) attroff(COLOR_PAIR(4));
            i++;
        }
        refresh();
        int ch = getch();
        if (ch == KEY_DOWN) {
            cursor++;
        } else if (ch == KEY_UP) cursor--;
        if (cursor < 0) cursor = files.size() - 1;
        if (cursor >= files.size()) cursor = 0;
        if (ch == KEY_ENTER || ch == ' ' || ch == '\n') {
            selection = files[cursor];
            goto goto_file_view_2;
        }
    }

    goto_file_view_2:

    cursor = 0;

    if (selection == "Create file") {
        set_title("File Creation");
        clearscreen();
        printw("");
        std::string name = get_input("File name: ", [](std::string input){
            size_t i = 0;
            if (!*input.c_str()) {
                attron(COLOR_PAIR(4));
                printw("|");
                attroff(COLOR_PAIR(4));
            }
            for (char ch : input) {
                if (i == input.length() - 1) attron(COLOR_PAIR(4));
                printw("%c", ch);
                if (i == input.length() - 1) attroff(COLOR_PAIR(4));
                i++;
            }
            printw(".md.enc");
        });
        name = std::format("{}/{}.md.enc", DOC_LOC, name);

        mk_file(name);
        unsigned char a = write_file(name, " ", encryption_key, false);
        if (a) {
            printf("Failed to open file (W) %s: (%d)\n", name.c_str(), a);
            exit(4);
        }

        goto goto_file_view_1;
    } else {
        std::string file = selection;
        int cursor_2 = 0;
        std::vector<std::string> choices = {"Edit file", "Export file", "Redact file"};

        std::string selection;
        while (true) {
            clearscreen();
            int i = 0;
            for (std::string choice : choices) {
                if (i == cursor_2) attron(COLOR_PAIR(4));
                printw("> %s\n", choice.c_str());
                if (i == cursor_2) attroff(COLOR_PAIR(4));
                i++;
            }
            refresh();
            int ch = getch();
            if (ch == KEY_DOWN) {
                cursor_2++;
            } else if (ch == KEY_UP) cursor_2--;
            if (cursor_2 < 0) cursor_2 = choices.size() - 1;
            if (cursor_2 >= choices.size()) cursor_2 = 0;
            if (ch == KEY_ENTER || ch == ' ' || ch == '\n') {
                selection = choices[cursor_2];
                goto goto_file_edit_menu_1;
            }
        }

        goto_file_edit_menu_1:

        if (selection == "Edit file") {
            goto goto_file_edit_1;
        } else if (selection == "Export file") {
            #ifdef EXPER_FEAT_EXPORT
                set_title("Export file " + file);
                clearscreen();
                std::string export_location = "/root/" + get_input("Export location: ", [](std::string input) {
                    if (input.empty()) {
                        printw("/root/.md");
                        return;
                    };
                    std::string input_most = input;
                    if (!input_most.empty()) {input_most.pop_back();}
                    printw("/root/%s", input_most.c_str());
                    attron(COLOR_PAIR(4));
                    printw("%c", input.back());
                    attroff(COLOR_PAIR(4));
                    printw(".md");
                }) + ".md";
                struct read_ret ret = read_file(file, encryption_key);
                if (ret.a != 0) {
                    clearscreen();
                    printw("Failed to export file %s. Errno: %d\n", file.c_str(), ret.a);
                }
                std::string data = ret.b;
                std::ofstream export_file = mk_file(export_location);
                export_file << data;
                export_file.flush(); export_file.close();
                clearscreen();
                printw("File successfully exported at '%s'. Press any key to return to menu.", export_location.c_str());
                getch();
                
                goto goto_file_view_1;
            #else
                goto goto_feat_not_ready;
            #endif
        } else if (selection == "Redact file") {
            #ifdef EXPER_FEAT_REDACT
            
            set_title("Redact file " + file);

            int offset = 0;
            struct {int line; int ch;} line_cursor{.line = 0, .ch = 0};

            struct read_ret ret = read_file(file, encryption_key);
            if (ret.a != 0) { printw("[FAILED TO OPEN FILE: %d]\n\nPress any key to return.", ret.a); goto goto_file_view_1;}
            std::string original_content = ret.b;

            int height, width;
            getmaxyx(stdscr, height, width);




            int total_lines;
            std::vector<std::string> per_line;
            std::string buffer = "";

            int line = 0, ch = 0, increment = 0;

            while (true) {
                if (original_content[increment] == '\n') {
                    total_lines++;
                    per_line.push_back(buffer);
                    continue;
                }
                buffer += original_content[increment];
            }




            while (true) {
                clearscreen();

                int real_height = height - 1 - 1 - 2 - 1;  // -TITLE -SUBTITLE -TOTAL_PADDING -BOTTOM_LINE

                int increment = offset;
                for (int line = 0; line < real_height; line++) {
                    for (int ch = 0; ch < width; ch++) {
                        if (original_content[increment] == '\n') break;
                        if (line_cursor.line == line && line_cursor.ch == ch) attron(COLOR_PAIR(4));
                        printw("%c", original_content[increment]);
                        if (line_cursor.line == line && line_cursor.ch == ch) attroff(COLOR_PAIR(4));
                        increment++;
                    }
                    printw("\n");
                    total_lines = line;
                }

                refresh();

                int input = getch();

                if (input == KEY_UP) {
                    if (line_cursor.line > 0) line_cursor.line--;
                } else if (input == KEY_DOWN) {
                    if (line_cursor.line < )
                }
            }

            #else
            goto goto_feat_not_ready;
            #endif
        } else {
            goto_feat_not_ready:
            clearscreen();
            printw("That feature () is not ready yet. Press any character to return.\n");
            getch();
            goto goto_file_view_1;
        }

        goto goto_file_view_1;

        goto_file_edit_1:
        std::string filename = file;
        filename.erase(filename.size() - 4); // removes ".enc"
        mk_file(filename);
        auto dat = read_file(file, encryption_key);
        if (dat.a != 0) {
            printf("Failed to decrypt file %s for writing (%d)\n", file.c_str(), dat.a);
            exit(151);
        }
        std::string orig_data = dat.b;
        std::ofstream _filename_f(filename);
        _filename_f << orig_data;
        _filename_f.flush();
        _filename_f.close();

        def_prog_mode();
        endwin();

        std::string cmd = std::format("nano {}", filename);
        int ret = system(cmd.c_str());

        reset_prog_mode();
        refresh();

        std::ifstream in(filename, std::ios::binary);
        std::string data((std::istreambuf_iterator<char>(in)), {});

        write_file(file, data, encryption_key, false);
        rm_file(filename);

        goto goto_file_view_1;
    }

    status->code = 0;
    add_trace(*status, "Exited");
}


// NOTE: auto plaintext = Decrypt(ciphertext, key512);
// NOTE: 
// NOTE: if (plaintext.size() == 208 &&
// NOTE:     std::all_of(plaintext.begin(), plaintext.end(),
// NOTE:                 [](unsigned char c) { return c == 0; }))
// NOTE: {
// NOTE:     // DECRYPTION FAILED
// NOTE:     // wrong key OR tampered data
// NOTE:     return ERROR;
// NOTE: }
// NOTE: 
// NOTE: // Safe to use plaintext
// NOTE: 



// NOTE: #include <cstdlib>
// NOTE: #include <iostream>
// NOTE: 
// NOTE: int main() {
// NOTE:     int ret = system("nano example.txt");
// NOTE: 
// NOTE:     if (ret == 0) {
// NOTE:         std::cout << "Nano exited successfully\n";
// NOTE:     } else {
// NOTE:         std::cout << "Nano exited with error\n";
// NOTE:     }
// NOTE: 
// NOTE:     // Continue execution
// NOTE:     std::cout << "Executing more code...\n";
// NOTE: }
