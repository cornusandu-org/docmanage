#include <ncurses.h>
#include <string>
#include <openssl/rand.h>
#include "../include/encrypt.hpp"
#include <locale.h>
#include <cctype>

constexpr int key_len = 32;

struct ExitStatus {
    int code;
    std::string msg = "";
    std::string trace = "";
};

void add_trace(ExitStatus &status, std::string toAdd) {
    status.trace += toAdd + ";";
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
    printw("\t\t\t\t==== Docmanage ====\n\n");
    refresh();
    return;
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
                printw("All keys are purely alphanumeric characters! This is not the correct key!");
                break;
            }
        }
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

    clearscreen();

    getch();

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
