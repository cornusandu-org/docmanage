#include <ncurses.h>
#include <string>
#include <openssl/rand.h>

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
}

void on_end() {
    endwin();               // restore terminal
}

std::string random_alnum_32_openssl()
{
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

    std::string input;
    int ch;

    std::string key;

    // TOFIX: This also detects KEY_UP signals, leading to double-typed characters
    while ((ch = getch()) != '\n') {   // Enter ends input
        if (ch == KEY_BACKSPACE || ch == 127) {
            if (!input.empty()) {
                input.pop_back();
                int y, x;
                getyx(stdscr, y, x);
                mvdelch(y, x - 1);
            }
        } else if (isprint(ch)) {
            input.push_back(ch);
            addch(ch);
        }
        refresh();
    }

    if (!*input.c_str()) {
        key = random_alnum_32_openssl().c_str();
        printw("Key: %s\n\nWARNING: Remember this!!", key.c_str());
        add_trace(*status, "Randomly generated key");
        getch();
    } else {
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
