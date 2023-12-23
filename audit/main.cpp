#include <string>
#include <fstream>
#include <iostream>
#include <ctime>
#include <vector>
#include <iomanip>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include "syscall_table.h"


using namespace std;
void logEvent(string event, int pid) {
    ofstream logFile;
    logFile.open("event_log.txt", ios_base::app);
    time_t now = time(0);
    tm *ltm = localtime(&now);
    logFile << put_time(ltm, "%c") << " : " << pid << " : " << event << endl;
    cout << pid << " : " << event << endl;
    logFile.close();
}

string long_to_str(unsigned long long value) {
    const int n = snprintf(NULL, 0, "%llu", value);
    char buf[n+1];
    int c = snprintf(buf, n+1, "%llu", value);
    return string(buf);
}

string get_syscall_name(unsigned long long rax) {
    if (0 <= rax <= 332) {
	return table[rax];
    }

    return long_to_str(rax);
}

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "write pid" << '\n';
        return 1;
    }

    int pid = stoi(argv[1]);
    logEvent("start ptrace", pid);
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) {
        std::cerr << "Failed to attach to the process" << std::endl;
        return 1;
    }

    int status;
    waitpid(pid, &status, 0);
    user_regs_struct regs;
    while (status != -1) {
        ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
        logEvent(get_syscall_name(regs.orig_rax), pid);
        if (ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr) == -1) {
            std::cerr << "Failed to trace next system call" << std::endl;
            break;
        }
        waitpid(pid, &status, 0);
    }

    if (ptrace(PTRACE_DETACH, pid, nullptr, nullptr) == -1) {
        std::cerr << "Failed to detach from the process" << std::endl;
        return 1;
    }

    return 0;
}

