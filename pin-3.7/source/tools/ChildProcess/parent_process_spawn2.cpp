/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2018 Intel Corporation. All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
#include <errno.h>
#include <spawn.h>
#include <iostream>
#include <string>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
using namespace std;

extern char **environ;

//Wait for a process completion
//Verify it returned the expected exit code

int main(int argc, char * argv[])
{
    posix_spawnattr_t attr;
    posix_spawn_file_actions_t file_actions;
    pid_t pid;
    int pip[2];
    const char* appArgv[] = {
            argv[1],
            "/dev/stdin",
            "/dev/stdout",
            NULL
    };
    if (0 != pipe(pip))
    {
        cout << "pipe failed: " << errno << endl;
        return 1;
    }

    posix_spawn_file_actions_init(&file_actions);
    posix_spawn_file_actions_addclose(&file_actions, 0);
    posix_spawn_file_actions_addclose(&file_actions, pip[1]);
    posix_spawn_file_actions_adddup2(&file_actions, pip[0], 0);
    posix_spawnattr_init(&attr);
    int err = posix_spawn(&pid, argv[1], &file_actions, &attr, (char* const*)appArgv, environ);
    if (err != 0)
    {
        // child process
        cout << "posix_spawn failed with errno " << err << endl;
    }
    else
    {
        int status;
        close(pip[0]);
        write(pip[1], "OK\n", 3);
        close(pip[1]);
        waitpid(pid, &status, 0);
        if (status !=0)
            cout << "Parent report: Child process failed. Status of the child process is "<< WEXITSTATUS(status) << endl;
        else
            cout << "Parent report: Child process exited successfully" << endl;
    }

    posix_spawnattr_destroy(&attr);
    posix_spawn_file_actions_destroy(&file_actions);
    return 0;
}
