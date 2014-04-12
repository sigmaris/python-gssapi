#!/usr/bin/env python
import subprocess


def subprocess_on_vm(vm, command):
    return subprocess.Popen(['vagrant', 'ssh', vm, '--', command])


if __name__ == '__main__':
    subprocess.check_call(('vagrant', 'up'))

    pip_install_procs = [subprocess_on_vm(vm, ' && '.join((
        'cd /python-gssapi',
        'sudo pip2 install -r dev_requirements.txt',
        'sudo pip3 install -r dev_requirements.txt',
    ))) for vm in ('server', 'client')]

    [process.wait() for process in pip_install_procs]

    server_proc = subprocess_on_vm('server', 'cd /python-gssapi && sudo python tests/integration/server.py')

    client_proc = subprocess_on_vm('client', ' && '.join((
        'echo "userpassword" | kinit -f testuser',
        'cd /python-gssapi',
        'nosetests tests.integration.test_client:ClientIntegrationTest'
    )))

    print("wait for client_proc")
    client_proc.wait()
    if client_proc.returncode == 0:
        print("wait for server_proc")
        server_proc.wait()
    else:
        print("client_proc exited with status {0}, terminating server".format(client_proc.returncode))
        server_proc.terminate()
