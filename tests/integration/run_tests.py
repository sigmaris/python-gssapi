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
        'python2 setup.py develop --user',
        'python3 setup.py develop --user',
    ))) for vm in ('server', 'client')]

    [process.wait() for process in pip_install_procs]

    server2_proc = subprocess_on_vm('server', 'cd /python-gssapi && sudo python2 tests/integration/server.py')
    server3_proc = subprocess_on_vm('server', 'cd /python-gssapi && sudo python3 tests/integration/server.py')

    client2_proc = subprocess_on_vm('client', ' && '.join((
        'echo "userpassword" | kinit -f testuser',
        'cd /python-gssapi',
        'nosetests-2.7 tests.integration.test_client:ClientIntegrationTest'
    )))
    client3_proc = subprocess_on_vm('client', ' && '.join((
        'echo "userpassword" | kinit -f testuser',
        'cd /python-gssapi',
        'nosetests-3.2 tests.integration.test_client:ClientIntegrationTest'
    )))


    print("wait for client_procs")
    client2_proc.wait()
    client3_proc.wait()
    if client2_proc.returncode == 0:
        print("wait for server2_proc")
        server2_proc.wait()
    else:
        print("client2_proc exited with status {0}, terminating server".format(client2_proc.returncode))
        server2_proc.terminate()
    if client3_proc.returncode == 0:
        print("wait for server3_proc")
        server3_proc.wait()
    else:
        print("client3_proc exited with status {0}, terminating server".format(client3_proc.returncode))
        server3_proc.terminate()
