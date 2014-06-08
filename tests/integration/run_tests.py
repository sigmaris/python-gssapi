#!/usr/bin/env python
import subprocess
import time


def subprocess_on_vm(vm, command):
    return subprocess.Popen(['vagrant', 'ssh', vm, '--', command])


if __name__ == '__main__':
    subprocess.check_call(('vagrant', 'up'))

    pip_install_procs = [subprocess_on_vm(vm, ' && '.join((
        'cd /python-gssapi',
        'sudo python2 -m pip install -r test_requirements.txt',
        'sudo pypy -m pip install -r test_requirements.txt',
        'sudo python3 -m pip install -r test_requirements.txt',
        'python2 setup.py develop --user',
        'pypy setup.py develop --user',
        'python3 setup.py develop --user',
    ))) for vm in ('server', 'client')]

    [process.wait() for process in pip_install_procs]

    server_procs = (
        subprocess_on_vm('server', 'cd /python-gssapi && sudo python2 tests/integration/server.py'),
        subprocess_on_vm('server', 'cd /python-gssapi && sudo pypy tests/integration/server.py'),
        subprocess_on_vm('server', 'cd /python-gssapi && sudo python3 tests/integration/server.py'),
    )

    print("Wait for server procs to start...")
    time.sleep(5)

    client_procs = (
        subprocess_on_vm('client', ' && '.join((
            'echo "userpassword" | kinit -f testuser',
            'cd /python-gssapi',
            'python2 /usr/local/bin/nosetests-2.7 tests.integration.test_client:ClientIntegrationTest'
        ))),
        subprocess_on_vm('client', ' && '.join((
            'echo "userpassword" | kinit -f testuser',
            'cd /python-gssapi',
            'pypy /usr/local/bin/nosetests-2.7 tests.integration.test_client:ClientIntegrationTest'
        ))),
        subprocess_on_vm('client', ' && '.join((
            'echo "userpassword" | kinit -f testuser',
            'cd /python-gssapi',
            'python3 /usr/local/bin/nosetests-3.2 tests.integration.test_client:ClientIntegrationTest'
        ))),
    )

    print("wait for client_procs")
    for index, client_proc in enumerate(client_procs):
        client_proc.wait()
        if client_proc.returncode == 0:
            print("wait for server proc {0}".format(index))
            server_procs[index].wait()
        else:
            print("client_proc {0} exited with status {1}, terminating server".format(
                index, client_proc.returncode
            ))
            server_procs[index].terminate()

    # Clean up any old server processes
    subprocess_on_vm('server', 'sudo pkill -f tests/integration/server.py')
