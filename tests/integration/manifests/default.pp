class defaults {
	include apt

	exec {
		"apt-get update":
			path => "/usr/bin:/usr/sbin:/bin:/sbin:/usr/local/bin";
		'easy_install-2.7 pip':
			require => Package['python-setuptools'],
			creates => '/usr/local/bin/pip2',
			path => "/usr/bin:/usr/sbin:/bin:/sbin:/usr/local/bin";
		'easy_install3 pip':
			require => Package['python3-setuptools'],
			creates => '/usr/local/bin/pip3',
			path => "/usr/bin:/usr/sbin:/bin:/sbin:/usr/local/bin";
	}

	Exec["apt-get update"] -> Package <| |>

	apt::ppa { 'ppa:pypy/ppa': }

	package {
		"krb5-user":
			ensure => installed;
		"libkrb5-dev":
			ensure => installed;
		"kstart":
			ensure => installed;
		"build-essential":
			ensure => installed;
		"python-dev":
			ensure => installed;
		"python3-dev":
			ensure => installed;
		"libffi-dev":
			ensure => installed;
		"python-setuptools":
			ensure => installed;
		"python3":
			ensure => installed;
		"python3-setuptools":
			ensure => installed;
		"pypy":
			ensure => installed,
			require => Apt::Ppa['ppa:pypy/ppa'];
	}

	file {
		"/etc/hosts":
			ensure => file,
			content => template("hosts/hosts");
		"/etc/krb5.conf":
			ensure => file,
			content => template("kerberos/krb5.conf"),
			require => Package["krb5-user"],
	}
}

node 'kdc' {
	require defaults

	package {
		"krb5-kdc":
			ensure => installed;
		"krb5-admin-server":
			ensure => installed;
	}

	file {
		"/etc/krb5kdc/kdc.conf":
			ensure => file,
			content => template("kerberos/kdc.conf"),
			require => Package["krb5-kdc"];
	}

	Exec {
		path => "/usr/bin:/usr/sbin:/bin:/sbin:/usr/local/bin",
	}

	exec {
		"ln -sf /dev/urandom /dev/random":  # https://www.virtualbox.org/ticket/11297
			unless => "test -L /dev/random";
		"create_krb_db":
			command => "kdb5_util create -s -r PYTHONGSSAPI.TEST -P masterpassword",
			creates => "/var/lib/krb5kdc/principal",
			require => [
				Exec["ln -sf /dev/urandom /dev/random"],
				File["/etc/krb5kdc/kdc.conf"],
			],
			notify => Exec["create_server_principal", "create_client_principal", "create_user_principal"];
		"create_server_principal":
			command => "kadmin.local -q 'addprinc -pw serverkey host/server.pythongssapi.test'",
			require => Exec["create_krb_db"],
			refreshonly => true;
		"extract_server_principal":
			command => "kadmin.local -q 'ktadd -k /vagrant/server.keytab host/server.pythongssapi.test'",
			require => Exec["create_server_principal"],
			creates => "/vagrant/server.keytab";
		"create_client_principal":
			command => "kadmin.local -q 'addprinc -pw clientkey host/client.pythongssapi.test'",
			require => Exec["create_krb_db"],
			refreshonly => true;
		"extract_client_principal":
			command => "kadmin.local -q 'ktadd -k /vagrant/client.keytab host/client.pythongssapi.test'",
			require => Exec["create_client_principal"],
			creates => "/vagrant/client.keytab";
		"create_user_principal":
			command => "kadmin.local -q 'addprinc -pw userpassword testuser'",
			require => Exec["create_krb_db"],
			refreshonly => true;
	}

	service { "krb5-kdc":
		enable => true,
		ensure => running,
		hasrestart => true,
		hasstatus => true,
		require => [
			Exec["create_krb_db"],
			File["/etc/krb5kdc/kdc.conf"]
		],
	}
}

node 'server' {
	include defaults

	file { "/etc/krb5.keytab":
		ensure => file,
		owner => root,
		group => root,
		mode => '0600',
		source => "file:///vagrant/server.keytab",
	}
}

node 'client' {
	include defaults

	file { "/etc/krb5.keytab":
		ensure => file,
		owner => root,
		group => root,
		mode => '0600',
		source => "file:///vagrant/client.keytab",
	}
}
