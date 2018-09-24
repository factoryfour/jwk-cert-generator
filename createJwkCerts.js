const { spawn, exec } = require('child_process');
const fs = require('fs');

const generatePrivate = () => {
	return new Promise((resolve, reject) => {
		exec('openssl genrsa 2048', (err, stdout) => {
			if (err) {
				return reject(err);
			}
			return resolve(stdout);
		});
	});
};

const generatePublic = (private) => {
	return new Promise((resolve, reject) => {
		const output = [];
		const errors = [];

		const child = spawn('openssl', ['rsa', '-RSAPublicKey_out']);

		child.stdin.write(private);

		child.on('exit', function (code, signal) {
			if (code > 0) {
				return errors.join('\n');
			}
			return resolve(output.join('\n'));
		});

		child.stdout.on('data', (data) => {
			output.push(data);
		});

		child.stderr.on('data', (data) => {
			errors.push(data);
		});
	})
}

const generate509 = (private) => {
	return new Promise((resolve, reject) => {
		const output = [];
		const errors = [];

		const command = 'req -new -x509 -subj /C=US/CN=FactoryFour/O=FactoryFour/OU=Engineering/CN=dev-api.factoryfour.com -key /dev/stdin';
		const args = command.split(' ');
		const child = spawn('openssl', args);

		child.stdin.write(private);

		child.on('exit', function (code, signal) {
			if (code > 0) {
				return errors.join('\n');
			}
			return resolve(output.map(o => o.toString()).join('\n'));
		});

		child.stdout.on('data', (data) => {
			output.push(data);
		});

		child.stderr.on('data', (data) => {
			errors.push(data);
		});
	})
}

const generatePrint = (public) => {
	return new Promise((resolve, reject) => {
		const output = [];
		const errors = [];

		const command = 'x509 -noout -fingerprint';
		const args = command.split(' ');
		const child = spawn('openssl', args);

		child.stdin.write(public);

		child.on('exit', function (code, signal) {
			if (code > 0) {
				return errors.join('line\n');
			}
			return resolve(output.map(o => o.toString()).join('\n').split('=')[1]);
		});

		child.stdout.on('data', (data) => {
			output.push(data);
		});

		child.stderr.on('data', (data) => {
			errors.push(data);
		});
	})
}

const certs = {};
generatePrivate()
	.then((privateKey) => {
		certs.privateKey = privateKey;
		return Promise.all([generatePublic(privateKey), generate509(privateKey)]);
	})
	.then(([publicKey, x509Key]) => {
		certs.publicKey = publicKey;
		certs.x509Key = x509Key;
		return generatePrint(x509Key);
	})
	.then((thumbprint) => {
		certs.thumbprint = thumbprint;
		certs.printEnc = Buffer
			.from(thumbprint.split(':')
			.join(''))
			.toString('base64')
			.replace(/=/g, '');

		console.log('Writing to', certs.printEnc);
		fs.mkdirSync(`generated/${certs.printEnc}`);
		fs.writeFileSync(`generated/${certs.printEnc}/public.pem`, certs.publicKey);
		fs.writeFileSync(`generated/${certs.printEnc}/private.pem`, certs.privateKey);
		fs.writeFileSync(`generated/${certs.printEnc}/x509.cert`, certs.x509Key);
	})
	.catch((err) => {
		console.log(err);
	});
