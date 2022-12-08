
import { console, isArray, isBoolean, isObject, isString } from '../extern/base.mjs';
import { ENVIRONMENT                                     } from '../source/ENVIRONMENT.mjs';
import { Filesystem                                      } from '../source/Filesystem.mjs';
import { isUpdater                                       } from '../source/Updater.mjs';



export const isDatabase = function(obj) {
	return Object.prototype.toString.call(obj) === '[object Database]';
};


export const containsSoftware = function(software, entry) {

	if (
		isArray(software) === true
		&& isObject(entry) === true
	) {

		let found = null;

		for (let s = 0, sl = software.length; s < sl; s++) {

			let other = software[s];
			if (
				isObject(other) === true
				&& other['name'] === entry['name']
				&& other['platform'] === entry['platform']
				&& other['version'] === entry['version']
			) {
				found = other;
				break;
			}

		}

		if (found !== null) {
			return true;
		}

	}

	return false;

};

const isIdentifier = function(identifier) {

	if (isString(identifier) === true) {

		if (identifier.startsWith('CVE-') === true) {

			let check = identifier.split('-');
			if (
				check.length === 3
				&& check[0] === 'CVE'
				&& /^([0-9]{4})$/g.test(check[1]) === true
				&& /^([0-9]+)$/g.test(check[2]) === true
			) {
				return true;
			}

		} else if (identifier.startsWith('DSA-') === true) {

			let check = identifier.split('-');
			if (
				(
					check.length === 2
					&& check[0] === 'DSA'
					&& /^([0-9]{3,5})$/g.test(check[1]) === true
				) || (
					check.length === 3
					&& check[0] === 'DSA'
					&& /^([0-9]{3,5})$/g.test(check[1]) === true
					&& /^([0-9]{1})$/g.test(check[2]) === true
				)
			) {
				return true;
			}

		}

	}

	return false;

};

const isValid = function(vulnerability) {

	if (
		isObject(vulnerability) === true
		&& isIdentifier(vulnerability['id']) === true
		&& isString(vulnerability['description']) === true
		&& isArray(vulnerability['hardware']) === true
		&& isArray(vulnerability['software']) === true
		&& isArray(vulnerability['references']) === true
		&& (isString(vulnerability['severity']) === true || vulnerability['severity'] === null)
		&& isString(vulnerability['state']) === true
		&& isBoolean(vulnerability['is_edited']) === true
	) {

		if (
			vulnerability['description'].length > 0
			|| vulnerability['hardware'].length > 0
			|| vulnerability['software'].length > 0
			|| vulnerability['references'].length > 0
			|| vulnerability['state'] !== 'invalid'
		) {
			return true;
		}

	}


	return false;

};

const isVulnerability = function(vulnerability) {

	if (
		isObject(vulnerability) === true
		&& isIdentifier(vulnerability['id']) === true
		&& isString(vulnerability['description']) === true
		&& isArray(vulnerability['hardware']) === true
		&& isArray(vulnerability['software']) === true
		&& isArray(vulnerability['references']) === true
		&& (isString(vulnerability['severity']) === true || vulnerability['severity'] === null)
		&& isString(vulnerability['state']) === true
		&& isBoolean(vulnerability['is_edited']) === true
	) {
		return true;
	}


	return false;

};

const updateVulnerability = function(vulnerability) {

	let state = vulnerability['state'];

	if (vulnerability['severity'] !== null) {

		if (vulnerability['description'].length > 0) {

			if (vulnerability['software'].length > 0 || vulnerability['hardware'].length > 0) {
				state = 'published';
			} else {
				state = 'invalid';
			}

		} else {
			state = 'invalid';
		}

	}

	if (
		vulnerability['state'] !== 'disputed'
		&& vulnerability['state'] !== 'rejected'
	) {
		vulnerability['state'] = state;
	}

	return vulnerability['state'];

};



const Database = function(updater) {

	updater = isUpdater(updater) ? updater : null;

	let folder = updater !== null ? updater._settings.folder : '/tmp/vulnerabilities';

	this.filesystem = new Filesystem({
		root: folder + '/vulnerabilities'
	});

	this.__state = {
		'index': {
			'disputed':  [],
			'invalid':   [],
			'published': [],
			'rejected':  []
		},
		'removed':         [],
		'updated':         [],
		'vulnerabilities': {}
	};

};


Database.isDatabase = isDatabase;


Database.prototype = {

	[Symbol.toStringTag]: 'Database',

	connect: function() {

		this.filesystem.index('/', 'CVE-*.json').forEach((path) => {

			let vulnerability = this.filesystem.read(path);
			if (isVulnerability(vulnerability) === true) {
				this.__state['vulnerabilities'][vulnerability['id']] = vulnerability;
			}

		});

	},

	disconnect: function() {

		if (this.__state['updated'].length > 0) {

			this.__state['updated'].forEach((identifier) => {

				let vulnerability = this.__state['vulnerabilities'][identifier];
				if (isString(vulnerability['id']) === true) {
					this.filesystem.write('/' + vulnerability['id'] + '.json', vulnerability);
				}

			});

			console.info('Database: Updated ' + this.__state['updated'].length + ' Vulnerabilities.');


			this.__state['index']['disputed']  = [];
			this.__state['index']['invalid']   = [];
			this.__state['index']['published'] = [];
			this.__state['index']['rejected']  = [];

			for (let identifier in this.__state['vulnerabilities']) {

				let vulnerability = this.__state['vulnerabilities'][identifier];

				updateVulnerability(vulnerability);

				let state = vulnerability['state'];
				if (state === 'disputed') {
					this.filesystem.write('/' + identifier + '.json', vulnerability);
					this.__state['index']['disputed'].push(identifier);
				} else if (state === 'invalid') {
					this.filesystem.write('/' + identifier + '.json', vulnerability);
					this.__state['index']['invalid'].push(identifier);
				} else if (state === 'published') {
					// Do not write already published and unmodified vulnerabilities
					this.__state['index']['published'].push(identifier);
				} else if (state === 'rejected') {
					this.filesystem.write('/' + identifier + '.json', vulnerability);
					this.__state['index']['rejected'].push(identifier);
				}

			}

			console.log('Database: Statistics');

			console.error('> ' + this.__state['index']['invalid'].length   + ' invalid');
			console.warn('> '  + this.__state['index']['rejected'].length  + ' rejected');
			console.log('> '   + this.__state['index']['disputed'].length  + ' disputed');
			console.info('> '  + this.__state['index']['published'].length + ' published');

			filesystem.write('/vulnerabilities/index.json', {
				'disputed':  this.__state['index']['disputed'].sort(),
				'invalid':   this.__state['index']['invalid'].sort(),
				'published': this.__state['index']['published'].sort(),
				'rejected':  this.__state['index']['rejected'].sort()
			});

		} else {

			console.info('Database: Updated 0 Vulnerabilities.');

		}

		if (this.__state['removed'].length > 0) {

			this.__state['removed'].forEach((identifier) => {
				this.filesystem.remove('/' + identifier + '.json');
			});

			console.info('Database: Removed ' + this.__state['removed'].length + ' Vulnerabilities.');

		} else {

			console.info('Database: Removed 0 Vulnerabilities.');

		}

	},

	read: function(identifier) {

		identifier = isString(identifier) ? identifier : null;


		if (identifier !== null) {

			let vulnerability = this.__state['vulnerabilities'][identifier] || null;
			if (vulnerability === null) {

				vulnerability = {
					'id':          identifier,
					'description': '',
					'hardware':    [],
					'software':    [],
					'references':  [],
					'severity':    null,
					'state':       'invalid',
					'is_edited':   false
				};

			}

			return vulnerability;

		}


		return {
			'id':          null,
			'description': '',
			'hardware':    [],
			'software':    [],
			'references':  [],
			'severity':    null,
			'state':       'invalid',
			'is_edited':   false
		};

	},

	clean: function() {

		for (let identifier in this.__state['vulnerabilities']) {

			let vulnerability = this.__state['vulnerabilities'][identifier];

			if (isValid(vulnerability) === false) {

				if (this.__state['removed'].includes(identifier) === false) {
					this.__state['removed'].push(identifier);
				}

			}

		}

	},

	update: function(vulnerability) {

		vulnerability = isVulnerability(vulnerability) ? vulnerability : null;


		if (vulnerability !== null) {

			let identifier = vulnerability['id'];

			this.__state['vulnerabilities'][identifier] = vulnerability;

			if (this.__state['updated'].includes(identifier) === false) {
				this.__state['updated'].push(identifier);
			}

			return true;

		}


		return false;

	}

};


export { Database };

