
import { console, Emitter, isArray, isNumber, isObject, isString } from '../../extern/base.mjs';
import { ENVIRONMENT                                             } from '../../source/ENVIRONMENT.mjs';
import { Filesystem                                              } from '../../source/Filesystem.mjs';
import { isUpdater                                               } from '../../source/Updater.mjs';
import { isDatabase, Database                                    } from '../../source/Database.mjs';
import { Webscraper                                              } from '../../source/Webscraper.mjs';



const mergeEntry = function(vulnerability, data) {

	if (
		isObject(data) === true
		&& isString(data['cveID']) === true
	) {

		if (isString(data['shortDescription']) === true) {

			let description = data['shortDescription'].trim();
			if (vulnerability['description'].includes(description) === false) {
				vulnerability['description'] += '\n\n' + description;
			}

		}

		// XXX: All Known Exploited Vulnerabilities are critical
		vulnerability['severity'] = 'critical';

	}

};



const CISA = function(database, updater) {

	this.database = isDatabase(database) ? database : new Database();
	this.updater  = isUpdater(updater)   ? updater  : null;

	let folder   = updater !== null ? updater._settings.folder   : '/tmp/vulnerabilities';
	let insecure = updater !== null ? updater._settings.insecure : false;

	this.filesystem = new Filesystem({
		root: folder + '/cache/cisa'
	});

	this.webscraper = new Webscraper({
		limit:    5,
		insecure: insecure
	});


	this.__state = {
		'vulnerabilities': {}
	};


	Emitter.call(this);

};


CISA.prototype = Object.assign({}, Emitter.prototype, {

	[Symbol.for('description')]: 'CISA Known Exploited Vulnerabilities Catalog',
	[Symbol.toStringTag]:        'CISA',

	'connect': function() {

		let data = this.filesystem.read('/known_exploited_vulnerabilities.json');

		if (isObject(data) === true && isArray(data['vulnerabilities']) === true) {

			data['vulnerabilities'].forEach((entry) => {
				this.__state['vulnerabilities'][entry['cveID']] = entry;
			});

		}

		this.filesystem.index('/', 'CVE-*.json').forEach((path) => {

			let entry = this.filesystem.read(path);
			if (
				isObject(entry) === true
				&& isString(entry['cveID']) === true
			) {
				this.__state['vulnerabilities'][entry['cveID']] = entry;
			}

		});

		this.emit('connect');

	},

	'disconnect': function() {

		this.webscraper.destroy();

		this.emit('disconnect');

	},

	'export': function() {

		console.info('CISA: Export');

		Object.values(this.__state['vulnerabilities']).forEach((entry) => {

			let vulnerability = this.database.read(entry['cveID']);
			if (vulnerability['is_edited'] === false) {

				mergeEntry.call(this, vulnerability, entry);

				this.database.update(vulnerability);

			}

		});

		setTimeout(() => {

			console.info('CISA: Export complete.');
			this.emit('export');

		}, 0);

	},

	'update': function() {

		console.info('CISA: Update');

		this.webscraper.request('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', (data) => {

			if (
				isObject(data) === true
				&& isString(data['title']) === true
				&& isString(data['catalogVersion']) === true
				&& isNumber(data['count']) === true
				&& isString(data['dateReleased']) === true
				&& isArray(data['vulnerabilities']) === true
				&& data['title'] === 'CISA Catalog of Known Exploited Vulnerabilities'
			) {

				this.filesystem.write('/known_exploited_vulnerabilities.json', data);

				data['vulnerabilities'].forEach((entry) => {

					if (isObject(entry) === true) {

						this.filesystem.write('/' + entry['cveID'] + '.json', entry);
						this.__state['vulnerabilities'][entry['cveID']] = entry;

					}

				});

				console.info('CISA: Update complete.');
				this.emit('update');

			}

		});

	}

});


export { CISA };

