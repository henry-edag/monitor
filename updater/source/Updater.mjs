
import process from 'process';

import { console, Emitter, isObject, isString } from '../extern/base.mjs';
import { ENVIRONMENT                          } from '../source/ENVIRONMENT.mjs';
import { Database                             } from '../source/Database.mjs';
import { Archlinux                            } from '../source/tracker/Archlinux.mjs';
import { CVE                                  } from '../source/tracker/CVE.mjs';
import { CISA                                 } from '../source/tracker/CISA.mjs';
import { Debian                               } from '../source/tracker/Debian.mjs';
import { Microsoft                            } from '../source/tracker/Microsoft.mjs';



const CONSTRUCTORS = [
	CVE,
	CISA,
	Archlinux,
	Debian,
	Microsoft
];

const TRACKERS = CONSTRUCTORS.map((Constructor) => Constructor.prototype[Symbol.toStringTag]);

export const isUpdater = function(obj) {
	return Object.prototype.toString.call(obj) === '[object Updater]';
};



const Updater = function(settings) {

	settings = isObject(settings) ? settings : {};


	this._settings = Object.assign({
		action:   null,
		folder:   '/tmp/vulnerabilities',
		debug:    false,
		insecure: false,
		trackers: TRACKERS
	}, settings);

	if (this._settings.trackers.length > 0) {

		this._settings.trackers = this._settings.trackers.map((search) => {

			let found = null;

			for (let t = 0, tl = TRACKERS.length; t < tl; t++) {

				if (TRACKERS[t].toLowerCase() === search.toLowerCase()) {
					found = TRACKERS[t];
					break;
				}

			}

			return found;

		}).filter((name) => name !== null);

	}

	Object.freeze(this._settings);


	console.clear();
	console.log('Updater: Command-Line Arguments:');
	console.log(this._settings);


	this.database = new Database(this);
	this.trackers = [];

	this.__state = {
		connected: false
	};


	if (this._settings.trackers.length > 0) {

		TRACKERS.forEach((name, c) => {

			if (this._settings.trackers.includes(name) === true) {
				this.trackers.push(new CONSTRUCTORS[c](this.database, this));
			}

		});

	}


	Emitter.call(this);


	this.on('connect', () => {

		console.info('Updater: Connect complete.');

		let action = this._settings.action || null;
		if (action === 'clean') {

			this.once('clean', () => {
				this.disconnect();
			});

			this.clean();

		} else if (action === 'export') {

			this.once('export', () => {
				this.disconnect();
			});

			this['export']();

		} else if (action === 'update') {

			this.once('update', () => {
				this.disconnect();
			});

			this['update']();

		}

	});

	this.on('clean', () => {
		console.info('Updater: Clean complete.');
	});

	this.on('export', () => {
		console.info('Updater: Export complete.');
	});

	this.on('update', () => {
		console.info('Updater: Update complete.');
	});

	this.on('disconnect', () => {

		let action = this._settings.action || null;
		if (action === 'clean') {
			this.database.disconnect();
		} else if (action === 'export') {
			this.database.disconnect();
		} else if (action === 'update') {
			this.database.disconnect();
		}

		console.info('Updater: Disconnect complete.');

	});


	process.on('SIGINT', () => {
		this.disconnect();
	});

	process.on('SIGQUIT', () => {
		this.disconnect();
	});

	process.on('SIGABRT', () => {
		this.disconnect();
	});

	process.on('SIGTERM', () => {
		this.disconnect();
	});

	process.on('error', () => {
		this.disconnect();
	});

};


Updater.isUpdater = isUpdater;
Updater.TRACKERS  = TRACKERS;


Updater.prototype = Object.assign({}, Emitter.prototype, {

	[Symbol.toStringTag]: 'Updater',

	'connect': function() {

		if (this.__state.connected === false) {

			console.info('Updater: Connect');


			this.database.connect();


			if (this.trackers.length > 0) {

				let connecting = this.trackers.length;

				this.trackers.forEach((tracker) => {

					tracker.once('connect', () => {

						connecting--;

						if (connecting === 0) {

							this.__state.connected = true;
							this.emit('connect');

						}

					});

					tracker.connect();

				});

			} else {

				this.__state.connected = true;
				this.emit('connect');

			}


			return true;

		}


		return false;

	},

	'destroy': function() {

		if (this.__state.connected === true) {
			return this.disconnect();
		}


		return false;

	},

	'disconnect': function() {

		if (this.__state.connected === true) {

			this.__state.connected = false;
			this.emit('disconnect');

			return true;

		}


		return false;

	},

	'clean': function() {

		if (this.__state.connected === true) {

			console.info('Updater: Clean');

			this.database.clean();
			this.emit('clean');

			return true;

		}


		return false;

	},

	'export': function() {

		if (this.__state.connected === true) {

			console.info('Updater: Export');


			let trackers = this.trackers.filter((tracker) => {
				return tracker[Symbol.toStringTag] !== 'CVE';
			});

			if (trackers.length > 0) {

				let merging = trackers.length;

				trackers.forEach((tracker) => {

					tracker.once('export', () => {

						merging--;

						if (merging === 0) {
							this.emit('export');
						}

					});

					tracker['export']();

				});

				return true;

			}

		}


		return false;

	},

	'update': function() {

		if (this.__state.connected === true) {

			console.info('Updater: Update');


			let cve = this.trackers.find((tracker) => {
				return tracker[Symbol.toStringTag] === 'CVE';
			}) || null;

			if (cve !== null) {

				let trackers = this.trackers.filter((tracker) => tracker !== cve);

				cve.once('update', () => {

					let updating = trackers.length - 1;

					trackers.forEach((tracker) => {

						tracker.once('update', () => {

							updating--;

							if (updating === 0) {
								this.emit('update');
							}

						});

						tracker.update();

					});

				});

				cve.update();

			} else {

				let updating = this.trackers.length;

				this.trackers.forEach((tracker) => {

					tracker.once('update', () => {

						updating--;

						if (updating === 0) {
							this.emit('update');
						}

					});

					tracker.update();

				});

			}

			return true;

		}


		return false;

	}

});


export { Updater };

