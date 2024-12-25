const party = require('hostparty');

require('dotenv').config();

const BASE_URL = process.env.CUSTOM_DOMAIN_NAME.split(',');

party.add('127.0.0.1', BASE_URL);
