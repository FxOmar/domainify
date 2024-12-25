const express = require('express');
const morgan = require('morgan');
const { createProxyMiddleware } = require('http-proxy-middleware');

const https = require('https');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

require('dotenv').config();

const app = express();

const LOCALHOST_SERVER = process.env.LOCALHOST_SERVER;
const CUSTOM_DOMAIN_NAME = process.env.CUSTOM_DOMAIN_NAME;

const baseUrl = CUSTOM_DOMAIN_NAME.split(',')[0];

app.use(morgan('dev'));

app.use(
  '/',
  createProxyMiddleware({
    target: LOCALHOST_SERVER,
    changeOrigin: true,
    secure: false,
    ws: true,
    headers: {
      host: baseUrl,
    },
  })
);

// Read SSL certificate and key files
const keyPath = path.resolve(__dirname, `${baseUrl}-key.pem`);
const certPath = path.resolve(__dirname, `${baseUrl}.pem`);

// Generate SSL certificates using mkcert if they don't exist
if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
  console.log(
    'SSL certificates not found. Generating self-signed certificates using mkcert...'
  );
  execSync(`mkcert ${baseUrl}`);
}

const options = {
  key: fs.readFileSync(keyPath),
  cert: fs.readFileSync(certPath),
};

// Create an HTTPS server
https.createServer(options, app).listen(443, () => {
  console.log(`Secure proxy server running on https://${baseUrl}`);
});
