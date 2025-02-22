module.exports = function (RED) {
  'use strict';

  const ActiveDirectory = require('activedirectory2');

  function loginUserNode(config) {
    RED.nodes.createNode(this, config);
    const node = this;
    const configNode = RED.nodes.getNode(config.configName);
    let cUsername;
    let cPassword;
    let domain;

    // Check if configuration node exists
    if (!configNode) {
      node.status({ fill: 'red', shape: 'dot', text: 'configuration error' });
      node.warn('No valid configuration specified');
      return;
    }

    // Extract configuration details
    node.url = configNode.url;
    node.baseDN = configNode.baseDN || ''; // Fallback to empty string if baseDN not set
    cUsername = configNode.credentials.username;
    cPassword = configNode.credentials.password;
    domain = cUsername.includes('@') ? cUsername.split('@')[1] : null;

    this.on('input', async function (msg) {
      node.status({ fill: 'blue', shape: 'ring', text: 'connecting' });

      // Configure Active Directory connection
      const adConfig = {
        url: node.url,
        baseDN: node.baseDN,
        username: cUsername,
        password: cPassword
      };

      if (msg.tlsOptions) {
        adConfig.tlsOptions = JSON.parse(JSON.stringify(msg.tlsOptions));
      }

      let ad;
      try {
        ad = new ActiveDirectory(adConfig);
        node.status({ fill: 'green', shape: 'dot', text: 'connected' });
      } catch (e) {
        const errTxt = 'Connection error: ' + e.message;
        node.status({ fill: 'red', shape: 'dot', text: 'connection error' });
        node.error(errTxt, msg);
        msg.error = errTxt;
        node.send([null, msg]);
        return;
      }

      // Get username and password from msg.payload
      const username = msg.payload.username;
      const password = msg.payload.password;

      if (!username || !password) {
        node.status({ fill: 'red', shape: 'dot', text: 'missing credentials' });
        msg.error = 'Username and password are required in msg.payload';
        node.send([null, msg]);
        return;
      }

      const isUPN = username.includes('@');

      // Helper function for authentication as Promise
      const tryAuthenticate = (loginName) => {
        return new Promise((resolve) => {
          ad.authenticate(loginName, password, (err, auth) => {
            if (err) resolve({ error: err, authenticated: false });
            else resolve({ error: null, authenticated: auth });
          });
        });
      };

      node.status({ fill: 'blue', shape: 'ring', text: 'authenticating' });

      try {
        if (isUPN) {
          // Direct authentication attempt with UPN
          const result = await tryAuthenticate(username);
          if (result.authenticated) {
            msg.payload = { authenticated: true, username: username };
            node.status({ fill: 'green', shape: 'dot', text: 'authenticated' });
            node.send([msg, null]);
          } else {
            const errTxt = result.error ? 'Authentication error: ' + JSON.stringify(result.error) : 'Authentication failed';
            node.status({ fill: 'yellow', shape: 'dot', text: 'authentication failed' });
            msg.payload = { authenticated: false, username: username };
            if (result.error) msg.error = errTxt;
            node.send([null, msg]);
          }
        } else {
          // Handle sAMAccountName login
          let loginName = username;
          if (domain) {
            loginName = `${username}@${domain}`; // Construct UPN from sAMAccountName and domain
          }

          let result = await tryAuthenticate(loginName);

          if (!result.authenticated && node.baseDN) {
            // If initial attempt fails and baseDN is available, try to find user
            const user = await new Promise((resolve) => {
              ad.findUser(username, (err, user) => {
                if (err || !user) resolve(null);
                else resolve(user);
              });
            });

            if (user && user.userPrincipalName) {
              // Try authentication with found UPN
              result = await tryAuthenticate(user.userPrincipalName);
            }
          }

          if (result.authenticated) {
            msg.payload = { authenticated: true, username: username };
            node.status({ fill: 'green', shape: 'dot', text: 'authenticated' });
            node.send([msg, null]);
          } else {
            const errTxt = result.error ? 'Authentication error: ' + JSON.stringify(result.error) : 'Authentication failed';
            if (!node.baseDN && !domain) {
              errTxt += ' (No baseDN or domain configured for sAMAccountName resolution)';
            }
            node.status({ fill: 'yellow', shape: 'dot', text: 'authentication failed' });
            msg.payload = { authenticated: false, username: username };
            if (result.error) msg.error = errTxt;
            node.send([null, msg]);
          }
        }
      } catch (e) {
        const errTxt = 'Unexpected error: ' + e.message;
        node.status({ fill: 'red', shape: 'dot', text: 'error' });
        node.error(errTxt, msg);
        msg.error = errTxt;
        node.send([null, msg]);
      }
    });
  }

  RED.nodes.registerType('login-user', loginUserNode);
};