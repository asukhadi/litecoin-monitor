// API - LTCMonitor.net

// Setup the modules required
var express = require('express');
var mysql = require('mysql');
var config = require('./config');
var validator = require('validator');
var litecoin = require('node-litecoin');

// Setup the initial variables
var app = express();
var connectionpool = mysql.createPool(
{
    host : config.mysql.host,
    user : config.mysql.username,
    password : config.mysql.password,
    database : config.mysql.database
});


// Configuring
app.configure(function()
{
    app.use(express.bodyParser());
    app.use(express.methodOverride());
    app.use(function(req, res, next)
    {
        res.setHeader("API-Version", config.settings.version);
        return next();
    });
    app.use(app.router);
    app.use(function(err, req, res, next)
    {
        console.error(err.stack);
        res.json(config.constants.http.INTERNALERROR, { error: 'InternalError' });
    });
});

// Create API Key
//   - Because of same origin policy for ajax requests, we return jsonp instead - this api function only meant for main site
app.get('/apikey', function(req, res)
{
    // Validate Email
    if(!validator.isEmail(req.query.email) && req.query.email.length <= config.settings.emailsize)
    {
        res.jsonp({ error: 'BadEmail' });
        
        return;
    }
    
    // Validate recaptcha
    var Recaptcha = require('recaptcha').Recaptcha;
    var data =
    {
        remoteip: req.connection.remoteAddress,
        challenge: req.query.recaptcha_challenge_field,
        response: req.query.recaptcha_response_field
    };
    var recaptcha = new Recaptcha(config.settings.publickey, config.settings.privatekey, data);
    
    recaptcha.verify(function(success, error_code)
    {
        if(success)
        {
            // Captcha was good -> Get a mysql connection from the pool
            connectionpool.getConnection(function(err, connection)
            {
                if(err)
                {
                    console.error('CONNECTION error: ', err);
                    res.jsonp({ error: 'InternalError' });
                    
                    return;
                }

                // Check for email in database
                connection.query('SELECT level FROM access WHERE email = ?', [req.query.email], function(err, results)
                {
                    if(err)
                    {
                        console.error('QUERY error: ', err);
                        res.jsonp({ error: 'InternalError' });
                        
                        return;
                    }
                    else
                    {
                        // Email already in database -> Maybe resend api key to email?
                        if(results.length > 0)
                        {
                            res.jsonp({ error: 'AlreadyExists' });
                            
                            return;
                        }
                    }
                });
                
                // Generate new api key
                var chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz';
                var token = '';
                
                for (var i = 0; i < config.settings.apikeysize; ++i)
                {
                    var rand = Math.floor(Math.random() * chars.length);
                    token += chars.substring(rand, rand + 1);
                }
                
                // Check for uniqueness of key
                connection.query('SELECT * FROM access WHERE apikey = ?', [token], function(err, results)
                {
                    if(err)
                    {
                        console.error('QUERY error: ', err);
                        res.jsonp({ error: 'InternalError' });
                        
                        return;
                    }
                    else
                    {
                        // Improbable event, generated a duplicate key
                        if(results.length > 0)
                        {
                            res.jsonp({ error: 'InternalError' });
                            
                            return;
                        }
                    }
                });
                
                // All good, add key and email to database
                var data = {email : req.query.email, apikey : token, used : 0, lastcleared : 0, level : config.constants.level.NORMAL};
                connection.query('INSERT INTO access SET ?', data, function(err, results)
                {
                    if(err)
                    {
                        console.error('QUERY error: ', err);
                        res.jsonp({ error: 'InternalError' });
                        
                        return;
                    }
                });
                
                // Release connection and add back to pool
                connection.release();
                
                // Send apikey back to user in jsonp
                res.jsonp({ apikey: token });
                
                // Setup email to user
                var nodemailer = require('nodemailer');
                var fs = require("fs");
                var pathlib = require("path");
                var transport = nodemailer.createTransport("sendmail");
                
                var message = 
                {
                    from: 'LTCMonitor.net <noreply@ltcmonitor.net>',
                    to: '<' + req.query.email +'>',
                    subject: 'Your API Key for LTCMonitor.net',
                    text: 'Thanks for signing up at ltcmonitor.net. Your API Key is ' + token + '. Read the API Documentation at http//www.ltcmonitor.net/usage to get started.',
                    html: 'Thanks for signing up at ltcmonitor.net.<br><br>Your API Key is <strong>' + token + '</strong><br>Read the API Documentation at <a href="http//www.ltcmonitor.net/usage">http//www.ltcmonitor.net/usage</a> to get started.'
                };
                
                // Setup dkim for outgoing email
                transport.useDKIM(
                {
                    domainName: "ltcmonitor.net",
                    keySelector: "dkim",
                    privateKey: fs.readFileSync(pathlib.join(__dirname, config.settings.dkimprivkey))
                });
                
                // Send the email
                transport.sendMail(message, function(error)
                {
                    if(error)
                    {
                        console.error('MAIL error: ', error.message);
                    }
                });
            });
        }
        else
        {
            res.jsonp({ error: 'WrongCaptcha' });
        }
    });
})

// Create Agent - Start monitoring litecoin address(es) for deposits or withdrawals and setup callbacks
app.post('/create', function(req, res)
{
    // Get mysql connection from pool
    connectionpool.getConnection(function(err, connection)
    {
        // Check for access
        connection.query('SELECT used,lastcleared,level,id FROM access WHERE apikey = ?', [req.body.api_key], function(err, results)
        {
            if(err)
            {
                console.error('QUERY error: ', err);
                res.json(config.constants.http.INTERNALERROR, { error: 'InternalError' });
            }
            else
            {
                // Found the apikey in database
                if(results.length == 1)
                {
                    var apikeyid = results[0].id;
                    
                    // Check for api limits
                    if((results[0].level == config.constants.level.NORMAL && results[0].used > config.constants.level.limits.NORMAL) ||
                        (results[0].level == config.constants.level.HEAVY && results[0].used > config.constants.level.limits.HEAVY))
                    {
                        var unixtime = Math.round(+new Date()/1000);
                        
                        // Has it been cleared in last 24 hours
                        if((unixtime - results[0].lastcleared) >= 86400)
                        {
                            // No it hasn't, clear the used counter and set new clear time
                            connection.query('UPDATE access SET used = 0, lastcleared = ? WHERE apikey = ?', [unixtime, req.body.api_key], function(err, results)
                            {
                                if(err)
                                {
                                    console.error('QUERY error: ', err);
                                    res.json(config.constants.http.INTERNALERROR, { error: 'InternalError' });
                                }
                            });
                            
                            // Maybe keep track of consequtive clears within few days and increase api usage level to HEAVY (500)
                        }
                        else
                        {
                            res.json(config.constants.http.UNAUTHORIZED, { error: 'LimitReached' });
                            
                            return;
                        }
                    }
                    
                    if(typeof req.body.event == 'undefined' || typeof req.body.callback_type == 'undefined' || typeof req.body.confirmation == 'undefined' || 
                        typeof req.body.callback_token == 'undefined' || typeof req.body.callback_type == 'undefined' || typeof req.body.address == 'undefined')
                    {
                        res.json(config.constants.http.BADREQUEST, { error: 'MissingFields' });
                        
                        return;
                    }

                    // Validate event
                    if(req.body.event != config.constants.event.DEPOSIT && req.body.event != config.constants.event.WITHDRAWAL && req.body.event != config.constants.event.BOTH)
                    {
                        res.json(config.constants.http.BADREQUEST, { error: 'InvalidEvent' });
                        
                        return;
                    }
                    
                    // Validate callback_type
                    if(req.body.callback_type != config.constants.callback.URL && req.body.callback_type != config.constants.callback.EMAIL && req.body.callback_type != config.constants.callback.SMS)
                    {
                        res.json(config.constants.http.BADREQUEST, { error: 'InvalidCallbackType' });
                        
                        return;
                    }
                    
                    // Validate confirmations
                    if(req.body.confirmation > config.constants.MAXCONFIRMS)
                    {
                        res.json(config.constants.http.BADREQUEST, { error: 'MaxConfirmation' });
                        
                        return;
                    }
                    
                    // Validate callback_token
                    if(req.body.callback_token.length > config.constants.MAXTOKENSIZE)
                    {
                        res.json(config.constants.http.BADREQUEST, { error: 'InvalidCallbackToken' });
                        
                        return;
                    }
                    
                    // Validate callback_payload
                    if(req.body.callback_type == config.constants.callback.URL)
                    {
                        if(!validator.isURL(req.body.callback_payload))
                        {
                            res.json(config.constants.http.BADREQUEST, { error: 'InvalidCallbackPayload' });
                            
                            return;
                        }
                    }
                    else if(req.body.callback_type == config.constants.callback.EMAIL)
                    {
                        if(!validator.isEmail(req.body.callback_payload))
                        {
                            res.json(config.constants.http.BADREQUEST, { error: 'InvalidCallbackPayload' });
                            
                            return;
                        }
                    }
                    else
                    {
                        res.json(config.constants.http.BADREQUEST, { error: 'InvalidCallbackPayload' });
                            
                        return;
                    }
                    
                    // Connect to litecoind rpc
                    var client = new litecoin.Client(
                    {
                        host: 'localhost',
                        port: config.litecoin.port,
                        user: config.litecoin.username,
                        pass: config.litecoin.password
                    });
                    
                    // Validate addresses
                    var addrs = req.body.address.split(',');
                    
                    for(var i = 0; i < addrs.length - 1; ++i)
                    {
                        // Using litecoin json api to validate the address -> maybe write the validation code in node.js
                        client.cmd('validateaddress', addrs[i], function(err, output)
                        {
                            if(err)
                            {
                                console.error('LITECOIN error: ', err);
                                res.json(config.constants.http.INTERNALERROR, { error: 'InternalError' });
                                
                                return;
                            }
                            else
                            {
                                // One of the address was invalid
                                if(output.isvalid == false)
                                {
                                    res.json(config.constants.http.BADREQUEST, { error: 'InvalidAddress' });
                                    
                                    return;
                                }
                            }
                        });
                    }
                    
                    // Update database to increase api usage counter
                    connection.query('UPDATE access SET used = used + 1 WHERE apikey = ?', [req.body.api_key], function(err, results)
                    {
                        if(err)
                        {
                            console.error('QUERY error: ', err);
                            res.json(config.constants.http.INTERNALERROR, { error: 'InternalError' });
                        }
                        else
                        {
                            // Generate monitorid
                            var chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz';
                            var token = '' + Math.round(+new Date());
                            
                            for (var i = 0; i < config.settings.monitoridsize; ++i)
                            {
                                var rand = Math.floor(Math.random() * chars.length);
                                token += chars.substring(rand, rand + 1);
                            }
                            
                            var monitor_id = require('crypto').createHash('md5').update(token).digest("hex");
                            
                            // Check uniqness of monitorid
                            connection.query('SELECT event FROM monitor WHERE monitorid = ?', [monitor_id], function(err, results)
                            {
                                if(err)
                                {
                                    console.error('QUERY error: ', err);
                                    res.json(config.constants.http.INTERNALERROR, { error: 'InternalError' });
                                    
                                    return;
                                }
                                else
                                {
                                    // Improbable event, generated a duplicate monitorid
                                    if(results.length > 0)
                                    {
                                        res.json(config.constants.http.INTERNALERROR, { error: 'InternalError' });
                                        
                                        return;
                                    }
                                }
                            });
                            
                            // All good -> add to database
                            var data = {monitorid : monitor_id, event : req.body.event, confirmation: req.body.confirmation, callback_type : req.body.callback_type, callback_payload : req.body.callback_payload, callback_token : req.body.callback_token, apikeyid: apikeyid};
                            connection.query('INSERT INTO monitor SET ?', data, function(err, info)
                            {
                                if(err)
                                {
                                    console.error('QUERY error: ', err);
                                    res.json(config.constants.http.INTERNALERROR, { error: 'InternalError' });
                                    
                                    return;
                                }
                                else
                                {
                                    // Add the addresses to the database and litecoind
                                    for(var i = 0; i < addrs.length; ++i)
                                    {
                                        var data = {address : addrs[i], monitor: info.insertId};
                                        connection.query('INSERT INTO ltcaddress SET ?', data, function(err, info)
                                        {
                                            if(err)
                                            {
                                                console.error('QUERY error: ', err);
                                                res.json(config.constants.http.INTERNALERROR, { error: 'InternalError' });
                                                
                                                return;
                                            }
                                            else
                                            {
                                                client.cmd('importaddress', addrs[i], 'monitor', 'false', function(err, output)
                                                {
                                                    if(err)
                                                    {
                                                        console.error('LITECOIN error: ', err);
                                                        res.json(config.constants.http.INTERNALERROR, { error: 'InternalError' });
                                                        
                                                        return;
                                                    }
                                                });
                                            }
                                        });
                                    }
                                    
                                    // Output monitor id
                                    res.json(config.constants.http.OK, { monitorid : monitor_id });
                                }
                            });
                        }
                    });
                }
                else
                {
                    res.json(config.constants.http.UNAUTHORIZED, { error: 'NoAccess' });
                }
            }
        });
    });
})

app.listen(config.settings.listen);
console.log('Started LTCMonitor::API');