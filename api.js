// API - LTCMonitor.net

// Setup the modules required
var express = require('express');
var mysql = require('mysql');
var config = require('./config');
var validator = require('validator');

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
    app.use(app.router);
    app.use(function(err, req, res, next)
    {
        console.error(err.stack);
        res.statusCode = 500;
        res.send({ error: 'InternalError' });
    });
});

// Create API Key
app.get('/create', function(req, res)
{
    // Validate Email
    if(!validator.isEmail(req.query.email))
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
            // Captcha was good -> Get a mysql connection
            connectionpool.getConnection(function(err, connection)
            {
                if(err)
                {
                    console.error('CONNECTION error: ', err);
                    res.jsonp({ error: 'InternalError' });
                    
                    return;
                }

                // Check for email in database
                connection.query('SELECT * FROM access WHERE email = ?', [req.query.email], function(err, results)
                {
                    if(err)
                    {
                        console.error('QUERY error: ', err);
                        res.jsonp({ error: 'InternalError' });
                    }
                    else
                    {
                        // Email already in database -> Maybe resend api key to email?
                        if(results.length > 0)
                        {
                            res.jsonp({ error: 'AlreadyExists' });
                        }
                        else
                        {
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
                                }
                                else
                                {
                                    // Improbable event, generated a duplicate key
                                    if(results.length > 0)
                                    {
                                        res.jsonp({ error: 'InternalError' });
                                    }
                                    else
                                    {
                                        // All good, add key and email to database
                                        var data = {email : req.query.email, apikey : token, used : 0, lastcleared : 0, level : config.settings.level.NORMAL};
                                        connection.query('INSERT INTO access SET ?', data, function(err, results)
                                        {
                                            if(err)
                                            {
                                                console.error('QUERY error: ', err);
                                                res.jsonp({ error: 'InternalError' });
                                            }
                                            else
                                            {
                                                // Send apikey back to user
                                                res.jsonp({ apikey: token });
                                            }
                                        });
                                    }
                                }
                            });
                        }
                    }
                    
                    // Release Connection
                    connection.release();
                });
            });
        }
        else
        {
            res.jsonp({ error: 'WrongCaptcha' });
        }
    });
})

app.listen(config.settings.listen);
console.log('Started LTCMonitor::API');