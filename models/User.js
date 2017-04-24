var mongoose = require('mongoose');
var mongooseUniqueValidator = require('mongoose-unique-validator');
var crypto = require('crypto');
var jwt = require('jsonwebtoken');
var secret = require('../config').secret;

var UserScheme = new mongoose.Schema({
    username: {
        type: String,
        lowercase: true,
        unique: true,
        required: [true, 'cannot be blank'],
        match: [/^[a-zA-Z0-9]+$/, 'is invalid'],
        index: true
    },
    email: {
        type: String,
        lowercase: true,
        unique: true,
        required: [true, 'cannot be blank'],
        match: [/\S+@\S+\.\S+/, 'is invalid'],
        index: true
    },
    bio: String,
    image: String,
    hash: String,
    salt: String
}, {timestamps: true});

UserScheme.plugin(mongooseUniqueValidator, {message: 'is already occupied.'});

UserScheme.methods.setPassword = function(password) {
    this.salt = crypto.randomBytes(16).toString('hex');
    this.hash = crypto.pbkdf2Sync(password, this.salt, 10000, 512, 'sha512').toString('hex');
};

UserScheme.methods.validPassword = function(password) {
    return this.hash ===
        crypto.pbkdf2Sync(password, this.salt, 10000, 512, 'sha512').toString('hex');
}

UserScheme.methods.generateJWT = function() {
    var today = new Date();
    var expire = new Date();
    expire.setDate(today + 60);

    return jwt.sign({
        id: this._id,
        username: this.username,
        exp: parseInt(expire.getTime() / 1000),
    }, secret);
}

UserScheme.methods.toAuthJSON = function() {
    return {
        username: this.username,
        email: this.email,
        token: this.generateJWT(),
    }
}

mongoose.model('User', UserScheme);