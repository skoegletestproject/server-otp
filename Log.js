const mongoose = require('mongoose');

const logSchema = new mongoose.Schema({
    timestamp: { type: Date, default: Date.now },
    method: String,
    path: String,
    query: Object,
    status: Number,
    duration: Number,
    userAgent: String,
    ip: String,
    owner: String,
    transactionId: String
});

module.exports = mongoose.model('smtplogs', logSchema);
